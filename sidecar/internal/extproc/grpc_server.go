package extproc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_procv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/Tony-Stark2025/prometheus-enterprise/sidecar/internal/policy"
	"github.com/Tony-Stark2025/prometheus-enterprise/sidecar/internal/scrub"
)

// Server implements the official Envoy v3 `envoy.service.ext_proc.v3.ExternalProcessor`
// bidirectional gRPC streaming filter for Envoy Proxy, Envoy AI Gateway / Agent Router,
// and Istio service meshes.
//
// Capabilities on a single bidirectional gRPC stream:
//   1. RequestHeaders: Captures path/MCP server/OBO auth/traceparent and strips `accept-encoding`.
//   2. RequestBody:    Enforces cryptographic OIDC/OBO identity, parameter bounds, single-use
//                      idempotency, and per-trace rate limits; writes HMAC-chained ledger;
//                      returns valid MCP JSON-RPC -32001 / -32002 ImmediateResponses (never bare 403).
//   3. ResponseHeaders: Drops `content-length` so body scrubbing never corrupts HTTP/1.1 framing.
//   4. ResponseBody:   Verifies live `tools/list` against `prometheus.lock` (blocks rug pulls with
//                      JSON-RPC -32001) and scrubs active secrets via BodyMutation.
type Server struct {
	ext_procv3.UnimplementedExternalProcessorServer
	Engine         *policy.Engine
	SecretsProvider func() []string
}

func NewServer(engine *policy.Engine, secretsProvider func() []string) *Server {
	return &Server{
		Engine:          engine,
		SecretsProvider: secretsProvider,
	}
}

func headerMapToHTTP(hm *corev3.HeaderMap) http.Header {
	out := http.Header{}
	if hm == nil {
		return out
	}
	for _, h := range hm.Headers {
		val := h.Value
		if val == "" && len(h.RawValue) > 0 {
			val = string(h.RawValue)
		}
		out.Add(h.Key, val)
	}
	return out
}

func extractMCPServerFromPath(path string, hdr http.Header) string {
	if explicit := strings.TrimSpace(hdr.Get("X-MCP-Server")); explicit != "" {
		return explicit
	}
	clean := strings.Split(path, "?")[0]
	if strings.HasPrefix(clean, "/mcp/") {
		rest := strings.TrimPrefix(clean, "/mcp/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) > 0 && parts[0] != "" {
			return parts[0]
		}
	}
	return "default"
}

func jsonRPCImmediateResponse(id any, code int, message string, data any) *ext_procv3.ProcessingResponse {
	bodyBytes, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": message,
			"data":    data,
		},
	})
	return &ext_procv3.ProcessingResponse{
		Response: &ext_procv3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &ext_procv3.ImmediateResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_OK},
				Headers: &ext_procv3.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{
						{
							Header: &corev3.HeaderValue{
								Key:      "content-type",
								RawValue: []byte("application/json"),
							},
						},
						{
							Header: &corev3.HeaderValue{
								Key:      "x-prometheus-enforced",
								RawValue: []byte("true"),
							},
						},
					},
				},
				Body: bodyBytes,
			},
		},
	}
}

type streamState struct {
	startTime   time.Time
	headers     http.Header
	serverName  string
	traceparent string
	rpcMethod   string
	rpcID       any
}

func (s *Server) Process(stream ext_procv3.ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()
	st := &streamState{
		startTime: time.Now(),
		headers:   http.Header{},
	}

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		var resp *ext_procv3.ProcessingResponse

		switch phase := req.Request.(type) {
		case *ext_procv3.ProcessingRequest_RequestHeaders:
			st.startTime = time.Now()
			st.headers = headerMapToHTTP(phase.RequestHeaders.GetHeaders())
			path := st.headers.Get(":path")
			st.serverName = extractMCPServerFromPath(path, st.headers)
			st.traceparent = st.headers.Get(s.Engine.Config.Identity.CorrelateHeader)
			if st.traceparent == "" {
				st.traceparent = fmt.Sprintf("00-%016x-01", time.Now().UnixNano())
			}

			// Strip Accept-Encoding so upstream responses arrive uncompressed for inspection/scrubbing
			resp = &ext_procv3.ProcessingResponse{
				Response: &ext_procv3.ProcessingResponse_RequestHeaders{
					RequestHeaders: &ext_procv3.HeadersResponse{
						Response: &ext_procv3.CommonResponse{
							Status: ext_procv3.CommonResponse_CONTINUE,
							HeaderMutation: &ext_procv3.HeaderMutation{
								RemoveHeaders: []string{"accept-encoding"},
								SetHeaders: []*corev3.HeaderValueOption{
									{
										Header: &corev3.HeaderValue{
											Key:      "traceparent",
											RawValue: []byte(st.traceparent),
										},
									},
								},
							},
						},
					},
				},
			}

		case *ext_procv3.ProcessingRequest_RequestBody:
			body := phase.RequestBody.GetBody()
			var rpcReq struct {
				JSONRPC string         `json:"jsonrpc"`
				ID      any            `json:"id"`
				Method  string         `json:"method"`
				Params  map[string]any `json:"params"`
			}
			if len(body) > 0 && json.Unmarshal(body, &rpcReq) == nil && rpcReq.Method != "" {
				st.rpcMethod = rpcReq.Method
				st.rpcID = rpcReq.ID

				if rpcReq.Method == "tools/call" {
					toolName, _ := rpcReq.Params["name"].(string)
					argsMap, _ := rpcReq.Params["arguments"].(map[string]any)
					if argsMap == nil {
						argsMap = map[string]any{}
					}
					idemKey := st.headers.Get("Idempotency-Key")
					if idemKey == "" {
						if ik, ok := argsMap["idempotency_key"].(string); ok {
							idemKey = ik
						}
					}

					oboPrincipal := s.Engine.ResolveOBOPrincipal(ctx, st.headers)
					ev := s.Engine.EvaluateToolCall(
						st.traceparent,
						st.serverName,
						toolName,
						argsMap,
						oboPrincipal,
						idemKey,
					)
					latMs := float64(time.Since(st.startTime).Microseconds()) / 1000.0
					_, _ = s.Engine.AppendLedgerRecord(
						st.traceparent,
						st.serverName,
						toolName,
						argsMap,
						ev,
						oboPrincipal,
						idemKey,
						latMs,
					)

					if ev.Verdict == "deny" {
						if err := stream.Send(jsonRPCImmediateResponse(rpcReq.ID, -32001, "Prometheus Policy Denial", ev)); err != nil {
							return err
						}
						continue
					}
					if ev.Verdict == "mrtr_escalate" {
						if err := stream.Send(jsonRPCImmediateResponse(rpcReq.ID, -32002, "Prometheus MRTR Out-of-Band Approval Required", ev)); err != nil {
							return err
						}
						continue
					}
				}
			}

			resp = &ext_procv3.ProcessingResponse{
				Response: &ext_procv3.ProcessingResponse_RequestBody{
					RequestBody: &ext_procv3.BodyResponse{
						Response: &ext_procv3.CommonResponse{
							Status: ext_procv3.CommonResponse_CONTINUE,
						},
					},
				},
			}

		case *ext_procv3.ProcessingRequest_ResponseHeaders:
			// Drop Content-Length so downstream response-body scrubbing never corrupts framing
			resp = &ext_procv3.ProcessingResponse{
				Response: &ext_procv3.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &ext_procv3.HeadersResponse{
						Response: &ext_procv3.CommonResponse{
							Status: ext_procv3.CommonResponse_CONTINUE,
							HeaderMutation: &ext_procv3.HeaderMutation{
								RemoveHeaders: []string{"content-length"},
							},
						},
					},
				},
			}

		case *ext_procv3.ProcessingRequest_ResponseBody:
			respBody := phase.ResponseBody.GetBody()

			// 1. Live `tools/list` manifest pin verification against `prometheus.lock`
			if st.rpcMethod == "tools/list" && len(respBody) > 0 {
				var rpcResp map[string]any
				if json.Unmarshal(respBody, &rpcResp) == nil {
					if resultObj, ok := rpcResp["result"].(map[string]any); ok {
						if rawTools, ok := resultObj["tools"].([]any); ok {
							toolsList := make([]map[string]any, 0, len(rawTools))
							for _, item := range rawTools {
								if m, ok := item.(map[string]any); ok {
									toolsList = append(toolsList, m)
								}
							}
							passed, drifts := s.Engine.VerifyToolsListResponse(st.serverName, toolsList)
							if !passed && s.Engine.Config.Agent.Mode == "enforce" {
								if err := stream.Send(jsonRPCImmediateResponse(st.rpcID, -32001, "MCP Manifest Pin Drift / Rug Pull Blocked", map[string]any{
									"server_name": st.serverName,
									"drifts":      drifts,
								})); err != nil {
									return err
								}
								continue
							}
						}
					}
				}
			}

			// 2. Response-phase secret scrubbing via BodyMutation
			var bodyMut *ext_procv3.BodyMutation
			if s.SecretsProvider != nil && len(respBody) > 0 {
				secrets := s.SecretsProvider()
				if len(secrets) > 0 {
					scrubbed, hits := scrub.ScrubBytes(respBody, secrets)
					if hits > 0 {
						bodyMut = &ext_procv3.BodyMutation{
							Mutation: &ext_procv3.BodyMutation_Body{
								Body: scrubbed,
							},
						}
					}
				}
			}

			resp = &ext_procv3.ProcessingResponse{
				Response: &ext_procv3.ProcessingResponse_ResponseBody{
					ResponseBody: &ext_procv3.BodyResponse{
						Response: &ext_procv3.CommonResponse{
							Status:       ext_procv3.CommonResponse_CONTINUE,
							BodyMutation: bodyMut,
						},
					},
				},
			}

		default:
			resp = &ext_procv3.ProcessingResponse{}
		}

		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}
