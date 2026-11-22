package extproc

import (
	"bytes"
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
// bidirectional gRPC streaming filter (audit-hardened):
//   - Derives MCP server strictly from `:path` (ignores untrusted client `X-MCP-Server` headers)
//   - Rejects JSON-RPC batch arrays `[...]` (fail closed)
//   - Enforces RS256/ES256 OIDC JWKS, parameter bounds, rolling 1h principal budgets, and
//     spec-compliant MCP 2026-07-28 MRTR `input_required` + signed `requestState`
//   - Parses BOTH JSON and `text/event-stream` SSE `tools/list` responses
//   - Rejects compressed upstream `Content-Encoding` responses that would bypass scrubbing
//   - Uses valid `BodyMutation` during `ResponseBody` (never invalid post-header `ImmediateResponse`)
type Server struct {
	ext_procv3.UnimplementedExternalProcessorServer
	Engine          *policy.Engine
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

// extractMCPServerFromPath derives the MCP server strictly from Envoy's routed `:path`
// (`/mcp/{server}`) and NEVER trusts client-supplied `X-MCP-Server` headers.
func extractMCPServerFromPath(path string) string {
	clean := strings.Split(path, "?")[0]
	if strings.HasPrefix(clean, "/mcp/") {
		rest := strings.TrimPrefix(clean, "/mcp/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) > 0 && parts[0] != "" {
			return parts[0]
		}
	}
	return ""
}

func immediateJSONResponse(payload any) *ext_procv3.ProcessingResponse {
	bodyBytes, _ := json.Marshal(payload)
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

func jsonRPCErrorPayload(id any, code int, message string, data any) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": message,
			"data":    data,
		},
	}
}

type streamState struct {
	startTime       time.Time
	headers         http.Header
	serverName      string
	traceparent     string
	rpcMethod       string
	rpcID           any
	respContentType string
	respEncoding    string
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
			st.serverName = extractMCPServerFromPath(st.headers.Get(":path"))
			st.traceparent = st.headers.Get(s.Engine.Config.Identity.CorrelateHeader)
			if st.traceparent == "" {
				st.traceparent = fmt.Sprintf("00-%016x-01", time.Now().UnixNano())
			}

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
			body := bytes.TrimSpace(phase.RequestBody.GetBody())
			// Fail closed on JSON-RPC batch arrays `[...]`
			if len(body) > 0 && body[0] == '[' {
				if err := stream.Send(immediateJSONResponse(jsonRPCErrorPayload(nil, -32600, "JSON-RPC batch requests are not permitted by Prometheus policy", nil))); err != nil {
					return err
				}
				continue
			}

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
					mrtrTok := st.headers.Get("X-Prometheus-MRTR-Approval")
					if mrtrTok == "" {
						if irs, ok := rpcReq.Params["inputResponses"].([]any); ok && len(irs) > 0 {
							if first, ok := irs[0].(map[string]any); ok {
								if tok, ok := first["approval_token"].(string); ok {
									mrtrTok = tok
								}
							}
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
						mrtrTok,
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
						if err := stream.Send(immediateJSONResponse(jsonRPCErrorPayload(rpcReq.ID, -32001, "Prometheus Policy Denial", ev))); err != nil {
							return err
						}
						continue
					}
					if ev.Verdict == "mrtr_escalate" {
						mrtrPayload := s.Engine.BuildMRTRInputRequiredPayload(rpcReq.ID, st.serverName, toolName, argsMap, oboPrincipal, ev)
						if err := stream.Send(immediateJSONResponse(mrtrPayload)); err != nil {
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
			respHdrs := headerMapToHTTP(phase.ResponseHeaders.GetHeaders())
			st.respContentType = respHdrs.Get("Content-Type")
			st.respEncoding = strings.ToLower(strings.TrimSpace(respHdrs.Get("Content-Encoding")))

			// Reject unexpected compressed responses that could smuggle secrets or poisoned tools past inspection
			if st.respEncoding != "" && st.respEncoding != "identity" {
				if err := stream.Send(immediateJSONResponse(jsonRPCErrorPayload(st.rpcID, -32001, "Compressed upstream response rejected by Prometheus inspection policy", map[string]any{
					"content_encoding": st.respEncoding,
				}))); err != nil {
					return err
				}
				continue
			}

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
			var bodyMut *ext_procv3.BodyMutation

			// 1. Live `tools/list` manifest pin + runtime poisoning verification (JSON + SSE!)
			// Uses BodyMutation (valid Envoy v3 ext_proc semantics after ResponseHeaders CONTINUE).
			if st.rpcMethod == "tools/list" && len(respBody) > 0 {
				if toolsList, ok := policy.ExtractToolsFromMCPResponse(respBody, st.respContentType); ok {
					passed, drifts := s.Engine.VerifyToolsListResponse(st.serverName, toolsList)
					if !passed && s.Engine.Config.Agent.Mode == "enforce" {
						errBytes, _ := json.Marshal(jsonRPCErrorPayload(st.rpcID, -32001, "MCP Manifest Pin Drift / Rug Pull Blocked", map[string]any{
							"server_name": st.serverName,
							"drifts":      drifts,
						}))
						bodyMut = &ext_procv3.BodyMutation{
							Mutation: &ext_procv3.BodyMutation_Body{
								Body: errBytes,
							},
						}
					}
				}
			}

			// 2. Response-phase secret scrubbing via BodyMutation
			if bodyMut == nil && s.SecretsProvider != nil && len(respBody) > 0 {
				secrets := s.SecretsProvider()
				if len(secrets) > 0 {
					scrubbed, hits := scrub.ScrubBytes(respBody, secrets)
					if hits > 0 {
						s.Engine.Metrics.SecretsRedacted.Add(int64(hits))
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
