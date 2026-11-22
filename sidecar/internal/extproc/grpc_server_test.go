package extproc_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_procv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Tony-Stark2025/prometheus-enterprise/sidecar/internal/extproc"
	"github.com/Tony-Stark2025/prometheus-enterprise/sidecar/internal/policy"
	"github.com/Tony-Stark2025/prometheus-enterprise/sidecar/internal/scrub"
)

func floatPtr(v float64) *float64 { return &v }
func b64url(b []byte) string      { return base64.RawURLEncoding.EncodeToString(b) }

func mintTestRS256(t *testing.T, priv *rsa.PrivateKey, issuer, aud, sub, actSub string) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	pay, _ := json.Marshal(map[string]any{
		"iss": issuer,
		"aud": aud,
		"sub": sub,
		"act": map[string]any{"sub": actSub},
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	})
	input := b64url(hdr) + "." + b64url(pay)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	return input + "." + b64url(sig)
}

func TestEnvoyGRPCExtProcBidirectionalHardenedOIDCPinningAndScrubbing(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	var idp *httptest.Server
	idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":   idp.URL,
				"jwks_uri": idp.URL + "/jwks",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": "k1",
					"use": "sig",
					"alg": "RS256",
					"n":   b64url(rsaKey.PublicKey.N.Bytes()),
					"e":   b64url(big.NewInt(int64(rsaKey.PublicKey.E)).Bytes()),
				},
			},
		})
	}))
	defer idp.Close()

	cleanTool := map[string]any{
		"name":        "refund_invoice",
		"description": "Issues a refund for an invoice.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"amount": map[string]any{"type": "number"}},
		},
	}

	lock := &policy.ManifestLockfile{
		Version: "1",
		Servers: map[string]policy.PinnedServerManifest{
			"vendor-billing": {
				TrustTier: "third_party",
				Tools: map[string]policy.PinnedToolEntry{
					"refund_invoice": {
						StructuralSHA256:    policy.ComputeStructuralSHA256(cleanTool),
						DescriptionSHA256:   policy.ComputeDescriptionSHA256(cleanTool),
						PoisoningLintPassed: true,
					},
				},
			},
		},
	}

	cfg := policy.AgentIaCConfig{
		Version: "1",
		Agent:   policy.AgentMeta{ID: "envoy-billing-agent", Mode: "enforce"},
		Identity: policy.IdentityConfig{
			Mode:                "oidc_obo",
			Issuer:              idp.URL, // auto-enables JWKS even without explicit verify_jwt_signature!
			Audience:            "mcp-gateway",
			RequireDelegatedSub: true,
			CorrelateHeader:     "traceparent",
		},
		MCPServers: map[string]policy.MCPServerPolicy{
			"vendor-billing": {
				TrustTier: "third_party",
				Tools: map[string]policy.ToolPolicy{
					"refund_invoice": {
						Tier:           "bounded_write",
						IdempotencyKey: "required",
						ParameterBounds: map[string]policy.ParameterBound{
							"amount": {Min: floatPtr(0.01), Max: floatPtr(50.0)},
						},
						OnBoundExceeded: "mrtr_escalate",
					},
				},
			},
		},
	}

	const activeSecret = "sk_live_ENVOY_SECRET_123456789"
	ledgerPath := filepath.Join(t.TempDir(), "traces.jsonl")
	eng, err := policy.NewEngine(cfg, lock, ledgerPath, []byte("grpc-test-key"), nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	grpcSrv := grpc.NewServer()
	ext_procv3.RegisterExternalProcessorServer(grpcSrv, extproc.NewServer(eng, func() []string {
		return []string{activeSecret}
	}))
	go func() { _ = grpcSrv.Serve(lis) }()
	defer grpcSrv.Stop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc dial: %v", err)
	}
	defer conn.Close()
	client := ext_procv3.NewExternalProcessorClient(conn)
	validJWT := mintTestRS256(t, rsaKey, idp.URL, "mcp-gateway", "alice@acme.com", "envoy-billing-agent")

	// Case A: Client-spoofed `x-mcp-server: bogus` header is IGNORED (strictly uses :path!)
	{
		stream, _ := client.Process(context.Background())
		_ = stream.Send(&ext_procv3.ProcessingRequest{
			Request: &ext_procv3.ProcessingRequest_RequestHeaders{
				RequestHeaders: &ext_procv3.HttpHeaders{
					Headers: &corev3.HeaderMap{
						Headers: []*corev3.HeaderValue{
							{Key: ":path", Value: "/mcp/vendor-billing"},
							{Key: "x-mcp-server", Value: "bogus-bypass-server"},
							{Key: "authorization", Value: "Bearer " + validJWT},
							{Key: "idempotency-key", Value: "idem-grpc-1"},
						},
					},
				},
			},
		})
		_, _ = stream.Recv()

		// $120 MUST still hit vendor-billing's $50 bound and return MCP 2026-07-28 input_required MRTR!
		reqJSON, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params":  map[string]any{"name": "refund_invoice", "arguments": map[string]any{"amount": 120.0}},
		})
		_ = stream.Send(&ext_procv3.ProcessingRequest{
			Request: &ext_procv3.ProcessingRequest_RequestBody{
				RequestBody: &ext_procv3.HttpBody{Body: reqJSON, EndOfStream: true},
			},
		})
		r2, _ := stream.Recv()
		imm := r2.GetImmediateResponse()
		if imm == nil || !strings.Contains(string(imm.GetBody()), `"resultType":"input_required"`) {
			t.Fatalf("expected spoofed x-mcp-server ignored and MRTR input_required returned, got: %v", r2)
		}
		_ = stream.CloseSend()
	}

	// Case B: Response-phase SSE `tools/list` rug pull uses valid Envoy BodyMutation (NOT ImmediateResponse!)
	{
		stream, _ := client.Process(context.Background())
		_ = stream.Send(&ext_procv3.ProcessingRequest{
			Request: &ext_procv3.ProcessingRequest_RequestHeaders{
				RequestHeaders: &ext_procv3.HttpHeaders{
					Headers: &corev3.HeaderMap{
						Headers: []*corev3.HeaderValue{
							{Key: ":path", Value: "/mcp/vendor-billing"},
						},
					},
				},
			},
		})
		_, _ = stream.Recv()

		listReq, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 4, "method": "tools/list"})
		_ = stream.Send(&ext_procv3.ProcessingRequest{
			Request: &ext_procv3.ProcessingRequest_RequestBody{
				RequestBody: &ext_procv3.HttpBody{Body: listReq, EndOfStream: true},
			},
		})
		_, _ = stream.Recv()

		_ = stream.Send(&ext_procv3.ProcessingRequest{
			Request: &ext_procv3.ProcessingRequest_ResponseHeaders{
				ResponseHeaders: &ext_procv3.HttpHeaders{
					Headers: &corev3.HeaderMap{
						Headers: []*corev3.HeaderValue{
							{Key: "content-type", Value: "text/event-stream"},
						},
					},
				},
			},
		})
		_, _ = stream.Recv()

		rugJSON, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      4,
			"result": map[string]any{
				"tools": []map[string]any{
					{
						"name":        "refund_invoice",
						"description": "MUTATED RUG PULL DESCRIPTION!",
						"inputSchema": cleanTool["inputSchema"],
					},
				},
			},
		})
		sseBody := []byte("event: message\ndata: " + string(rugJSON) + "\n\n")
		_ = stream.Send(&ext_procv3.ProcessingRequest{
			Request: &ext_procv3.ProcessingRequest_ResponseBody{
				ResponseBody: &ext_procv3.HttpBody{Body: sseBody, EndOfStream: true},
			},
		})
		rResp, _ := stream.Recv()
		mut := rResp.GetResponseBody().GetResponse().GetBodyMutation()
		if mut == nil || !strings.Contains(string(mut.GetBody()), "-32001") {
			t.Fatalf("expected SSE tools/list rug pull blocked via BodyMutation -32001, got: %v", rResp)
		}
		_ = stream.CloseSend()
	}

	// Case C: Valid $35 refund + response secret scrub via BodyMutation
	{
		stream, _ := client.Process(context.Background())
		_ = stream.Send(&ext_procv3.ProcessingRequest{
			Request: &ext_procv3.ProcessingRequest_RequestHeaders{
				RequestHeaders: &ext_procv3.HttpHeaders{
					Headers: &corev3.HeaderMap{
						Headers: []*corev3.HeaderValue{
							{Key: ":path", Value: "/mcp/vendor-billing"},
							{Key: "authorization", Value: "Bearer " + validJWT},
							{Key: "idempotency-key", Value: "idem-grpc-ok"},
						},
					},
				},
			},
		})
		_, _ = stream.Recv()

		reqJSON, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      5,
			"method":  "tools/call",
			"params":  map[string]any{"name": "refund_invoice", "arguments": map[string]any{"amount": 35.0}},
		})
		_ = stream.Send(&ext_procv3.ProcessingRequest{
			Request: &ext_procv3.ProcessingRequest_RequestBody{
				RequestBody: &ext_procv3.HttpBody{Body: reqJSON, EndOfStream: true},
			},
		})
		r2, _ := stream.Recv()
		if r2.GetImmediateResponse() != nil {
			t.Fatalf("expected valid $35 refund to CONTINUE, got ImmediateResponse: %s", string(r2.GetImmediateResponse().GetBody()))
		}

		_ = stream.Send(&ext_procv3.ProcessingRequest{
			Request: &ext_procv3.ProcessingRequest_ResponseHeaders{
				ResponseHeaders: &ext_procv3.HttpHeaders{},
			},
		})
		_, _ = stream.Recv()

		_ = stream.Send(&ext_procv3.ProcessingRequest{
			Request: &ext_procv3.ProcessingRequest_ResponseBody{
				ResponseBody: &ext_procv3.HttpBody{
					Body:        []byte(`{"jsonrpc":"2.0","id":5,"result":{"debug":"` + activeSecret + `"}}`),
					EndOfStream: true,
				},
			},
		})
		r4, _ := stream.Recv()
		mutated := string(r4.GetResponseBody().GetResponse().GetBodyMutation().GetBody())
		if strings.Contains(mutated, activeSecret) || !strings.Contains(mutated, scrub.RedactionMarker) {
			t.Fatalf("expected secret redacted via BodyMutation, got: %s", mutated)
		}
		_ = stream.CloseSend()
	}
}
