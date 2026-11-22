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

func TestEnvoyGRPCExtProcBidirectionalOIDCPinningAndScrubbing(t *testing.T) {
	// 1. Live RSA-2048 OIDC Discovery + JWKS Server
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
			Issuer:              idp.URL,
			Audience:            "mcp-gateway",
			VerifyJWTSignature:  true,
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

	// 2. Start real Envoy v3 gRPC ExternalProcessor server on loopback TCP
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

	// Case A: Full 4-phase bidirectional stream (Valid RS256 OBO JWT + $35 refund + response secret scrub)
	{
		stream, err := client.Process(context.Background())
		if err != nil {
			t.Fatalf("open stream: %v", err)
		}

		// Phase 1: RequestHeaders -> must strip accept-encoding
		_ = stream.Send(&ext_procv3.ProcessingRequest{
			Request: &ext_procv3.ProcessingRequest_RequestHeaders{
				RequestHeaders: &ext_procv3.HttpHeaders{
					Headers: &corev3.HeaderMap{
						Headers: []*corev3.HeaderValue{
							{Key: ":path", Value: "/mcp/vendor-billing"},
							{Key: "authorization", Value: "Bearer " + validJWT},
							{Key: "idempotency-key", Value: "idem-grpc-1"},
							{Key: "accept-encoding", Value: "gzip"},
						},
					},
				},
			},
		})
		r1, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv phase 1: %v", err)
		}
		removed := r1.GetRequestHeaders().GetResponse().GetHeaderMutation().GetRemoveHeaders()
		if len(removed) == 0 || removed[0] != "accept-encoding" {
			t.Fatalf("expected accept-encoding stripped, got %v", removed)
		}

		// Phase 2: RequestBody ($35 within $50 bound) -> CONTINUE
		reqJSON, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name":      "refund_invoice",
				"arguments": map[string]any{"amount": 35.0},
			},
		})
		_ = stream.Send(&ext_procv3.ProcessingRequest{
			Request: &ext_procv3.ProcessingRequest_RequestBody{
				RequestBody: &ext_procv3.HttpBody{Body: reqJSON, EndOfStream: true},
			},
		})
		r2, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv phase 2: %v", err)
		}
		if r2.GetImmediateResponse() != nil {
			t.Fatalf("expected valid $35 refund to CONTINUE, got ImmediateResponse: %s", string(r2.GetImmediateResponse().GetBody()))
		}

		// Phase 3: ResponseHeaders -> must strip content-length
		_ = stream.Send(&ext_procv3.ProcessingRequest{
			Request: &ext_procv3.ProcessingRequest_ResponseHeaders{
				ResponseHeaders: &ext_procv3.HttpHeaders{},
			},
		})
		r3, _ := stream.Recv()
		if rem := r3.GetResponseHeaders().GetResponse().GetHeaderMutation().GetRemoveHeaders(); len(rem) == 0 || rem[0] != "content-length" {
			t.Fatalf("expected content-length removed in response headers, got %v", rem)
		}

		// Phase 4: ResponseBody containing leaked secret -> BodyMutation scrubs it!
		_ = stream.Send(&ext_procv3.ProcessingRequest{
			Request: &ext_procv3.ProcessingRequest_ResponseBody{
				ResponseBody: &ext_procv3.HttpBody{
					Body:        []byte(`{"jsonrpc":"2.0","id":1,"result":{"debug":"` + activeSecret + `"}}`),
					EndOfStream: true,
				},
			},
		})
		r4, _ := stream.Recv()
		mutated := string(r4.GetResponseBody().GetResponse().GetBodyMutation().GetBody())
		if strings.Contains(mutated, activeSecret) || !strings.Contains(mutated, scrub.RedactionMarker) {
			t.Fatalf("expected response body secret redacted via BodyMutation, got: %s", mutated)
		}
		_ = stream.CloseSend()
	}

	// Case B: Forged/spoofed X-OBO-Principal header WITHOUT valid RS256 JWT -> ImmediateResponse -32001!
	{
		stream, _ := client.Process(context.Background())
		_ = stream.Send(&ext_procv3.ProcessingRequest{
			Request: &ext_procv3.ProcessingRequest_RequestHeaders{
				RequestHeaders: &ext_procv3.HttpHeaders{
					Headers: &corev3.HeaderMap{
						Headers: []*corev3.HeaderValue{
							{Key: ":path", Value: "/mcp/vendor-billing"},
							{Key: "x-obo-principal", Value: "user:spoofed-admin@acme.com"},
							{Key: "idempotency-key", Value: "idem-grpc-2"},
						},
					},
				},
			},
		})
		_, _ = stream.Recv()

		reqJSON, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      2,
			"method":  "tools/call",
			"params":  map[string]any{"name": "refund_invoice", "arguments": map[string]any{"amount": 10.0}},
		})
		_ = stream.Send(&ext_procv3.ProcessingRequest{
			Request: &ext_procv3.ProcessingRequest_RequestBody{
				RequestBody: &ext_procv3.HttpBody{Body: reqJSON, EndOfStream: true},
			},
		})
		r2, _ := stream.Recv()
		imm := r2.GetImmediateResponse()
		if imm == nil || !strings.Contains(string(imm.GetBody()), "-32001") {
			t.Fatalf("expected spoofed header without valid RS256 JWT to be blocked with -32001, got: %v", r2)
		}
		_ = stream.CloseSend()
	}

	// Case C: Valid RS256 JWT but $120 exceeds $50 ceiling -> ImmediateResponse -32002 (MRTR escalation)
	{
		stream, _ := client.Process(context.Background())
		_ = stream.Send(&ext_procv3.ProcessingRequest{
			Request: &ext_procv3.ProcessingRequest_RequestHeaders{
				RequestHeaders: &ext_procv3.HttpHeaders{
					Headers: &corev3.HeaderMap{
						Headers: []*corev3.HeaderValue{
							{Key: ":path", Value: "/mcp/vendor-billing"},
							{Key: "authorization", Value: "Bearer " + validJWT},
							{Key: "idempotency-key", Value: "idem-grpc-3"},
						},
					},
				},
			},
		})
		_, _ = stream.Recv()

		reqJSON, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      3,
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
		if imm == nil || !strings.Contains(string(imm.GetBody()), "-32002") {
			t.Fatalf("expected $120 refund to trigger MRTR -32002, got: %v", r2)
		}
		_ = stream.CloseSend()
	}

	// Case D: Response-phase live `tools/list` third-party rug pull -> ImmediateResponse -32001!
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

		rugResp, _ := json.Marshal(map[string]any{
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
		_ = stream.Send(&ext_procv3.ProcessingRequest{
			Request: &ext_procv3.ProcessingRequest_ResponseBody{
				ResponseBody: &ext_procv3.HttpBody{Body: rugResp, EndOfStream: true},
			},
		})
		rResp, _ := stream.Recv()
		imm := rResp.GetImmediateResponse()
		if imm == nil || !strings.Contains(string(imm.GetBody()), "-32001") {
			t.Fatalf("expected response-phase tools/list rug pull blocked with -32001, got: %v", rResp)
		}
		_ = stream.CloseSend()
	}
}
