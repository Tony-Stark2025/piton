package proxy

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Tony-Stark2025/piton/sidecar/internal/policy"
	"github.com/Tony-Stark2025/piton/sidecar/internal/scrub"
)

const maxBodyBytes = 10 << 20 // 10 MiB safety limit against memory exhaustion

// Server implements the Piton HTTP sidecar endpoints:
//  1. `/mcp/{server}` — Bidirectional MCP proxy (JSON + SSE tools/list pinning, MRTR, bounds)
//  2. `/gw/{slot}/{path...}` — Zero-secret reverse proxy (constant-time ghost check, strict `/` prefix,
//     no-redirect, compressed-response rejection, sliding-window scrubbing of ALL active secrets)
//  3. `/healthz` & `/metrics` — K8s health & OpenMetrics exposition
type Server struct {
	Engine      *policy.Engine
	HTTPClient  *http.Client
	GhostTokens map[string]string
	Mux         *http.ServeMux
}

func NewServer(engine *policy.Engine, ghostTokens map[string]string) *Server {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DisableCompression: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	s := &Server{
		Engine:      engine,
		HTTPClient:  client,
		GhostTokens: ghostTokens,
		Mux:         http.NewServeMux(),
	}
	s.Mux.HandleFunc("/healthz", s.handleHealthz)
	s.Mux.HandleFunc("/metrics", s.handleMetrics)
	s.Mux.HandleFunc("/gw/", s.handleGatewayProxy)
	s.Mux.HandleFunc("/mcp/", s.handleMCPProxy)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.Mux.ServeHTTP(w, r)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":          "ok",
		"agent_id":        s.Engine.Config.Agent.ID,
		"mode":            s.Engine.Config.Agent.Mode,
		"policy_sha256":   s.Engine.PolicySHA256,
		"lockfile_sha256": s.Engine.LockfileSHA256,
		"oidc_jwks":       s.Engine.OIDCVerifier != nil,
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	m := &s.Engine.Metrics
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# TYPE piton_sidecar_requests_total counter\npiton_sidecar_requests_total %d\n", m.RequestsTotal.Load())
	fmt.Fprintf(w, "# TYPE piton_sidecar_allowed_total counter\npiton_sidecar_allowed_total %d\n", m.AllowedTotal.Load())
	fmt.Fprintf(w, "# TYPE piton_sidecar_shadow_denied_total counter\npiton_sidecar_shadow_denied_total %d\n", m.ShadowDeniedTotal.Load())
	fmt.Fprintf(w, "# TYPE piton_sidecar_denied_total counter\npiton_sidecar_denied_total %d\n", m.DeniedTotal.Load())
	fmt.Fprintf(w, "# TYPE piton_sidecar_mrtr_escalated_total counter\npiton_sidecar_mrtr_escalated_total %d\n", m.MRTREscalated.Load())
	fmt.Fprintf(w, "# TYPE piton_sidecar_rug_pulls_blocked_total counter\npiton_sidecar_rug_pulls_blocked_total %d\n", m.RugPullsBlocked.Load())
	fmt.Fprintf(w, "# TYPE piton_sidecar_secrets_redacted_total counter\npiton_sidecar_secrets_redacted_total %d\n", m.SecretsRedacted.Load())
	fmt.Fprintf(w, "# TYPE piton_sidecar_bytes_projected_total counter\npiton_sidecar_bytes_projected_total %d\n", m.BytesProjected.Load())
}

func resolveSecret(source string) (string, error) {
	if strings.HasPrefix(source, "env://") {
		varName := strings.TrimPrefix(source, "env://")
		val := os.Getenv(varName)
		if val == "" {
			return "", fmt.Errorf("environment variable %s is empty", varName)
		}
		return val, nil
	}
	if strings.HasPrefix(source, "file://") {
		p := strings.TrimPrefix(source, "file://")
		b, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", fmt.Errorf("unsupported secret source scheme: %s", source)
}

func (s *Server) ActiveSecrets() []string {
	var out []string
	for _, slot := range s.Engine.Config.LocalDevCredentials {
		if sec, err := resolveSecret(slot.Source); err == nil && sec != "" {
			out = append(out, sec)
		}
	}
	return out
}

// matchPathPrefix enforces strict `/` segment boundaries (`/v1/refunds` matches
// `/v1/refunds` or `/v1/refunds/123`, NEVER `/v1/refunds_admin`).
func matchPathPrefix(relPath, prefix string) bool {
	if prefix == "/" {
		return strings.HasPrefix(relPath, "/")
	}
	trimmed := strings.TrimRight(prefix, "/")
	if relPath == trimmed {
		return true
	}
	return strings.HasPrefix(relPath, trimmed+"/")
}

func constantTimeMatchesGhost(r *http.Request, expectedGhost string) bool {
	exp := []byte(expectedGhost)
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		got := []byte(strings.TrimSpace(auth[7:]))
		if len(got) == len(exp) && subtle.ConstantTimeCompare(got, exp) == 1 {
			return true
		}
	}
	apiKey := []byte(strings.TrimSpace(r.Header.Get("X-API-Key")))
	if len(apiKey) == len(exp) && subtle.ConstantTimeCompare(apiKey, exp) == 1 {
		return true
	}
	return false
}

// ============================================================================
// 1. Zero-Secret Reverse Proxy (`/gw/{slot}/{path...}`)
// ============================================================================

func (s *Server) handleGatewayProxy(w http.ResponseWriter, r *http.Request) {
	if len(r.Header.Values("Host")) > 1 {
		http.Error(w, `{"error":"ambiguous_host_header"}`, http.StatusBadRequest)
		return
	}

	// Use EscapedPath so `%23`/`%3f`/`..` cannot smuggle fragments, query injection, or traversal
	escaped := r.URL.EscapedPath()
	lowerEsc := strings.ToLower(escaped)
	if strings.Contains(lowerEsc, "%23") || strings.Contains(lowerEsc, "%3f") || strings.Contains(escaped, "..") || strings.Contains(escaped, "@") {
		http.Error(w, `{"error":"unsafe_encoded_path"}`, http.StatusForbidden)
		return
	}

	trimmed := strings.TrimPrefix(escaped, "/gw/")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, `{"error":"missing_credential_slot"}`, http.StatusBadRequest)
		return
	}
	slotName := parts[0]
	relPath := "/"
	if len(parts) == 2 {
		relPath = "/" + parts[1]
	}

	slot, ok := s.Engine.Config.LocalDevCredentials[slotName]
	if !ok {
		http.Error(w, `{"error":"unknown_credential_slot"}`, http.StatusNotFound)
		return
	}

	if len(slot.AllowedMethods) > 0 {
		allowed := false
		for _, m := range slot.AllowedMethods {
			if strings.EqualFold(m, r.Method) {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, `{"error":"method_not_allowed_for_slot"}`, http.StatusForbidden)
			return
		}
	}

	if len(slot.AllowedPathPrefixes) > 0 {
		allowed := false
		for _, pfx := range slot.AllowedPathPrefixes {
			if matchPathPrefix(relPath, pfx) {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, `{"error":"path_prefix_not_allowed_for_slot"}`, http.StatusForbidden)
			return
		}
	}

	upstreamBase, err := url.Parse(strings.TrimRight(slot.UpstreamBaseURL, "/"))
	if err != nil || upstreamBase.Hostname() == "" {
		http.Error(w, `{"error":"invalid_upstream_base_url"}`, http.StatusBadGateway)
		return
	}
	if len(slot.AllowedHosts) > 0 {
		hostOK := false
		for _, h := range slot.AllowedHosts {
			if strings.EqualFold(h, upstreamBase.Hostname()) {
				hostOK = true
				break
			}
		}
		if !hostOK {
			http.Error(w, `{"error":"upstream_host_not_allowlisted"}`, http.StatusForbidden)
			return
		}
	}

	if expectedGhost, hasGhost := s.GhostTokens[slotName]; hasGhost && expectedGhost != "" {
		if !constantTimeMatchesGhost(r, expectedGhost) {
			http.Error(w, `{"error":"invalid_ghost_token"}`, http.StatusUnauthorized)
			return
		}
	}

	realSecret, err := resolveSecret(slot.Source)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"secret_resolution_failed","detail":%q}`, err.Error()), http.StatusBadGateway)
		return
	}

	targetURL := upstreamBase.String() + relPath
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, `{"error":"upstream_request_build_failed"}`, http.StatusBadGateway)
		return
	}
	for k, vals := range r.Header {
		kl := strings.ToLower(k)
		if kl == "host" || kl == "accept-encoding" || kl == "authorization" || kl == "x-api-key" {
			continue
		}
		for _, v := range vals {
			upReq.Header.Add(k, v)
		}
	}
	upReq.Header.Set("Authorization", "Bearer "+realSecret)

	upResp, err := s.HTTPClient.Do(upReq)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"upstream_dispatch_failed","detail":%q}`, err.Error()), http.StatusBadGateway)
		return
	}
	defer upResp.Body.Close()

	if !slot.FollowRedirects && upResp.StatusCode >= 300 && upResp.StatusCode < 400 {
		http.Error(w, `{"error":"upstream_redirect_blocked_by_broker"}`, http.StatusBadGateway)
		return
	}

	// Refuse compressed responses when response scrubbing is enabled so gzip cannot hide secrets
	if ce := strings.ToLower(strings.TrimSpace(upResp.Header.Get("Content-Encoding"))); slot.RedactInResponses && ce != "" && ce != "identity" {
		http.Error(w, `{"error":"compressed_upstream_response_rejected"}`, http.StatusBadGateway)
		return
	}

	secretsToScrub := s.ActiveSecrets()
	for k, vals := range upResp.Header {
		kl := strings.ToLower(k)
		if slot.RedactInResponses && kl == "content-length" {
			continue
		}
		for _, v := range vals {
			if slot.RedactInResponses {
				scrubbedVal, hits := scrub.ScrubBytes([]byte(v), secretsToScrub)
				if hits > 0 {
					s.Engine.Metrics.SecretsRedacted.Add(int64(hits))
				}
				v = string(scrubbedVal)
			}
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(upResp.StatusCode)

	if !slot.RedactInResponses {
		_, _ = io.Copy(w, io.LimitReader(upResp.Body, maxBodyBytes))
		return
	}

	scrubber := scrub.NewSlidingWindowScrubber(w, secretsToScrub)
	buf := make([]byte, 4096)
	flusher, canFlush := w.(http.Flusher)
	limited := io.LimitReader(upResp.Body, maxBodyBytes)
	for {
		n, readErr := limited.Read(buf)
		if n > 0 {
			_, _ = scrubber.Write(buf[:n])
			if canFlush {
				flusher.Flush()
			}
		}
		if readErr != nil {
			break
		}
	}
	_ = scrubber.Flush()
	if scrubber.RedactedHits > 0 {
		s.Engine.Metrics.SecretsRedacted.Add(int64(scrubber.RedactedHits))
	}
	if canFlush {
		flusher.Flush()
	}
}

// ============================================================================
// 2. Bidirectional MCP HTTP Proxy (`/mcp/{server_name}`)
// ============================================================================

type jsonRPCRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      any            `json:"id"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params,omitempty"`
}

func writeJSONRPCError(w http.ResponseWriter, id any, code int, message string, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": message,
			"data":    data,
		},
	})
}

func (s *Server) handleMCPProxy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	serverName := strings.Trim(strings.TrimPrefix(r.URL.Path, "/mcp/"), "/")
	srvCfg, ok := s.Engine.Config.MCPServers[serverName]
	if !ok || srvCfg.URL == "" {
		http.Error(w, `{"error":"unknown_mcp_server"}`, http.StatusNotFound)
		return
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, `{"error":"failed_to_read_body"}`, http.StatusBadRequest)
		return
	}

	trimmedBody := bytes.TrimSpace(bodyBytes)
	if len(trimmedBody) > 0 && trimmedBody[0] == '[' {
		writeJSONRPCError(w, nil, -32600, "JSON-RPC batch requests are not permitted by Piton policy", nil)
		return
	}

	var rpcReq jsonRPCRequest
	if err := json.Unmarshal(trimmedBody, &rpcReq); err != nil {
		http.Error(w, `{"error":"invalid_jsonrpc"}`, http.StatusBadRequest)
		return
	}

	traceparent := r.Header.Get(s.Engine.Config.Identity.CorrelateHeader)
	if traceparent == "" {
		traceparent = fmt.Sprintf("00-%016x-01", time.Now().UnixNano())
	}
	oboPrincipal := s.Engine.ResolveOBOPrincipal(r.Context(), r.Header)
	idemKey := r.Header.Get("Idempotency-Key")

	if rpcReq.Method == "tools/call" {
		toolName, _ := rpcReq.Params["name"].(string)
		argsMap, _ := rpcReq.Params["arguments"].(map[string]any)
		if argsMap == nil {
			argsMap = map[string]any{}
		}
		if idemKey == "" {
			if ik, ok := argsMap["idempotency_key"].(string); ok {
				idemKey = ik
			}
		}
		mrtrTok := r.Header.Get("X-Piton-MRTR-Approval")
		if mrtrTok == "" {
			if irs, ok := rpcReq.Params["inputResponses"].([]any); ok && len(irs) > 0 {
				if first, ok := irs[0].(map[string]any); ok {
					if tok, ok := first["approval_token"].(string); ok {
						mrtrTok = tok
					}
				}
			}
		}

		ev := s.Engine.EvaluateToolCall(traceparent, serverName, toolName, argsMap, oboPrincipal, idemKey, mrtrTok)
		latMs := float64(time.Since(start).Microseconds()) / 1000.0
		_, _ = s.Engine.AppendLedgerRecord(traceparent, serverName, toolName, argsMap, ev, oboPrincipal, idemKey, latMs)

		if ev.Verdict == "deny" {
			writeJSONRPCError(w, rpcReq.ID, -32001, "Piton Policy Denial", ev)
			return
		}
		if ev.Verdict == "mrtr_escalate" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(s.Engine.BuildMRTRInputRequiredPayload(rpcReq.ID, serverName, toolName, argsMap, oboPrincipal, ev))
			return
		}
	}

	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, srvCfg.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, `{"error":"mcp_upstream_build_failed"}`, http.StatusBadGateway)
		return
	}
	upReq.Header.Set("Content-Type", "application/json")
	upReq.Header.Set("Accept", "application/json, text/event-stream")
	upReq.Header.Set("MCP-Protocol-Version", "2026-07-28")
	upReq.Header.Set("Mcp-Method", rpcReq.Method)
	upReq.Header.Set("traceparent", traceparent)
	if auth := r.Header.Get("Authorization"); auth != "" {
		upReq.Header.Set("Authorization", auth)
	}

	upResp, err := s.HTTPClient.Do(upReq)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"mcp_upstream_failed","detail":%q}`, err.Error()), http.StatusBadGateway)
		return
	}
	defer upResp.Body.Close()

	if ce := strings.ToLower(strings.TrimSpace(upResp.Header.Get("Content-Encoding"))); ce != "" && ce != "identity" {
		writeJSONRPCError(w, rpcReq.ID, -32001, "Compressed upstream MCP response rejected", map[string]any{"content_encoding": ce})
		return
	}

	respBytes, err := io.ReadAll(io.LimitReader(upResp.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, `{"error":"mcp_response_read_failed"}`, http.StatusBadGateway)
		return
	}

	respContentType := upResp.Header.Get("Content-Type")
	if rpcReq.Method == "tools/list" {
		if toolsList, ok := policy.ExtractToolsFromMCPResponse(respBytes, respContentType); ok {
			passed, drifts := s.Engine.VerifyToolsListResponse(serverName, toolsList)
			if !passed && s.Engine.Config.Agent.Mode == "enforce" {
				writeJSONRPCError(w, rpcReq.ID, -32001, "MCP Manifest Pin Drift / Rug Pull Blocked", map[string]any{
					"server_name": serverName,
					"drifts":      drifts,
				})
				return
			}
			if len(drifts) > 0 {
				w.Header().Set("X-Piton-Manifest-Warnings", fmt.Sprintf("%d", len(drifts)))
			}
		}
	}

	if rpcReq.Method == "tools/call" {
		if toolName, ok := rpcReq.Params["name"].(string); ok && toolName != "" {
			respBytes, _ = s.Engine.ProjectMCPToolResponse(serverName, toolName, respBytes)
		}
	}

	secrets := s.ActiveSecrets()
	if len(secrets) > 0 {
		var hits int
		respBytes, hits = scrub.ScrubBytes(respBytes, secrets)
		if hits > 0 {
			s.Engine.Metrics.SecretsRedacted.Add(int64(hits))
		}
	}

	if respContentType == "" {
		respContentType = "application/json"
	}
	w.Header().Set("Content-Type", respContentType)
	w.WriteHeader(upResp.StatusCode)
	_, _ = w.Write(respBytes)
}
