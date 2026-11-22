package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Tony-Stark2025/prometheus-enterprise/sidecar/internal/policy"
	"github.com/Tony-Stark2025/prometheus-enterprise/sidecar/internal/scrub"
)

// Server implements the Prometheus bidirectional inline sidecar:
//  1. `/mcp/{server}` — Bidirectional MCP Streamable HTTP proxy (request bounds + live tools/list pinning)
//  2. `/gw/{slot}/{path...}` — Zero-secret reverse proxy (ghost token swap, host/method/path check,
//     no-redirect guard, Accept-Encoding strip, sliding-window response secret scrubbing)
//  3. `/ext_proc` & `/ext_mcp` — Bidirectional Envoy ext_proc / agentgateway ExtMcp adapter
//  4. `/healthz` — Health & policy hash introspection
type Server struct {
	Engine      *policy.Engine
	HTTPClient  *http.Client
	GhostTokens map[string]string // slot -> expected ghost token (optional verification)
	Mux         *http.ServeMux
}

func NewServer(engine *policy.Engine, ghostTokens map[string]string) *Server {
	// Never follow 3xx redirects and disable auto Accept-Encoding: gzip so upstream
	// compressed bodies can never smuggle secrets past the sliding-window scrubber.
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
	s.Mux.HandleFunc("/gw/", s.handleGatewayProxy)
	s.Mux.HandleFunc("/mcp/", s.handleMCPProxy)
	s.Mux.HandleFunc("/ext_proc", s.handleExtBidirectional)
	s.Mux.HandleFunc("/ext_mcp", s.handleExtBidirectional)
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
	})
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

func (s *Server) activeSecrets() []string {
	return s.ActiveSecrets()
}

// ============================================================================
// 1. Zero-Secret Reverse Proxy (`/gw/{slot}/{path...}`)
// ============================================================================

func (s *Server) handleGatewayProxy(w http.ResponseWriter, r *http.Request) {
	// Reject ambiguous multi-Host smuggling
	if len(r.Header.Values("Host")) > 1 {
		http.Error(w, `{"error":"ambiguous_host_header"}`, http.StatusBadRequest)
		return
	}

	trimmed := strings.TrimPrefix(r.URL.Path, "/gw/")
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

	// Reject URL userinfo (`@`) smuggling in path
	if strings.Contains(relPath, "@") {
		http.Error(w, `{"error":"userinfo_not_permitted"}`, http.StatusForbidden)
		return
	}

	// Verify HTTP method allowlist
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

	// Verify path prefix allowlist
	if len(slot.AllowedPathPrefixes) > 0 {
		allowed := false
		for _, pfx := range slot.AllowedPathPrefixes {
			if strings.HasPrefix(relPath, pfx) {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, `{"error":"path_prefix_not_allowed_for_slot"}`, http.StatusForbidden)
			return
		}
	}

	// Verify target upstream host matches allowed_hosts
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

	// If a ghost token is registered for this slot, verify caller presented it (fail closed)
	if expectedGhost, hasGhost := s.GhostTokens[slotName]; hasGhost && expectedGhost != "" {
		authHdr := r.Header.Get("Authorization")
		apiKeyHdr := r.Header.Get("X-API-Key")
		if !strings.Contains(authHdr, expectedGhost) && apiKeyHdr != expectedGhost {
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

	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, `{"error":"upstream_request_build_failed"}`, http.StatusBadGateway)
		return
	}
	for k, vals := range r.Header {
		kl := strings.ToLower(k)
		// Strip Accept-Encoding so compressed upstream bodies cannot hide leaked secrets
		if kl == "host" || kl == "accept-encoding" || kl == "authorization" || kl == "x-api-key" {
			continue
		}
		for _, v := range vals {
			upReq.Header.Add(k, v)
		}
	}
	// Inject real credential exclusively at the gateway egress boundary
	upReq.Header.Set("Authorization", "Bearer "+realSecret)

	upResp, err := s.HTTPClient.Do(upReq)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"upstream_dispatch_failed","detail":%q}`, err.Error()), http.StatusBadGateway)
		return
	}
	defer upResp.Body.Close()

	// Refuse 3xx redirects rather than forwarding credentials or leaking redirect targets
	if !slot.FollowRedirects && upResp.StatusCode >= 300 && upResp.StatusCode < 400 {
		http.Error(w, `{"error":"upstream_redirect_blocked_by_broker"}`, http.StatusBadGateway)
		return
	}

	secretsToScrub := []string{realSecret}
	for k, vals := range upResp.Header {
		kl := strings.ToLower(k)
		// Drop Content-Length when redacting so modified chunked streams never corrupt framing
		if slot.RedactInResponses && kl == "content-length" {
			continue
		}
		for _, v := range vals {
			if slot.RedactInResponses {
				scrubbedVal, _ := scrub.ScrubBytes([]byte(v), secretsToScrub)
				v = string(scrubbedVal)
			}
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(upResp.StatusCode)

	if !slot.RedactInResponses {
		_, _ = io.Copy(w, upResp.Body)
		return
	}

	scrubber := scrub.NewSlidingWindowScrubber(w, secretsToScrub)
	buf := make([]byte, 4096)
	flusher, canFlush := w.(http.Flusher)
	for {
		n, readErr := upResp.Body.Read(buf)
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
	w.WriteHeader(http.StatusOK) // MCP JSON-RPC carries protocol errors in the JSON-RPC envelope
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

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"failed_to_read_body"}`, http.StatusBadRequest)
		return
	}

	var rpcReq jsonRPCRequest
	if err := json.Unmarshal(bodyBytes, &rpcReq); err != nil {
		http.Error(w, `{"error":"invalid_jsonrpc"}`, http.StatusBadRequest)
		return
	}

	traceparent := r.Header.Get(s.Engine.Config.Identity.CorrelateHeader)
	if traceparent == "" {
		traceparent = fmt.Sprintf("00-%016x-01", time.Now().UnixNano())
	}
	oboPrincipal := s.Engine.ResolveOBOPrincipal(r.Context(), r.Header)
	idemKey := r.Header.Get("Idempotency-Key")

	// Request phase: evaluate parameter bounds & OBO identity for tools/call
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

		ev := s.Engine.EvaluateToolCall(traceparent, serverName, toolName, argsMap, oboPrincipal, idemKey)
		latMs := float64(time.Since(start).Microseconds()) / 1000.0
		_, _ = s.Engine.AppendLedgerRecord(traceparent, serverName, toolName, argsMap, ev, oboPrincipal, idemKey, latMs)

		if ev.Verdict == "deny" {
			writeJSONRPCError(w, rpcReq.ID, -32001, "Prometheus Policy Denial", ev)
			return
		}
		if ev.Verdict == "mrtr_escalate" {
			writeJSONRPCError(w, rpcReq.ID, -32002, "Prometheus MRTR Out-of-Band Approval Required", ev)
			return
		}
	}

	// Forward upstream MCP request (stripping Accept-Encoding for response inspection/scrubbing)
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, srvCfg.URL, bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, `{"error":"mcp_upstream_build_failed"}`, http.StatusBadGateway)
		return
	}
	upReq.Header.Set("Content-Type", "application/json")
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

	respBytes, err := io.ReadAll(upResp.Body)
	if err != nil {
		http.Error(w, `{"error":"mcp_response_read_failed"}`, http.StatusBadGateway)
		return
	}

	// Response phase 1: verify live `tools/list` against `prometheus.lock` (blocks rug pulls!)
	if rpcReq.Method == "tools/list" {
		var rpcResp map[string]any
		if json.Unmarshal(respBytes, &rpcResp) == nil {
			if resultObj, ok := rpcResp["result"].(map[string]any); ok {
				if rawTools, ok := resultObj["tools"].([]any); ok {
					toolsList := make([]map[string]any, 0, len(rawTools))
					for _, item := range rawTools {
						if m, ok := item.(map[string]any); ok {
							toolsList = append(toolsList, m)
						}
					}
					passed, drifts := s.Engine.VerifyToolsListResponse(serverName, toolsList)
					if !passed && s.Engine.Config.Agent.Mode == "enforce" {
						writeJSONRPCError(w, rpcReq.ID, -32001, "MCP Manifest Pin Drift / Rug Pull Blocked", map[string]any{
							"server_name": serverName,
							"drifts":      drifts,
						})
						return
					}
					if len(drifts) > 0 {
						w.Header().Set("X-Prometheus-Manifest-Warnings", fmt.Sprintf("%d", len(drifts)))
					}
				}
			}
		}
	}

	// Response phase 2: scrub any active secrets before returning to agent
	secrets := s.activeSecrets()
	if len(secrets) > 0 {
		respBytes, _ = scrub.ScrubBytes(respBytes, secrets)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(upResp.StatusCode)
	_, _ = w.Write(respBytes)
}

// ============================================================================
// 3. Bidirectional Envoy `ext_proc` / agentgateway `ExtMcp` Decision Endpoint
// ============================================================================

type ExtDecisionRequest struct {
	Phase          string            `json:"phase"` // "request" | "response"
	ServerName     string            `json:"server_name"`
	Method         string            `json:"method"` // "tools/call" | "tools/list"
	ToolName       string            `json:"tool_name,omitempty"`
	Arguments      map[string]any    `json:"arguments,omitempty"`
	ToolsList      []map[string]any  `json:"tools_list,omitempty"`
	ResponseBody   string            `json:"response_body,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	IdempotencyKey string            `json:"idempotency_key,omitempty"`
}

func (s *Server) handleExtBidirectional(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req ExtDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_ext_payload"}`, http.StatusBadRequest)
		return
	}

	hdr := http.Header{}
	for k, v := range req.Headers {
		hdr.Set(k, v)
	}
	traceparent := hdr.Get(s.Engine.Config.Identity.CorrelateHeader)
	if traceparent == "" {
		traceparent = fmt.Sprintf("00-%016x-01", time.Now().UnixNano())
	}

	w.Header().Set("Content-Type", "application/json")
	if req.Phase == "response" {
		if req.Method == "tools/list" {
			passed, drifts := s.Engine.VerifyToolsListResponse(req.ServerName, req.ToolsList)
			action := "continue"
			if !passed && s.Engine.Config.Agent.Mode == "enforce" {
				action = "block"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"phase":          "response",
				"action":         action,
				"jsonrpc_code":   -32001,
				"drifts":         drifts,
				"lockfile_sha":   s.Engine.LockfileSHA256,
			})
			return
		}
		scrubbed, hits := scrub.ScrubBytes([]byte(req.ResponseBody), s.activeSecrets())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"phase":         "response",
			"action":        "continue",
			"redacted_hits": hits,
			"response_body": string(scrubbed),
		})
		return
	}

	// Default: request phase
	obo := s.Engine.ResolveOBOPrincipal(r.Context(), hdr)
	ev := s.Engine.EvaluateToolCall(traceparent, req.ServerName, req.ToolName, req.Arguments, obo, req.IdempotencyKey)
	latMs := float64(time.Since(start).Microseconds()) / 1000.0
	rec, _ := s.Engine.AppendLedgerRecord(traceparent, req.ServerName, req.ToolName, req.Arguments, ev, obo, req.IdempotencyKey, latMs)

	action := "continue"
	rpcCode := 0
	if ev.Verdict == "deny" {
		action = "block"
		rpcCode = -32001
	} else if ev.Verdict == "mrtr_escalate" {
		action = "mrtr_escalate"
		rpcCode = -32002
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"phase":         "request",
		"action":        action,
		"verdict":       ev.Verdict,
		"jsonrpc_code":  rpcCode,
		"violations":    ev.Violations,
		"record_hmac":   rec.RecordHMAC,
		"policy_sha256": s.Engine.PolicySHA256,
	})
}
