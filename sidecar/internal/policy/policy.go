package policy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Policy structures mirror `prometheus/iac/schema.py` 1:1 so compiled runtime_policy.json
// and prometheus.lock evaluate identically across Python CLI and Go hot path.

type AgentMeta struct {
	ID    string `json:"id"`
	Owner string `json:"owner"`
	Mode  string `json:"mode"` // "shadow" | "enforce"
}

type IdentityConfig struct {
	Mode                string `json:"mode"` // "oidc_obo" | "local_dev"
	Issuer              string `json:"issuer,omitempty"`
	RequireDelegatedSub bool   `json:"require_delegated_sub"`
	CorrelateHeader     string `json:"correlate_header"`
}

type LocalDevCredentialSlot struct {
	GhostFormat         string   `json:"ghost_format"`
	Source              string   `json:"source"`
	UpstreamBaseURL     string   `json:"upstream_base_url"`
	AllowedHosts        []string `json:"allowed_hosts"`
	AllowedMethods      []string `json:"allowed_methods"`
	AllowedPathPrefixes []string `json:"allowed_path_prefixes"`
	FollowRedirects     bool     `json:"follow_redirects"`
	RedactInResponses   bool     `json:"redact_in_responses"`
}

type ParameterBound struct {
	Min          *float64 `json:"min,omitempty"`
	Max          *float64 `json:"max,omitempty"`
	Enum         []any    `json:"enum,omitempty"`
	AllowDomains []string `json:"allow_domains,omitempty"`
	DenyDomains  []string `json:"deny_domains,omitempty"`
	Regex        string   `json:"regex,omitempty"`
	MaxLength    *int     `json:"max_length,omitempty"`
}

type RateLimitPolicy struct {
	MaxCallsPerTrace *int `json:"max_calls_per_trace,omitempty"`
}

type ToolPolicy struct {
	Tier            string                    `json:"tier"`
	IdempotencyKey  string                    `json:"idempotency_key,omitempty"`
	ParameterBounds map[string]ParameterBound `json:"parameter_bounds,omitempty"`
	RateLimit       *RateLimitPolicy          `json:"rate_limit,omitempty"`
	OnBoundExceeded string                    `json:"on_bound_exceeded,omitempty"`
}

type MCPServerPolicy struct {
	URL       string                `json:"url,omitempty"`
	Command   string                `json:"command,omitempty"`
	Args      []string              `json:"args,omitempty"`
	TrustTier string                `json:"trust_tier"` // "internal" | "third_party"
	Tools     map[string]ToolPolicy `json:"tools,omitempty"`
}

type AgentIaCConfig struct {
	Version             string                            `json:"version"`
	Agent               AgentMeta                         `json:"agent"`
	Identity            IdentityConfig                    `json:"identity"`
	LocalDevCredentials map[string]LocalDevCredentialSlot `json:"local_dev_credentials,omitempty"`
	MCPServers          map[string]MCPServerPolicy        `json:"mcp_servers,omitempty"`
}

type PinnedToolEntry struct {
	StructuralSHA256    string   `json:"structural_sha256"`
	DescriptionSHA256   string   `json:"description_sha256"`
	DescriptionPreview  string   `json:"description_preview"`
	PoisoningLintPassed bool     `json:"poisoning_lint_passed"`
	PoisoningWarnings   []string `json:"poisoning_warnings,omitempty"`
}

type PinnedServerManifest struct {
	TrustTier string                     `json:"trust_tier"`
	URL       string                     `json:"url,omitempty"`
	Tools     map[string]PinnedToolEntry `json:"tools"`
}

type ManifestLockfile struct {
	Version     string                          `json:"version"`
	GeneratedAt float64                         `json:"generated_at"`
	Servers     map[string]PinnedServerManifest `json:"servers"`
}

type RuleViolation struct {
	RuleID            string  `json:"rule_id"`
	Parameter         *string `json:"parameter"`
	Message           string  `json:"message"`
	ObservedValue     any     `json:"observed_value"`
	ConfiguredBound   any     `json:"configured_bound"`
	RecommendedAction string  `json:"recommended_action"`
}

type EvaluationResult struct {
	Verdict    string          `json:"verdict"` // "allow" | "shadow_deny" | "mrtr_escalate" | "deny"
	Violations []RuleViolation `json:"violations"`
	ServerName string          `json:"server_name"`
	ToolName   string          `json:"tool_name"`
}

type DecisionLedgerRecord struct {
	Timestamp          float64         `json:"timestamp"`
	AgentID            string          `json:"agent_id"`
	Traceparent        string          `json:"traceparent"`
	OBOPrincipal       *string         `json:"obo_principal"`
	ServerName         string          `json:"server_name"`
	ToolName           string          `json:"tool_name"`
	TokenizedArguments map[string]any  `json:"tokenized_arguments"`
	IdempotencyKey     *string         `json:"idempotency_key"`
	InputSHA256        string          `json:"input_sha256"`
	PolicySHA256       string          `json:"policy_sha256"`
	LockfileSHA256     string          `json:"lockfile_sha256"`
	Verdict            string          `json:"verdict"`
	Violations         []RuleViolation `json:"violations"`
	LatencyMs          float64         `json:"latency_ms"`
	PrevRecordHMAC     string          `json:"prev_record_hmac"`
	RecordHMAC         string          `json:"record_hmac"`
}

// Engine executes sub-millisecond parameter-bound evaluation, split-hash MCP pinning,
// OIDC/OBO principal extraction, and HMAC-chained ledger recording.
type Engine struct {
	Config         AgentIaCConfig
	Lockfile       *ManifestLockfile
	PolicySHA256   string
	LockfileSHA256 string

	ledgerPath    string
	signingKey    []byte
	tokenizerKey  []byte
	mu            sync.Mutex
	traceCounts   map[string]int
	seenIdemKeys  map[string]struct{}
	lastRecordMac string
}

func NewEngine(cfg AgentIaCConfig, lock *ManifestLockfile, ledgerPath string, signingKey, tokenizerKey []byte) (*Engine, error) {
	if len(signingKey) == 0 {
		signingKey = []byte("prometheus-ledger-signing-key")
	}
	if len(tokenizerKey) == 0 {
		tokenizerKey = []byte("prometheus-default-tokenizer-key")
	}
	policyBytes, err := canonicalJSON(cfg)
	if err != nil {
		return nil, err
	}
	policySum := sha256.Sum256(policyBytes)

	lockSHA := "NONE"
	if lock != nil {
		lockPayload := map[string]any{
			"version": lock.Version,
			"servers": lock.Servers,
		}
		lb, err := canonicalJSON(lockPayload)
		if err != nil {
			return nil, err
		}
		ls := sha256.Sum256(lb)
		lockSHA = hex.EncodeToString(ls[:])
	}

	eng := &Engine{
		Config:         cfg,
		Lockfile:       lock,
		PolicySHA256:   hex.EncodeToString(policySum[:]),
		LockfileSHA256: lockSHA,
		ledgerPath:     ledgerPath,
		signingKey:     signingKey,
		tokenizerKey:   tokenizerKey,
		traceCounts:    make(map[string]int),
		seenIdemKeys:   make(map[string]struct{}),
		lastRecordMac:  "GENESIS",
	}

	// Resume chain if ledger file already exists
	if ledgerPath != "" {
		if raw, err := os.ReadFile(ledgerPath); err == nil {
			lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
			for i := len(lines) - 1; i >= 0; i-- {
				line := strings.TrimSpace(lines[i])
				if line == "" {
					continue
				}
				var rec DecisionLedgerRecord
				if json.Unmarshal([]byte(line), &rec) == nil && rec.RecordHMAC != "" {
					eng.lastRecordMac = rec.RecordHMAC
					break
				}
			}
		}
	}
	return eng, nil
}

func LoadConfigFile(path string) (AgentIaCConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return AgentIaCConfig{}, err
	}
	var cfg AgentIaCConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return AgentIaCConfig{}, err
	}
	if cfg.Identity.CorrelateHeader == "" {
		cfg.Identity.CorrelateHeader = "traceparent"
	}
	return cfg, nil
}

func LoadLockfile(path string) (*ManifestLockfile, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock ManifestLockfile
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}
	return &lock, nil
}

// ExtractOBOPrincipal extracts user+agent principal from either trusted IdP proxy headers
// (X-OBO-Principal / X-Forwarded-User) or an OIDC/OAuth2 Bearer JWT (`sub` + optional `act.sub`).
func ExtractOBOPrincipal(hdr http.Header) string {
	if v := strings.TrimSpace(hdr.Get("X-OBO-Principal")); v != "" {
		return v
	}
	auth := strings.TrimSpace(hdr.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		tok := strings.TrimSpace(auth[7:])
		parts := strings.Split(tok, ".")
		if len(parts) == 3 {
			if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
				var claims map[string]any
				if json.Unmarshal(payload, &claims) == nil {
					if expVal, ok := claims["exp"].(float64); ok {
						if time.Now().Unix() > int64(expVal) {
							return ""
						}
					}
					sub, _ := claims["sub"].(string)
					if sub != "" {
						if act, ok := claims["act"].(map[string]any); ok {
							if actSub, _ := act["sub"].(string); actSub != "" {
								return fmt.Sprintf("user:%s|agent:%s", sub, actSub)
							}
						}
						return "user:" + sub
					}
				}
			}
		}
	}
	if v := strings.TrimSpace(hdr.Get("X-Forwarded-User")); v != "" {
		return "user:" + v
	}
	return ""
}

// EvaluateToolCall deterministically enforces OBO principal, idempotency, per-trace rate limits,
// and parameter bounds in O(1) sub-millisecond time.
func (e *Engine) EvaluateToolCall(
	traceparent string,
	serverName string,
	toolName string,
	arguments map[string]any,
	oboPrincipal string,
	idempotencyKey string,
) EvaluationResult {
	var violations []RuleViolation

	// 1. OIDC/OBO delegated principal requirement
	if e.Config.Identity.Mode == "oidc_obo" && e.Config.Identity.RequireDelegatedSub && oboPrincipal == "" {
		violations = append(violations, RuleViolation{
			RuleID:            "MISSING_OBO_PRINCIPAL",
			Message:           "OIDC/OBO delegated user principal (`sub`/`act`) is required in production.",
			RecommendedAction: "block",
		})
	}

	srvPolicy, hasSrv := e.Config.MCPServers[serverName]
	var toolPolicy ToolPolicy
	var hasTool bool
	if hasSrv {
		toolPolicy, hasTool = srvPolicy.Tools[toolName]
	}

	if hasTool {
		onExceed := toolPolicy.OnBoundExceeded
		if onExceed == "" {
			onExceed = "mrtr_escalate"
		}

		// 2. Single-use idempotency check
		if toolPolicy.IdempotencyKey == "required" {
			if idempotencyKey == "" {
				violations = append(violations, RuleViolation{
					RuleID:            "MISSING_IDEMPOTENCY_KEY",
					Message:           fmt.Sprintf("Bounded write '%s.%s' requires an idempotency key.", serverName, toolName),
					RecommendedAction: "block",
				})
			} else {
				e.mu.Lock()
				idemScoped := serverName + "::" + toolName + "::" + idempotencyKey
				if _, exists := e.seenIdemKeys[idemScoped]; exists {
					violations = append(violations, RuleViolation{
						RuleID:            "DUPLICATE_IDEMPOTENCY_KEY",
						Message:           fmt.Sprintf("Idempotency key '%s' was already executed for '%s.%s'.", idempotencyKey, serverName, toolName),
						ObservedValue:     idempotencyKey,
						RecommendedAction: "block",
					})
				} else if e.Config.Agent.Mode == "enforce" {
					e.seenIdemKeys[idemScoped] = struct{}{}
				}
				e.mu.Unlock()
			}
		}

		// 3. Per-trace call quota
		if toolPolicy.RateLimit != nil && toolPolicy.RateLimit.MaxCallsPerTrace != nil {
			e.mu.Lock()
			ck := traceparent + "::" + serverName + "::" + toolName
			e.traceCounts[ck]++
			count := e.traceCounts[ck]
			e.mu.Unlock()
			if count > *toolPolicy.RateLimit.MaxCallsPerTrace {
				violations = append(violations, RuleViolation{
					RuleID:            "TRACE_RATE_LIMIT_EXCEEDED",
					Message:           fmt.Sprintf("Call #%d to '%s.%s' exceeds max_calls_per_trace=%d.", count, serverName, toolName, *toolPolicy.RateLimit.MaxCallsPerTrace),
					ObservedValue:     count,
					ConfiguredBound:   *toolPolicy.RateLimit.MaxCallsPerTrace,
					RecommendedAction: onExceed,
				})
			}
		}

		// 4. Parameter bounds
		for pname, bound := range toolPolicy.ParameterBounds {
			val, present := arguments[pname]
			if !present {
				continue
			}
			violations = append(violations, checkParamBound(pname, val, bound, onExceed)...)
		}
	}

	verdict := "allow"
	if len(violations) > 0 {
		if e.Config.Agent.Mode == "shadow" {
			verdict = "shadow_deny"
		} else {
			verdict = "allow"
			for _, v := range violations {
				if v.RecommendedAction == "block" {
					verdict = "deny"
					break
				}
				if v.RecommendedAction == "mrtr_escalate" {
					verdict = "mrtr_escalate"
				}
			}
		}
	}

	if violations == nil {
		violations = []RuleViolation{}
	}
	return EvaluationResult{
		Verdict:    verdict,
		Violations: violations,
		ServerName: serverName,
		ToolName:   toolName,
	}
}

func checkParamBound(paramName string, val any, bound ParameterBound, onExceed string) []RuleViolation {
	var out []RuleViolation
	if bound.Min != nil || bound.Max != nil {
		num, ok := toFloat64(val)
		if !ok {
			out = append(out, RuleViolation{
				RuleID:            "PARAM_TYPE_MISMATCH",
				Parameter:         &paramName,
				Message:           fmt.Sprintf("Parameter '%s' expected numeric value.", paramName),
				ObservedValue:     val,
				RecommendedAction: onExceed,
			})
		} else {
			if bound.Min != nil && num < *bound.Min {
				out = append(out, RuleViolation{
					RuleID:            "PARAM_MIN_EXCEEDED",
					Parameter:         &paramName,
					Message:           fmt.Sprintf("Parameter '%s'=%v is below min %v.", paramName, num, *bound.Min),
					ObservedValue:     num,
					ConfiguredBound:   *bound.Min,
					RecommendedAction: onExceed,
				})
			}
			if bound.Max != nil && num > *bound.Max {
				out = append(out, RuleViolation{
					RuleID:            "PARAM_MAX_EXCEEDED",
					Parameter:         &paramName,
					Message:           fmt.Sprintf("Parameter '%s'=%v exceeds max %v.", paramName, num, *bound.Max),
					ObservedValue:     num,
					ConfiguredBound:   *bound.Max,
					RecommendedAction: onExceed,
				})
			}
		}
	}

	if len(bound.Enum) > 0 {
		matched := false
		for _, allowed := range bound.Enum {
			if fmt.Sprintf("%v", allowed) == fmt.Sprintf("%v", val) {
				matched = true
				break
			}
		}
		if !matched {
			out = append(out, RuleViolation{
				RuleID:            "PARAM_ENUM_VIOLATION",
				Parameter:         &paramName,
				Message:           fmt.Sprintf("Parameter '%s'=%v not in allowed enum.", paramName, val),
				ObservedValue:     val,
				ConfiguredBound:   bound.Enum,
				RecommendedAction: onExceed,
			})
		}
	}

	if strVal, ok := val.(string); ok {
		if bound.MaxLength != nil && len(strVal) > *bound.MaxLength {
			out = append(out, RuleViolation{
				RuleID:            "PARAM_MAX_LENGTH_EXCEEDED",
				Parameter:         &paramName,
				Message:           fmt.Sprintf("Parameter '%s' length %d exceeds max_length %d.", paramName, len(strVal), *bound.MaxLength),
				ObservedValue:     len(strVal),
				ConfiguredBound:   *bound.MaxLength,
				RecommendedAction: onExceed,
			})
		}
		if bound.Regex != "" {
			if re, err := regexp.Compile(bound.Regex); err == nil && !re.MatchString(strVal) {
				out = append(out, RuleViolation{
					RuleID:            "PARAM_REGEX_MISMATCH",
					Parameter:         &paramName,
					Message:           fmt.Sprintf("Parameter '%s' failed regex bound.", paramName),
					ObservedValue:     strVal,
					ConfiguredBound:   bound.Regex,
					RecommendedAction: onExceed,
				})
			}
		}
		if len(bound.AllowDomains) > 0 || len(bound.DenyDomains) > 0 {
			dom := extractDomain(strVal)
			for _, denied := range bound.DenyDomains {
				if dom != "" && strings.EqualFold(dom, denied) {
					out = append(out, RuleViolation{
						RuleID:            "PARAM_DOMAIN_DENIED",
						Parameter:         &paramName,
						Message:           fmt.Sprintf("Domain '%s' is explicitly denied.", dom),
						ObservedValue:     dom,
						ConfiguredBound:   bound.DenyDomains,
						RecommendedAction: onExceed,
					})
				}
			}
			if len(bound.AllowDomains) > 0 {
				allowed := false
				for _, ad := range bound.AllowDomains {
					if dom != "" && strings.EqualFold(dom, ad) {
						allowed = true
						break
					}
				}
				if !allowed {
					out = append(out, RuleViolation{
						RuleID:            "PARAM_DOMAIN_NOT_ALLOWED",
						Parameter:         &paramName,
						Message:           fmt.Sprintf("Domain '%s' is not in allow_domains.", dom),
						ObservedValue:     dom,
						ConfiguredBound:   bound.AllowDomains,
						RecommendedAction: onExceed,
					})
				}
			}
		}
	}
	return out
}

// ============================================================================
// Live Bidirectional `tools/list` Split-Hash Verification (matches lockfile.py)
// ============================================================================

type ManifestDrift struct {
	ServerName string `json:"server_name"`
	ToolName   string `json:"tool_name"`
	Kind       string `json:"kind"`
	Action     string `json:"action"` // "block" | "warn"
	Message    string `json:"message"`
}

func stripSchemaDescriptions(obj any) any {
	switch v := obj.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			if k == "description" || k == "title" {
				continue
			}
			out[k] = stripSchemaDescriptions(val)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = stripSchemaDescriptions(item)
		}
		return out
	default:
		return obj
	}
}

func extractSchemaProse(obj any) any {
	switch v := obj.(type) {
	case map[string]any:
		out := make(map[string]any)
		for k, val := range v {
			if (k == "description" || k == "title") {
				if s, ok := val.(string); ok {
					out[k] = strings.TrimSpace(s)
				}
			} else {
				sub := extractSchemaProse(val)
				if m, ok := sub.(map[string]any); ok && len(m) > 0 {
					out[k] = m
				} else if a, ok := sub.([]any); ok && len(a) > 0 {
					out[k] = a
				}
			}
		}
		return out
	case []any:
		var out []any
		for _, item := range v {
			sub := extractSchemaProse(item)
			if m, ok := sub.(map[string]any); ok && len(m) > 0 {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

func ComputeStructuralSHA256(tool map[string]any) string {
	name, _ := tool["name"].(string)
	schema := tool["inputSchema"]
	if schema == nil {
		schema = map[string]any{}
	}
	contract := map[string]any{
		"name":        name,
		"inputSchema": stripSchemaDescriptions(schema),
	}
	b, _ := canonicalJSON(contract)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func ComputeDescriptionSHA256(tool map[string]any) string {
	desc, _ := tool["description"].(string)
	schema := tool["inputSchema"]
	if schema == nil {
		schema = map[string]any{}
	}
	prose := map[string]any{
		"description":  strings.TrimSpace(desc),
		"schema_prose": extractSchemaProse(schema),
	}
	b, _ := canonicalJSON(prose)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// VerifyToolsListResponse checks an upstream MCP `tools/list` response against `prometheus.lock`.
func (e *Engine) VerifyToolsListResponse(serverName string, tools []map[string]any) (bool, []ManifestDrift) {
	if e.Lockfile == nil {
		return true, nil
	}
	pinnedSrv, ok := e.Lockfile.Servers[serverName]
	trustTier := "third_party"
	if ok && pinnedSrv.TrustTier != "" {
		trustTier = pinnedSrv.TrustTier
	} else if srvCfg, exists := e.Config.MCPServers[serverName]; exists && srvCfg.TrustTier != "" {
		trustTier = srvCfg.TrustTier
	}

	var drifts []ManifestDrift
	blocked := false
	for _, tool := range tools {
		tname, _ := tool["name"].(string)
		if tname == "" {
			continue
		}
		obsStruct := ComputeStructuralSHA256(tool)
		obsDesc := ComputeDescriptionSHA256(tool)

		pinned, exists := pinnedSrv.Tools[tname]
		if !exists {
			act := "warn"
			if trustTier == "third_party" {
				act = "block"
				blocked = true
			}
			drifts = append(drifts, ManifestDrift{
				ServerName: serverName,
				ToolName:   tname,
				Kind:       "unpinned_tool",
				Action:     act,
				Message:    fmt.Sprintf("Tool '%s' on server '%s' is not pinned in prometheus.lock.", tname, serverName),
			})
			continue
		}
		if obsStruct != pinned.StructuralSHA256 {
			blocked = true
			drifts = append(drifts, ManifestDrift{
				ServerName: serverName,
				ToolName:   tname,
				Kind:       "structural_drift",
				Action:     "block",
				Message:    fmt.Sprintf("Structural inputSchema drift detected on '%s.%s'.", serverName, tname),
			})
		}
		if obsDesc != pinned.DescriptionSHA256 {
			act := "warn"
			if trustTier == "third_party" {
				act = "block"
				blocked = true
			}
			drifts = append(drifts, ManifestDrift{
				ServerName: serverName,
				ToolName:   tname,
				Kind:       "description_drift",
				Action:     act,
				Message:    fmt.Sprintf("Description drift detected on %s server '%s.%s'.", trustTier, serverName, tname),
			})
		}
	}
	return !blocked, drifts
}

// ============================================================================
// PII-Preserving Deterministic Tokenizer + HMAC-Chained Ledger (Python Parity)
// ============================================================================

var (
	emailRE     = regexp.MustCompile(`^([^@\s]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$`)
	piiKeyHints = []string{"email", "user", "customer", "recipient", "phone", "ssn", "name", "address", "card", "account"}
)

func (e *Engine) hmacHex(key []byte, val string, length int) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(val))
	h := hex.EncodeToString(mac.Sum(nil))
	if length > 0 && length < len(h) {
		return h[:length]
	}
	return h
}

func (e *Engine) tokenizeValue(key string, val any) any {
	switch v := val.(type) {
	case nil, bool, float64, int, int64:
		return v
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, sub := range v {
			out[k] = e.tokenizeValue(k, sub)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, sub := range v {
			out[i] = e.tokenizeValue(key, sub)
		}
		return out
	case string:
		trimmed := strings.TrimSpace(v)
		if m := emailRE.FindStringSubmatch(trimmed); len(m) == 3 {
			return fmt.Sprintf("tok_%s@%s", e.hmacHex(e.tokenizerKey, m[1], 8), strings.ToLower(m[2]))
		}
		kl := strings.ToLower(key)
		for _, hint := range piiKeyHints {
			if strings.Contains(kl, hint) && !strings.HasPrefix(v, "tok_") {
				return "tok_" + e.hmacHex(e.tokenizerKey, v, 12)
			}
		}
		return v
	default:
		return v
	}
}

// AppendLedgerRecord writes a Python-compatible HMAC-chained DecisionLedgerRecord to JSONL.
func (e *Engine) AppendLedgerRecord(
	traceparent string,
	serverName string,
	toolName string,
	rawArgs map[string]any,
	ev EvaluationResult,
	oboPrincipal string,
	idempotencyKey string,
	latencyMs float64,
) (DecisionLedgerRecord, error) {
	if rawArgs == nil {
		rawArgs = map[string]any{}
	}
	rawBytes, _ := canonicalJSON(rawArgs)
	inSum := sha256.Sum256(rawBytes)

	tokArgs := make(map[string]any, len(rawArgs))
	for k, v := range rawArgs {
		tokArgs[k] = e.tokenizeValue(k, v)
	}

	var oboPtr *string
	if oboPrincipal != "" {
		p := oboPrincipal
		oboPtr = &p
	}
	var idemPtr *string
	if idempotencyKey != "" {
		p := idempotencyKey
		idemPtr = &p
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	rec := DecisionLedgerRecord{
		Timestamp:          float64(time.Now().UnixNano()) / 1e9,
		AgentID:            e.Config.Agent.ID,
		Traceparent:        traceparent,
		OBOPrincipal:       oboPtr,
		ServerName:         serverName,
		ToolName:           toolName,
		TokenizedArguments: tokArgs,
		IdempotencyKey:     idemPtr,
		InputSHA256:        hex.EncodeToString(inSum[:]),
		PolicySHA256:       e.PolicySHA256,
		LockfileSHA256:     e.LockfileSHA256,
		Verdict:            ev.Verdict,
		Violations:         ev.Violations,
		LatencyMs:          latencyMs,
		PrevRecordHMAC:     e.lastRecordMac,
	}

	// Compute HMAC identically to Python SignedDecisionLedger._compute_record_hmac
	// (canonical JSON excluding `record_hmac` with sorted keys and no whitespace).
	recMap := make(map[string]any)
	tmp, _ := json.Marshal(rec)
	_ = json.Unmarshal(tmp, &recMap)
	delete(recMap, "record_hmac")
	canon, err := canonicalJSON(recMap)
	if err != nil {
		return rec, err
	}
	rec.RecordHMAC = e.hmacHex(e.signingKey, string(canon), 0)
	e.lastRecordMac = rec.RecordHMAC

	if e.ledgerPath != "" {
		if err := os.MkdirAll(filepath.Dir(e.ledgerPath), 0o755); err != nil {
			return rec, err
		}
		f, err := os.OpenFile(e.ledgerPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return rec, err
		}
		defer f.Close()
		line, err := json.Marshal(rec)
		if err != nil {
			return rec, err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return rec, err
		}
	}
	return rec, nil
}

func canonicalJSON(v any) ([]byte, error) {
	// Deterministically sorts map keys with no spaces and no HTML escaping (matches Python json.dumps).
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

func extractDomain(val string) string {
	v := strings.ToLower(strings.TrimSpace(val))
	if idx := strings.LastIndex(v, "@"); idx >= 0 && idx < len(v)-1 {
		return v[idx+1:]
	}
	if idx := strings.Index(v, "://"); idx >= 0 {
		rest := v[idx+3:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			rest = rest[:slash]
		}
		if colon := strings.Index(rest, ":"); colon >= 0 {
			rest = rest[:colon]
		}
		return rest
	}
	if strings.Contains(v, ".") && !strings.Contains(v, " ") {
		return v
	}
	return ""
}
