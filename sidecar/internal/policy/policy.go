package policy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Tony-Stark2025/prometheus-enterprise/sidecar/internal/oidc"
)

const (
	maxTrackedTraces    = 100_000
	maxTrackedIdemKeys  = 200_000
	traceEntryTTL       = 15 * time.Minute
	idemEntryTTL        = 24 * time.Hour
	rollingWindowDur    = time.Hour
	mrtrStateTTL        = 10 * time.Minute
)

// Policy structures mirror `prometheus/iac/schema.py` 1:1.

type AgentMeta struct {
	ID    string `json:"id"`
	Owner string `json:"owner"`
	Mode  string `json:"mode"` // "shadow" | "enforce"
}

type IdentityConfig struct {
	Mode                string `json:"mode"` // "oidc_obo" | "local_dev"
	Issuer              string `json:"issuer,omitempty"`
	JWKSURL             string `json:"jwks_url,omitempty"`
	Audience            string `json:"audience,omitempty"`
	VerifyJWTSignature  bool   `json:"verify_jwt_signature"`
	AllowTrustedHeaders bool   `json:"allow_trusted_headers"`
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
	Required     *bool    `json:"required,omitempty"`
	Min          *float64 `json:"min,omitempty"`
	Max          *float64 `json:"max,omitempty"`
	Enum         []any    `json:"enum,omitempty"`
	AllowDomains []string `json:"allow_domains,omitempty"`
	DenyDomains  []string `json:"deny_domains,omitempty"`
	Regex        string   `json:"regex,omitempty"`
	MaxLength    *int     `json:"max_length,omitempty"`
}

func (b ParameterBound) IsRequired() bool {
	if b.Required == nil {
		return true
	}
	return *b.Required
}

type RateLimitPolicy struct {
	MaxCallsPerTrace *int     `json:"max_calls_per_trace,omitempty"`
	MaxCallsPerHour  *int     `json:"max_calls_per_hour,omitempty"`
	MaxSumPerHour    *float64 `json:"max_sum_per_hour,omitempty"`
	SumParameter     string   `json:"sum_parameter,omitempty"`
}

type ToolPolicy struct {
	Tier            string                    `json:"tier"`
	IdempotencyKey  string                    `json:"idempotency_key,omitempty"`
	ParameterBounds map[string]ParameterBound `json:"parameter_bounds,omitempty"`
	RateLimit       *RateLimitPolicy          `json:"rate_limit,omitempty"`
	OnBoundExceeded string                    `json:"on_bound_exceeded,omitempty"`
}

type MCPServerPolicy struct {
	URL                string                `json:"url,omitempty"`
	Command            string                `json:"command,omitempty"`
	Args               []string              `json:"args,omitempty"`
	TrustTier          string                `json:"trust_tier"` // "internal" | "third_party"
	StrictUnknownTools *bool                 `json:"strict_unknown_tools,omitempty"`
	Tools              map[string]ToolPolicy `json:"tools,omitempty"`
}

func (m MCPServerPolicy) IsStrictUnknownTools() bool {
	if m.StrictUnknownTools == nil {
		return true
	}
	return *m.StrictUnknownTools
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

type traceCounter struct {
	Count     int
	UpdatedAt time.Time
}

type rollingSample struct {
	At    time.Time
	Value float64
}

// Metrics counters exposed via Prometheus `/metrics`.
type Metrics struct {
	RequestsTotal     atomic.Int64
	AllowedTotal      atomic.Int64
	ShadowDeniedTotal atomic.Int64
	DeniedTotal       atomic.Int64
	MRTREscalated     atomic.Int64
	RugPullsBlocked   atomic.Int64
	SecretsRedacted   atomic.Int64
}

// Engine executes sub-millisecond parameter-bound evaluation, split-hash MCP pinning,
// cryptographic OIDC/OBO principal resolution, rolling principal budgets, MCP MRTR
// signed requestState minting/verification, and HMAC-chained ledger recording.
type Engine struct {
	Config         AgentIaCConfig
	Lockfile       *ManifestLockfile
	PolicySHA256   string
	LockfileSHA256 string
	OIDCVerifier   *oidc.Verifier
	Metrics        Metrics

	ledgerPath       string
	signingKey       []byte
	tokenizerKey     []byte
	mu               sync.Mutex
	ledgerMu         sync.Mutex
	traceCounts      map[string]traceCounter
	seenIdemKeys     map[string]time.Time
	principalRolling map[string][]rollingSample
	lastRecordMac    string
}

func NewEngine(cfg AgentIaCConfig, lock *ManifestLockfile, ledgerPath string, signingKey, tokenizerKey []byte) (*Engine, error) {
	// Require explicit signing key in enforce mode when ledger recording is active
	if len(signingKey) == 0 {
		if cfg.Agent.Mode == "enforce" && ledgerPath != "" {
			return nil, errors.New("PROMETHEUS_LEDGER_SIGNING_KEY must be set in enforce mode (refusing hardcoded fallback)")
		}
		signingKey = []byte("prometheus-ledger-signing-key")
	}
	if len(tokenizerKey) == 0 {
		tokenizerKey = []byte("prometheus-default-tokenizer-key")
	}

	// Normalize policy via generic map so canonical_sha256 matches Python sorted-keys JSON
	policyMap := structToMapNoNulls(cfg)
	policyBytes, err := canonicalJSON(policyMap)
	if err != nil {
		return nil, err
	}
	policySum := sha256.Sum256(policyBytes)

	lockSHA := "NONE"
	if lock != nil {
		lockMap := structToMapNoNulls(map[string]any{
			"version": lock.Version,
			"servers": lock.Servers,
		})
		lb, err := canonicalJSON(lockMap)
		if err != nil {
			return nil, err
		}
		ls := sha256.Sum256(lb)
		lockSHA = hex.EncodeToString(ls[:])
	}

	// Auto-enable cryptographic OIDC JWKS verification whenever Issuer or JWKSURL is set
	var verifier *oidc.Verifier
	if cfg.Identity.Issuer != "" || cfg.Identity.JWKSURL != "" || cfg.Identity.VerifyJWTSignature {
		if cfg.Identity.Issuer != "" || cfg.Identity.JWKSURL != "" {
			verifier = oidc.NewVerifier(oidc.VerifierConfig{
				Issuer:   cfg.Identity.Issuer,
				JWKSURL:  cfg.Identity.JWKSURL,
				Audience: cfg.Identity.Audience,
			})
		}
	}

	eng := &Engine{
		Config:           cfg,
		Lockfile:         lock,
		PolicySHA256:     hex.EncodeToString(policySum[:]),
		LockfileSHA256:   lockSHA,
		OIDCVerifier:     verifier,
		ledgerPath:       ledgerPath,
		signingKey:       signingKey,
		tokenizerKey:     tokenizerKey,
		traceCounts:      make(map[string]traceCounter),
		seenIdemKeys:     make(map[string]time.Time),
		principalRolling: make(map[string][]rollingSample),
		lastRecordMac:    "GENESIS",
	}

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

// ResolveOBOPrincipal resolves caller identity fail-closed:
//   - If OIDCVerifier is active (issuer/jwks_url set): strictly verifies RS256/ES256 Bearer JWT;
//     never trusts X-OBO-Principal headers.
//   - If no OIDCVerifier is configured: only trusts X-OBO-Principal/X-Forwarded-User when
//     `allow_trusted_headers: true` OR in `shadow` mode (fails closed in `enforce`!).
func (e *Engine) ResolveOBOPrincipal(ctx context.Context, hdr http.Header) string {
	if e.OIDCVerifier != nil {
		auth := strings.TrimSpace(hdr.Get("Authorization"))
		if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			return ""
		}
		rawTok := strings.TrimSpace(auth[7:])
		principal, err := e.OIDCVerifier.VerifyToken(ctx, rawTok)
		if err != nil || principal == nil {
			return ""
		}
		return principal.CanonicalID
	}
	if e.Config.Identity.AllowTrustedHeaders || e.Config.Agent.Mode == "shadow" {
		return ExtractOBOPrincipal(hdr)
	}
	return ""
}

func ExtractOBOPrincipal(hdr http.Header) string {
	if v := strings.TrimSpace(hdr.Get("X-OBO-Principal")); v != "" {
		return v
	}
	if v := strings.TrimSpace(hdr.Get("X-Forwarded-User")); v != "" {
		return "user:" + v
	}
	return ""
}

// ============================================================================
// MCP 2026-07-28 MRTR Signed RequestState & Approval Token Verification
// ============================================================================

type MRTRStatePayload struct {
	ServerName string `json:"server_name"`
	ToolName   string `json:"tool_name"`
	ArgsHash   string `json:"args_hash"`
	Principal  string `json:"principal"`
	ExpiresAt  int64  `json:"expires_at"`
	Approved   bool   `json:"approved"`
}

func (e *Engine) MintMRTRState(serverName, toolName string, args map[string]any, principal string, approved bool) string {
	ab, _ := canonicalJSON(args)
	ah := sha256.Sum256(ab)
	st := MRTRStatePayload{
		ServerName: serverName,
		ToolName:   toolName,
		ArgsHash:   hex.EncodeToString(ah[:]),
		Principal:  principal,
		ExpiresAt:  time.Now().Add(mrtrStateTTL).Unix(),
		Approved:   approved,
	}
	raw, _ := canonicalJSON(st)
	mac := e.hmacHex(e.signingKey, string(raw), 32)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + mac
}

func (e *Engine) VerifyMRTRApprovalToken(token, serverName, toolName string, args map[string]any, principal string) bool {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 2 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	expectedMac := e.hmacHex(e.signingKey, string(raw), 32)
	if !hmac.Equal([]byte(parts[1]), []byte(expectedMac)) {
		return false
	}
	var st MRTRStatePayload
	if json.Unmarshal(raw, &st) != nil {
		return false
	}
	if !st.Approved || time.Now().Unix() > st.ExpiresAt {
		return false
	}
	ab, _ := canonicalJSON(args)
	ah := sha256.Sum256(ab)
	return st.ServerName == serverName &&
		st.ToolName == toolName &&
		st.ArgsHash == hex.EncodeToString(ah[:]) &&
		st.Principal == principal
}

// BuildMRTRInputRequiredPayload constructs a spec-compliant MCP 2026-07-28 MRTR
// `input_required` result envelope with signed `requestState` for out-of-band approval.
func (e *Engine) BuildMRTRInputRequiredPayload(reqID any, serverName, toolName string, args map[string]any, principal string, ev EvaluationResult) map[string]any {
	stateToken := e.MintMRTRState(serverName, toolName, args, principal, false)
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      reqID,
		"result": map[string]any{
			"resultType":   "input_required",
			"requestState": stateToken,
			"inputRequests": []map[string]any{
				{
					"id":     "prometheus-mrtr-approval",
					"method": "elicitation/create",
					"params": map[string]any{
						"message": fmt.Sprintf("Out-of-band approval required for %s.%s (exceeds autonomous parameter bounds).", serverName, toolName),
						"requestedSchema": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"approval_token": map[string]any{"type": "string", "description": "Signed Prometheus MRTR approval token"},
							},
							"required": []string{"approval_token"},
						},
					},
				},
			},
			"prometheus": ev,
		},
	}
}

func (e *Engine) pruneCachesLocked(now time.Time) {
	if len(e.traceCounts) > maxTrackedTraces {
		for k, v := range e.traceCounts {
			if now.Sub(v.UpdatedAt) > traceEntryTTL || len(e.traceCounts) > maxTrackedTraces {
				delete(e.traceCounts, k)
			}
		}
	}
	if len(e.seenIdemKeys) > maxTrackedIdemKeys {
		for k, ts := range e.seenIdemKeys {
			if now.Sub(ts) > idemEntryTTL || len(e.seenIdemKeys) > maxTrackedIdemKeys {
				delete(e.seenIdemKeys, k)
			}
		}
	}
}

// EvaluateToolCall deterministically enforces OBO principal, fail-closed server/tool allowlists,
// idempotency (committed ONLY on allowed calls), bounded per-trace & rolling 1h per-principal
// budgets, and type-safe parameter bounds.
func (e *Engine) EvaluateToolCall(
	traceparent string,
	serverName string,
	toolName string,
	arguments map[string]any,
	oboPrincipal string,
	idempotencyKey string,
	mrtrApprovalToken ...string,
) EvaluationResult {
	e.Metrics.RequestsTotal.Add(1)
	var violations []RuleViolation
	now := time.Now()

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
	if !hasSrv {
		violations = append(violations, RuleViolation{
			RuleID:            "UNKNOWN_MCP_SERVER",
			Message:           fmt.Sprintf("MCP server '%s' is not declared in prometheus.yaml.", serverName),
			RecommendedAction: "block",
		})
	} else {
		toolPolicy, hasTool = srvPolicy.Tools[toolName]
		if !hasTool && srvPolicy.IsStrictUnknownTools() {
			violations = append(violations, RuleViolation{
				RuleID:            "UNLISTED_MCP_TOOL",
				Message:           fmt.Sprintf("Tool '%s.%s' is not declared in prometheus.yaml.", serverName, toolName),
				RecommendedAction: "block",
			})
		}
	}

	var idemScoped string
	if hasTool {
		onExceed := toolPolicy.OnBoundExceeded
		if onExceed == "" {
			onExceed = "mrtr_escalate"
		}

		// 2. Check idempotency key (committed ONLY if call is ultimately admitted!)
		if toolPolicy.IdempotencyKey == "required" {
			if idempotencyKey == "" {
				violations = append(violations, RuleViolation{
					RuleID:            "MISSING_IDEMPOTENCY_KEY",
					Message:           fmt.Sprintf("Bounded write '%s.%s' requires an idempotency key.", serverName, toolName),
					RecommendedAction: "block",
				})
			} else {
				idemScoped = serverName + "::" + toolName + "::" + idempotencyKey
				e.mu.Lock()
				if ts, exists := e.seenIdemKeys[idemScoped]; exists && now.Sub(ts) <= idemEntryTTL {
					violations = append(violations, RuleViolation{
						RuleID:            "DUPLICATE_IDEMPOTENCY_KEY",
						Message:           fmt.Sprintf("Idempotency key '%s' was already executed for '%s.%s'.", idempotencyKey, serverName, toolName),
						ObservedValue:     idempotencyKey,
						RecommendedAction: "block",
					})
				}
				e.mu.Unlock()
			}
		}

		// 3. Per-trace & rolling 1h per-principal cumulative budgets (kills cross-trace smurfing)
		if toolPolicy.RateLimit != nil {
			e.mu.Lock()
			e.pruneCachesLocked(now)
			if toolPolicy.RateLimit.MaxCallsPerTrace != nil {
				ck := traceparent + "::" + serverName + "::" + toolName
				cur := e.traceCounts[ck]
				if now.Sub(cur.UpdatedAt) > traceEntryTTL {
					cur.Count = 0
				}
				cur.Count++
				cur.UpdatedAt = now
				e.traceCounts[ck] = cur
				if cur.Count > *toolPolicy.RateLimit.MaxCallsPerTrace {
					violations = append(violations, RuleViolation{
						RuleID:            "TRACE_RATE_LIMIT_EXCEEDED",
						Message:           fmt.Sprintf("Call #%d to '%s.%s' exceeds max_calls_per_trace=%d.", cur.Count, serverName, toolName, *toolPolicy.RateLimit.MaxCallsPerTrace),
						ObservedValue:     cur.Count,
						ConfiguredBound:   *toolPolicy.RateLimit.MaxCallsPerTrace,
						RecommendedAction: onExceed,
					})
				}
			}

			if toolPolicy.RateLimit.MaxCallsPerHour != nil || toolPolicy.RateLimit.MaxSumPerHour != nil {
				pkey := oboPrincipal + "::" + e.Config.Agent.ID + "::" + serverName + "::" + toolName
				samples := e.principalRolling[pkey]
				cutoff := now.Add(-rollingWindowDur)
				kept := samples[:0]
				var sum float64
				for _, s := range samples {
					if s.At.After(cutoff) {
						kept = append(kept, s)
						sum += s.Value
					}
				}
				sumParam := toolPolicy.RateLimit.SumParameter
				if sumParam == "" {
					sumParam = "amount"
				}
				valNum, _ := toFloat64(arguments[sumParam])
				nextCalls := len(kept) + 1
				nextSum := sum + valNum
				if toolPolicy.RateLimit.MaxCallsPerHour != nil && nextCalls > *toolPolicy.RateLimit.MaxCallsPerHour {
					violations = append(violations, RuleViolation{
						RuleID:            "PRINCIPAL_HOURLY_CALLS_EXCEEDED",
						Message:           fmt.Sprintf("Hourly call #%d for principal exceeds max_calls_per_hour=%d.", nextCalls, *toolPolicy.RateLimit.MaxCallsPerHour),
						ObservedValue:     nextCalls,
						ConfiguredBound:   *toolPolicy.RateLimit.MaxCallsPerHour,
						RecommendedAction: onExceed,
					})
				}
				if toolPolicy.RateLimit.MaxSumPerHour != nil && nextSum > *toolPolicy.RateLimit.MaxSumPerHour {
					violations = append(violations, RuleViolation{
						RuleID:            "PRINCIPAL_HOURLY_SUM_EXCEEDED",
						Parameter:         &sumParam,
						Message:           fmt.Sprintf("Cumulative 1h %s=%.2f exceeds max_sum_per_hour=%.2f.", sumParam, nextSum, *toolPolicy.RateLimit.MaxSumPerHour),
						ObservedValue:     nextSum,
						ConfiguredBound:   *toolPolicy.RateLimit.MaxSumPerHour,
						RecommendedAction: onExceed,
					})
				}
				if len(violations) == 0 {
					kept = append(kept, rollingSample{At: now, Value: valNum})
				}
				e.principalRolling[pkey] = kept
			}
			e.mu.Unlock()
		}

		// 4. Parameter bounds (fail closed on omitted required bounded params)
		for pname, bound := range toolPolicy.ParameterBounds {
			p := pname
			val, present := arguments[p]
			if !present {
				if bound.IsRequired() {
					violations = append(violations, RuleViolation{
						RuleID:            "MISSING_BOUNDED_PARAMETER",
						Parameter:         &p,
						Message:           fmt.Sprintf("Required bounded parameter '%s' was omitted.", p),
						RecommendedAction: "block",
					})
				}
				continue
			}
			violations = append(violations, checkParamBound(p, val, bound, onExceed)...)
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

	// If MRTR escalation occurred AND caller supplied a cryptographically signed MRTR approval token
	// matching this exact server/tool/arguments/principal, honor the human approval!
	if verdict == "mrtr_escalate" && len(mrtrApprovalToken) > 0 && mrtrApprovalToken[0] != "" {
		if e.VerifyMRTRApprovalToken(mrtrApprovalToken[0], serverName, toolName, arguments, oboPrincipal) {
			verdict = "allow"
			violations = []RuleViolation{}
		}
	}

	// Commit idempotency key ONLY if call is admitted in enforce mode (never burn key on rejected calls)
	if verdict == "allow" && idemScoped != "" && e.Config.Agent.Mode == "enforce" {
		e.mu.Lock()
		e.pruneCachesLocked(now)
		e.seenIdemKeys[idemScoped] = now
		e.mu.Unlock()
	}

	switch verdict {
	case "allow":
		e.Metrics.AllowedTotal.Add(1)
	case "shadow_deny":
		e.Metrics.ShadowDeniedTotal.Add(1)
	case "mrtr_escalate":
		e.Metrics.MRTREscalated.Add(1)
	case "deny":
		e.Metrics.DeniedTotal.Add(1)
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

func strictEnumMatch(val any, allowed []any) bool {
	for _, item := range allowed {
		// Prevent bool <-> int/string confusion
		_, vBool := val.(bool)
		_, iBool := item.(bool)
		if vBool || iBool {
			if vBool && iBool && val == item {
				return true
			}
			continue
		}
		if vf, ok1 := toFloat64(val); ok1 {
			if inf, ok2 := toFloat64(item); ok2 {
				if vf == inf {
					return true
				}
				continue
			}
		}
		if reflect.TypeOf(val) == reflect.TypeOf(item) && reflect.DeepEqual(val, item) {
			return true
		}
	}
	return false
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

	if len(bound.Enum) > 0 && !strictEnumMatch(val, bound.Enum) {
		out = append(out, RuleViolation{
			RuleID:            "PARAM_ENUM_VIOLATION",
			Parameter:         &paramName,
			Message:           fmt.Sprintf("Parameter '%s'=%v not in allowed enum.", paramName, val),
			ObservedValue:     val,
			ConfiguredBound:   bound.Enum,
			RecommendedAction: onExceed,
		})
	}

	hasStringBounds := bound.MaxLength != nil || bound.Regex != "" || len(bound.AllowDomains) > 0 || len(bound.DenyDomains) > 0
	if hasStringBounds {
		strVal, ok := val.(string)
		if !ok {
			out = append(out, RuleViolation{
				RuleID:            "PARAM_TYPE_MISMATCH",
				Parameter:         &paramName,
				Message:           fmt.Sprintf("Parameter '%s' expected string value for domain/regex/length bound.", paramName),
				ObservedValue:     val,
				RecommendedAction: onExceed,
			})
		} else {
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
	}
	return out
}

// ============================================================================
// Live Bidirectional `tools/list` Split-Hash + Runtime Poisoning Verification
// ============================================================================

type ManifestDrift struct {
	ServerName string `json:"server_name"`
	ToolName   string `json:"tool_name"`
	Kind       string `json:"kind"`
	Action     string `json:"action"` // "block" | "warn"
	Message    string `json:"message"`
}

var (
	invisibleUnicodeRE = regexp.MustCompile("[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
	goPoisonRules      = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(ignore\s+(all\s+)?(previous|prior|above)\s+instructions?|disregard\s+(all\s+)?(previous|prior)|new\s+system\s+prompt)`),
		regexp.MustCompile(`(?i)(do\s+not\s+(tell|inform|mention|show|notify)\s+the\s+user|silently\s+(send|forward|copy|bcc|exfiltrate|execute)|<\s*IMPORTANT\s*>|<\s*SYSTEM\s*>)`),
		regexp.MustCompile(`(?i)(~/\.ssh|id_rsa|/etc/passwd|\.aws/credentials|\.env\b|exfiltrat|webhook\.site)`),
	}
)

func hasRuntimePoisoning(tool map[string]any) bool {
	b, _ := json.Marshal(tool)
	s := string(b)
	if invisibleUnicodeRE.MatchString(s) {
		return true
	}
	cleaned := invisibleUnicodeRE.ReplaceAllString(s, "")
	for _, re := range goPoisonRules {
		if re.MatchString(cleaned) {
			return true
		}
	}
	return false
}

// ExtractToolsFromMCPResponse parses `result.tools` from BOTH standard JSON and
// MCP 2026-07-28 `text/event-stream` SSE responses!
func ExtractToolsFromMCPResponse(body []byte, contentType string) ([]map[string]any, bool) {
	extractFromObj := func(obj map[string]any) ([]map[string]any, bool) {
		res, ok := obj["result"].(map[string]any)
		if !ok {
			return nil, false
		}
		rawTools, ok := res["tools"].([]any)
		if !ok {
			return nil, false
		}
		out := make([]map[string]any, 0, len(rawTools))
		for _, item := range rawTools {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out, true
	}

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, false
	}

	if !strings.Contains(strings.ToLower(contentType), "text/event-stream") && trimmed[0] == '{' {
		var obj map[string]any
		if json.Unmarshal(trimmed, &obj) == nil {
			return extractFromObj(obj)
		}
	}

	// SSE `data:` frame extraction
	var dataBuf []string
	flush := func() ([]map[string]any, bool) {
		if len(dataBuf) == 0 {
			return nil, false
		}
		chunk := strings.TrimSpace(strings.Join(dataBuf, "\n"))
		dataBuf = nil
		if chunk == "" || chunk == "[DONE]" {
			return nil, false
		}
		var obj map[string]any
		if json.Unmarshal([]byte(chunk), &obj) == nil {
			return extractFromObj(obj)
		}
		return nil, false
	}
	for _, line := range strings.Split(string(trimmed), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "data:") {
			dataBuf = append(dataBuf, strings.TrimSpace(line[5:]))
		} else if strings.TrimSpace(line) == "" {
			if tools, ok := flush(); ok {
				return tools, true
			}
		}
	}
	return flush()
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
			if k == "description" || k == "title" {
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

// VerifyToolsListResponse checks an upstream MCP `tools/list` response against `prometheus.lock`
// AND runs Go runtime poisoning detection on every observed tool!
func (e *Engine) VerifyToolsListResponse(serverName string, tools []map[string]any) (bool, []ManifestDrift) {
	var drifts []ManifestDrift
	blocked := false

	var pinnedSrv PinnedServerManifest
	var hasPinnedSrv bool
	if e.Lockfile != nil {
		pinnedSrv, hasPinnedSrv = e.Lockfile.Servers[serverName]
	}

	trustTier := "third_party"
	if hasPinnedSrv && pinnedSrv.TrustTier != "" {
		trustTier = pinnedSrv.TrustTier
	} else if srvCfg, exists := e.Config.MCPServers[serverName]; exists && srvCfg.TrustTier != "" {
		trustTier = srvCfg.TrustTier
	}

	for _, tool := range tools {
		tname, _ := tool["name"].(string)
		if tname == "" {
			continue
		}

		// Runtime poisoning check fires on ALL servers (internal or third-party)
		if hasRuntimePoisoning(tool) {
			blocked = true
			drifts = append(drifts, ManifestDrift{
				ServerName: serverName,
				ToolName:   tname,
				Kind:       "day1_poisoning",
				Action:     "block",
				Message:    fmt.Sprintf("Runtime MCP tool poisoning detected on '%s.%s'.", serverName, tname),
			})
		}

		if e.Lockfile == nil {
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
	if blocked {
		e.Metrics.RugPullsBlocked.Add(1)
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

	// Separate ledgerMu from hot-path policy mutex so file I/O never stalls evaluations
	e.ledgerMu.Lock()
	defer e.ledgerMu.Unlock()

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
		line, err := canonicalJSON(rec)
		if err != nil {
			return rec, err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return rec, err
		}
	}
	return rec, nil
}

func structToMapNoNulls(v any) any {
	raw, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(raw, &out)
	return stripNulls(out)
}

func stripNulls(v any) any {
	switch m := v.(type) {
	case map[string]any:
		clean := make(map[string]any, len(m))
		for k, val := range m {
			if val == nil {
				continue
			}
			clean[k] = stripNulls(val)
		}
		return clean
	case []any:
		res := make([]any, len(m))
		for i, item := range m {
			res[i] = stripNulls(item)
		}
		return res
	default:
		return v
	}
}

func canonicalJSON(v any) ([]byte, error) {
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

// extractDomain safely extracts the domain without URL parser differentials
// (`https://evil.com/?x=@acme.com` returns `evil.com`, NEVER `acme.com`).
func extractDomain(val string) string {
	v := strings.ToLower(strings.TrimSpace(val))
	if v == "" || strings.ContainsAny(v, " \t\r\n") {
		return ""
	}
	if strings.Contains(v, "://") {
		u, err := url.Parse(v)
		if err != nil || u.User != nil {
			return ""
		}
		return strings.ToLower(u.Hostname())
	}
	if m := emailRE.FindStringSubmatch(v); len(m) == 3 {
		return strings.ToLower(m[2])
	}
	if strings.Contains(v, ".") && !strings.Contains(v, "@") && !strings.Contains(v, "/") {
		return v
	}
	return ""
}
