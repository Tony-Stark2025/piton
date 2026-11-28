package policy

import (
	"math"
	"sync"
	"testing"
)

func intPtr(v int) *int          { return &v }
func floatPtr(v float64) *float64 { return &v }

func newEnforceBillingEngine(t *testing.T, maxSum float64) *Engine {
	t.Helper()
	cfg := AgentIaCConfig{
		Version: "1.0",
		Agent:   AgentMeta{ID: "hotfix-agent", Owner: "sec@acme.com", Mode: "enforce"},
		Identity: IdentityConfig{
			Mode:                "local_dev",
			RequireDelegatedSub: false,
			AllowTrustedHeaders: true,
		},
		MCPServers: map[string]MCPServerPolicy{
			"billing": {
				TrustTier: "internal",
				Tools: map[string]ToolPolicy{
					"refund": {
						Tier:           "bounded_write",
						IdempotencyKey: "required",
						ParameterBounds: map[string]ParameterBound{
							"amount": {Max: floatPtr(100.0)},
						},
						RateLimit: &RateLimitPolicy{
							MaxSumPerHour: floatPtr(maxSum),
							SumParameter:  "amount",
						},
						OnBoundExceeded: "mrtr_escalate",
					},
					"regex_tool": {
						Tier: "read",
						ParameterBounds: map[string]ParameterBound{
							"code": {Regex: `(?=invalid_re2_lookahead)`},
						},
						OnBoundExceeded: "block",
					},
				},
			},
		},
	}
	eng, err := NewEngine(cfg, nil, "", []byte("test-signing-key-32-bytes-000000"), []byte("tok-key"))
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	return eng
}

func TestConcurrentIdempotencyNoTOCTOU(t *testing.T) {
	eng := newEnforceBillingEngine(t, 10000.0)
	const workers = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	dupBlocked := 0

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := eng.EvaluateToolCall(
				"00-trace-01",
				"billing",
				"refund",
				map[string]any{"amount": 10.0},
				"user:alice",
				"same-idem-key-1",
			)
			mu.Lock()
			defer mu.Unlock()
			if res.Verdict == "allow" {
				allowed++
			} else if res.Verdict == "deny" {
				for _, v := range res.Violations {
					if v.RuleID == "DUPLICATE_IDEMPOTENCY_KEY" {
						dupBlocked++
						break
					}
				}
			}
		}()
	}
	wg.Wait()

	if allowed != 1 {
		t.Fatalf("TOCTOU race detected: expected strictly 1 allowed call, got %d", allowed)
	}
	if dupBlocked != workers-1 {
		t.Fatalf("expected %d duplicate denials, got %d", workers-1, dupBlocked)
	}
}

func TestConcurrentRollingBudgetNoTOCTOUAndNegativeSpendBlocked(t *testing.T) {
	eng := newEnforceBillingEngine(t, 100.0)

	// 1. Negative & NaN spend smurfing MUST fail closed
	for _, bad := range []float64{-50.0, math.NaN(), math.Inf(1)} {
		res := eng.EvaluateToolCall(
			"00-trace-neg",
			"billing",
			"refund",
			map[string]any{"amount": bad},
			"user:bob",
			"idem-neg-1",
		)
		if res.Verdict != "deny" {
			t.Fatalf("expected deny for bad budget amount %v, got %s", bad, res.Verdict)
		}
	}

	// 2. 20 concurrent calls of $40 against a $100/hr budget -> strictly 2 allowed!
	const workers = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			res := eng.EvaluateToolCall(
				"00-trace-budget",
				"billing",
				"refund",
				map[string]any{"amount": 40.0},
				"user:bob",
				"idem-unique-"+string(rune('A'+idx)),
			)
			if res.Verdict == "allow" {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if allowed != 2 {
		t.Fatalf("budget TOCTOU race detected: expected strictly 2 calls allowed within $100 budget, got %d", allowed)
	}
}

func TestMRTRApprovalTokenSingleUseNoReplay(t *testing.T) {
	eng := newEnforceBillingEngine(t, 1000.0)
	args := map[string]any{"amount": 250.0}

	// Mint approved token bound to idem-mrtr-1
	tok := eng.MintMRTRState("billing", "refund", args, "user:carol", true, "idem-mrtr-1")

	// Wrong idempotency key MUST be rejected (without consuming valid token)
	resWrongIK := eng.EvaluateToolCall("00-t1", "billing", "refund", args, "user:carol", "idem-other", tok)
	if resWrongIK.Verdict != "mrtr_escalate" {
		t.Fatalf("expected mrtr_escalate for mismatched idempotency_key, got %s", resWrongIK.Verdict)
	}

	// First legitimate use with matching idempotency key MUST succeed
	resFirst := eng.EvaluateToolCall("00-t2", "billing", "refund", args, "user:carol", "idem-mrtr-1", tok)
	if resFirst.Verdict != "allow" {
		t.Fatalf("expected allow on first valid MRTR token use, got %s (%+v)", resFirst.Verdict, resFirst.Violations)
	}

	// Replay of the exact same token (even with a different non-idempotency-bound token) MUST fail!
	unboundTok := eng.MintMRTRState("billing", "refund", args, "user:carol", true)
	resUnbound1 := eng.EvaluateToolCall("00-t3", "billing", "refund", args, "user:carol", "idem-mrtr-2", unboundTok)
	if resUnbound1.Verdict != "allow" {
		t.Fatalf("expected allow on first unbound MRTR token use, got %s", resUnbound1.Verdict)
	}
	resReplay := eng.EvaluateToolCall("00-t4", "billing", "refund", args, "user:carol", "idem-mrtr-3", unboundTok)
	if resReplay.Verdict != "mrtr_escalate" {
		t.Fatalf("MRTR replay attack succeeded! Expected mrtr_escalate on 2nd use, got %s", resReplay.Verdict)
	}
}

func TestInvalidRE2RegexFailsClosedAndUnicodeTagsDetected(t *testing.T) {
	eng := newEnforceBillingEngine(t, 1000.0)
	res := eng.EvaluateToolCall("00-re", "billing", "regex_tool", map[string]any{"code": "anything"}, "user:dave", "")
	if res.Verdict != "deny" {
		t.Fatalf("expected fail-closed deny on invalid Go RE2 regex, got %s", res.Verdict)
	}
	found := false
	for _, v := range res.Violations {
		if v.RuleID == "INVALID_POLICY_REGEX" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected INVALID_POLICY_REGEX violation, got %+v", res.Violations)
	}

	// Unicode Tags block (U+E0041) must trigger Go runtime poisoning detector
	poisoned := map[string]any{
		"name":        "helper",
		"description": "Normal tool\U000e0041",
	}
	if !hasRuntimePoisoning(poisoned) {
		t.Fatalf("expected Go hasRuntimePoisoning to catch Unicode Tag character U+E0041")
	}
}
