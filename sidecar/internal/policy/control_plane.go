package policy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

type asyncEvent struct {
	URL     string
	Payload []byte
}

// ControlPlaneBridge asynchronously ships signed DecisionLedgerRecords, lockfile drift
// events, and MCP MRTR escalations to the central Prometheus Control Plane / Approval Bridge
// using a bounded non-blocking queue so Envoy / MCP tail latency is unaffected.
type ControlPlaneBridge struct {
	CollectorURL       string
	ApprovalWebhookURL string
	APIKey             string

	client *http.Client
	ch     chan asyncEvent
	stopCh chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
}

func NewControlPlaneBridge(collectorURL, approvalWebhookURL, apiKey string) *ControlPlaneBridge {
	cURL := strings.TrimRight(strings.TrimSpace(collectorURL), "/")
	aURL := strings.TrimSpace(approvalWebhookURL)
	if aURL == "" && cURL != "" {
		aURL = cURL + "/api/v1/mrtr/escalations"
	}
	if cURL == "" && aURL == "" {
		return nil
	}
	b := &ControlPlaneBridge{
		CollectorURL:       cURL,
		ApprovalWebhookURL: aURL,
		APIKey:             strings.TrimSpace(apiKey),
		client: &http.Client{
			Timeout:   3 * time.Second,
			Transport: &http.Transport{DisableCompression: true},
		},
		ch:     make(chan asyncEvent, 256),
		stopCh: make(chan struct{}),
	}
	b.wg.Add(1)
	go b.worker()
	return b
}

func (b *ControlPlaneBridge) worker() {
	defer b.wg.Done()
	for {
		select {
		case ev := <-b.ch:
			b.post(ev.URL, ev.Payload)
		case <-b.stopCh:
			// Drain queued events briefly during graceful shutdown
			for {
				select {
				case ev := <-b.ch:
					b.post(ev.URL, ev.Payload)
				default:
					return
				}
			}
		}
	}
}

func (b *ControlPlaneBridge) post(targetURL string, body []byte) {
	if targetURL == "" || len(body) == 0 {
		return
	}
	req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if b.APIKey != "" {
		req.Header.Set("X-Prometheus-Control-Key", b.APIKey)
	}
	resp, err := b.client.Do(req)
	if err == nil && resp != nil {
		_ = resp.Body.Close()
	}
}

func (b *ControlPlaneBridge) enqueue(targetURL string, payload any) {
	if b == nil || targetURL == "" {
		return
	}
	raw, err := canonicalJSON(payload)
	if err != nil {
		return
	}
	select {
	case b.ch <- asyncEvent{URL: targetURL, Payload: raw}:
	default:
		// Non-blocking backpressure: never stall hot-path enforcement
	}
}

func (b *ControlPlaneBridge) EmitLedgerRecord(rec DecisionLedgerRecord) {
	if b == nil || b.CollectorURL == "" {
		return
	}
	b.enqueue(b.CollectorURL+"/api/v1/ledger/ingest", rec)
}

func (b *ControlPlaneBridge) EmitDriftEvents(agentID, serverName string, drifts []ManifestDrift) {
	if b == nil || b.CollectorURL == "" || len(drifts) == 0 {
		return
	}
	b.enqueue(b.CollectorURL+"/api/v1/drift/ingest", map[string]any{
		"timestamp":   float64(time.Now().UnixNano()) / 1e9,
		"agent_id":    agentID,
		"server_name": serverName,
		"drifts":      drifts,
	})
}

func (b *ControlPlaneBridge) EmitMRTREscalation(payload map[string]any) {
	if b == nil || b.ApprovalWebhookURL == "" {
		return
	}
	b.enqueue(b.ApprovalWebhookURL, payload)
}

func (b *ControlPlaneBridge) Close() {
	if b == nil {
		return
	}
	b.once.Do(func() {
		close(b.stopCh)
	})
	b.wg.Wait()
}

// ConfigureControlPlane attaches an optional async ControlPlaneBridge to the Engine.
func (e *Engine) ConfigureControlPlane(collectorURL, approvalWebhookURL, apiKey string) {
	e.ControlPlane = NewControlPlaneBridge(collectorURL, approvalWebhookURL, apiKey)
}

// ============================================================================
// Uber-Style Declarative Response Projection (Token Savings + Exfil Reduction)
// ============================================================================

// projectObject keeps only top-level or dot-path keys declared in `allowedFields`.
func projectValue(v any, allowedFields []string) any {
	switch obj := v.(type) {
	case []any:
		out := make([]any, len(obj))
		for i, item := range obj {
			out[i] = projectValue(item, allowedFields)
		}
		return out
	case map[string]any:
		out := make(map[string]any)
		// Group exact keys and nested prefixes ("customer.email" -> prefix "customer", sub "email")
		direct := make(map[string]bool)
		nested := make(map[string][]string)
		for _, f := range allowedFields {
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			if idx := strings.IndexByte(f, '.'); idx >= 0 {
				head := f[:idx]
				tail := f[idx+1:]
				nested[head] = append(nested[head], tail)
			} else {
				direct[f] = true
			}
		}
		for k, val := range obj {
			if direct[k] {
				out[k] = val
			} else if subFields, ok := nested[k]; ok {
				out[k] = projectValue(val, subFields)
			}
		}
		return out
	default:
		return v
	}
}

// ProjectMCPToolResponse strips unprojected fields from MCP `tools/call` responses
// (both JSON-RPC `result.content[*].text` JSON payloads and direct JSON objects)
// when `response_projection` is configured on the tool in `prometheus.yaml`.
// Returns `(projectedBytes, bytesSaved)`.
func (e *Engine) ProjectMCPToolResponse(serverName, toolName string, rawBody []byte) ([]byte, int) {
	if len(rawBody) == 0 || serverName == "" || toolName == "" {
		return rawBody, 0
	}
	srv, ok := e.Config.MCPServers[serverName]
	if !ok {
		return rawBody, 0
	}
	tp, ok := srv.Tools[toolName]
	if !ok || len(tp.ResponseProjection) == 0 {
		return rawBody, 0
	}

	var envelope map[string]any
	if err := json.Unmarshal(rawBody, &envelope); err != nil {
		return rawBody, 0
	}
	resObj, ok := envelope["result"].(map[string]any)
	if !ok {
		return rawBody, 0
	}

	mutated := false
	// 1. Standard MCP tools/call: result.content[*].text carrying serialized JSON
	if contentArr, ok := resObj["content"].([]any); ok {
		for _, item := range contentArr {
			cMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			textVal, ok := cMap["text"].(string)
			if !ok || strings.TrimSpace(textVal) == "" {
				continue
			}
			var inner any
			if err := json.Unmarshal([]byte(textVal), &inner); err != nil {
				continue
			}
			projected := projectValue(inner, tp.ResponseProjection)
			if projBytes, err := json.Marshal(projected); err == nil {
				cMap["text"] = string(projBytes)
				mutated = true
			}
		}
	}
	// 2. MCP 2025/2026 structuredContent field
	if sc, exists := resObj["structuredContent"]; exists {
		resObj["structuredContent"] = projectValue(sc, tp.ResponseProjection)
		mutated = true
	}

	if !mutated {
		return rawBody, 0
	}
	outBytes, err := json.Marshal(envelope)
	if err != nil {
		return rawBody, 0
	}
	saved := len(rawBody) - len(outBytes)
	if saved > 0 {
		e.Metrics.BytesProjected.Add(int64(saved))
	} else {
		saved = 0
	}
	return outBytes, saved
}
