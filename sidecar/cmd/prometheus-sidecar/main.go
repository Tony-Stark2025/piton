package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/Tony-Stark2025/prometheus-enterprise/sidecar/internal/policy"
	"github.com/Tony-Stark2025/prometheus-enterprise/sidecar/internal/proxy"
)

func parseGhostEnvFile(path string, cfg policy.AgentIaCConfig) map[string]string {
	out := make(map[string]string)
	if path == "" {
		return out
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	envVals := make(map[string]string)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		envVals[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	for slotName, slot := range cfg.LocalDevCredentials {
		if strings.HasPrefix(slot.Source, "env://") {
			varName := strings.TrimPrefix(slot.Source, "env://")
			if ghost, ok := envVals[varName]; ok {
				out[slotName] = ghost
			}
		}
	}
	return out
}

func main() {
	policyPath := flag.String("policy", ".prometheus/runtime_policy.json", "Path to compiled runtime_policy.json")
	lockPath := flag.String("lock", "prometheus.lock", "Path to prometheus.lock")
	tracesPath := flag.String("traces", ".prometheus/traces.jsonl", "Path to signed JSONL decision ledger")
	ghostEnvPath := flag.String("ghost-env", ".env.agent", "Optional path to .env.agent ghost handles")
	addr := flag.String("addr", "127.0.0.1:8080", "Listen address")
	flag.Parse()

	cfg, err := policy.LoadConfigFile(*policyPath)
	if err != nil {
		log.Fatalf("failed to load runtime policy %s: %v", *policyPath, err)
	}
	var lock *policy.ManifestLockfile
	if *lockPath != "" {
		if _, statErr := os.Stat(*lockPath); statErr == nil {
			lock, err = policy.LoadLockfile(*lockPath)
			if err != nil {
				log.Fatalf("failed to load lockfile %s: %v", *lockPath, err)
			}
		}
	}

	signingKey := []byte(os.Getenv("PROMETHEUS_LEDGER_SIGNING_KEY"))
	tokenizerKey := []byte(os.Getenv("PROMETHEUS_TOKENIZER_KEY"))
	eng, err := policy.NewEngine(cfg, lock, *tracesPath, signingKey, tokenizerKey)
	if err != nil {
		log.Fatalf("failed to initialize policy engine: %v", err)
	}

	ghosts := parseGhostEnvFile(*ghostEnvPath, cfg)
	srv := proxy.NewServer(eng, ghosts)

	fmt.Printf("prometheus-sidecar listening on http://%s (agent=%s mode=%s policy_sha=%s)\n",
		*addr, cfg.Agent.ID, cfg.Agent.Mode, eng.PolicySHA256[:12])
	if err := http.ListenAndServe(*addr, srv); err != nil {
		log.Fatalf("sidecar exited: %v", err)
	}
}
