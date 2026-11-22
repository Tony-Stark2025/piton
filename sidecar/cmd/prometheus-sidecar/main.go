package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	ext_procv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"

	"github.com/Tony-Stark2025/prometheus-enterprise/sidecar/internal/extproc"
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
	addr := flag.String("addr", "127.0.0.1:8080", "HTTP listen address (/gw, /mcp, /ext_mcp, /healthz)")
	grpcAddr := flag.String("grpc-addr", "", "Optional Envoy v3 gRPC ext_proc listen address (e.g. 127.0.0.1:50051)")
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
	httpSrv := proxy.NewServer(eng, ghosts)

	if *grpcAddr != "" {
		lis, err := net.Listen("tcp", *grpcAddr)
		if err != nil {
			log.Fatalf("failed to bind Envoy gRPC ext_proc on %s: %v", *grpcAddr, err)
		}
		grpcServer := grpc.NewServer()
		ext_procv3.RegisterExternalProcessorServer(grpcServer, extproc.NewServer(eng, httpSrv.ActiveSecrets))
		go func() {
			fmt.Printf("prometheus-sidecar Envoy gRPC ext_proc listening on %s\n", *grpcAddr)
			if err := grpcServer.Serve(lis); err != nil {
				log.Fatalf("gRPC ext_proc exited: %v", err)
			}
		}()
	}

	fmt.Printf("prometheus-sidecar HTTP listening on http://%s (agent=%s mode=%s policy_sha=%s oidc_jwks=%v)\n",
		*addr, cfg.Agent.ID, cfg.Agent.Mode, eng.PolicySHA256[:12], eng.OIDCVerifier != nil)
	if err := http.ListenAndServe(*addr, httpSrv); err != nil {
		log.Fatalf("sidecar exited: %v", err)
	}
}
