package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	ext_procv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

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
	addr := flag.String("addr", "127.0.0.1:8080", "HTTP listen address (/gw, /mcp, /healthz, /metrics)")
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
	httpHandler := proxy.NewServer(eng, ghosts)

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           httpHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	var grpcServer *grpc.Server
	if *grpcAddr != "" {
		lis, err := net.Listen("tcp", *grpcAddr)
		if err != nil {
			log.Fatalf("failed to bind Envoy gRPC ext_proc on %s: %v", *grpcAddr, err)
		}
		grpcServer = grpc.NewServer(grpc.MaxRecvMsgSize(10 << 20), grpc.MaxSendMsgSize(10 << 20))
		ext_procv3.RegisterExternalProcessorServer(grpcServer, extproc.NewServer(eng, httpHandler.ActiveSecrets))
		hs := health.NewServer()
		hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
		healthpb.RegisterHealthServer(grpcServer, hs)

		go func() {
			fmt.Printf("prometheus-sidecar Envoy gRPC ext_proc listening on %s\n", *grpcAddr)
			if err := grpcServer.Serve(lis); err != nil {
				log.Printf("gRPC ext_proc stopped: %v", err)
			}
		}()
	}

	// Graceful SIGTERM/SIGINT drain for zero-downtime Kubernetes rollouts
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		fmt.Println("prometheus-sidecar received shutdown signal; draining gracefully...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
		if grpcServer != nil {
			grpcServer.GracefulStop()
		}
	}()

	fmt.Printf("prometheus-sidecar HTTP listening on http://%s (agent=%s mode=%s policy_sha=%s oidc_jwks=%v)\n",
		*addr, cfg.Agent.ID, cfg.Agent.Mode, eng.PolicySHA256[:12], eng.OIDCVerifier != nil)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("sidecar exited: %v", err)
	}
}
