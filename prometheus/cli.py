"""
Unified Prometheus Control Loop CLI (`prometheus`).

Commands:
- `prometheus init [--repo .]` — Scan repo MCP configs & env templates, run Day-1 poisoning lint,
  and generate `prometheus.yaml` (shadow mode), `prometheus.lock`, and `.env.agent`.
- `prometheus lock [--diff | --update] [--manifest <json>]` — Verify or update split-hash MCP pins
  with GitHub PR-ready markdown diff output for CI gates.
- `prometheus replay --config prometheus.yaml --traces .prometheus/traces.jsonl [--simulate-enforce]`
  — Replay recorded shadow traces against candidate policies to reach 0% false blocks before enforcement.
- `prometheus ledger-verify --traces .prometheus/traces.jsonl` — Verify HMAC chain integrity of
  the version-pinned decision ledger.
- `prometheus top --traces .prometheus/traces.jsonl` — Stream/display live flight-recorder events.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional
import urllib.request

from prometheus.iac.lockfile import (
    DriftAction,
    DriftKind,
    ManifestDriftItem,
    build_lockfile_from_servers,
    detect_cross_server_shadowing,
    diff_lockfiles,
    render_diff_markdown,
    verify_tools_list,
)
from prometheus.iac.mcp_probe import probe_configured_servers, wrap_stdio_mcp
from prometheus.iac.scanner import scan_repository, write_init_artifacts
from prometheus.iac.replay import (
    SignedDecisionLedger,
    export_cedar_policies,
    export_cel_policies,
    load_otel_or_ledger_records,
    replay_traces,
)
from prometheus.iac.schema import AgentIaCConfig, ManifestLockfile, TrustTier


def _cmd_init(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    live_tools: Optional[Dict[str, List[Dict[str, Any]]]] = None
    if args.manifest:
        live_tools = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    elif args.probe:
        # First pass discovers MCP server URLs/commands from repo configs, then probes them live!
        pre = scan_repository(repo_root=repo, agent_id=args.agent_id, owner=args.owner)
        probed, probe_errs = probe_configured_servers(pre.config, timeout=args.probe_timeout)
        live_tools = probed
        for srv_name, err in probe_errs.items():
            print(f"[warn] Live probe failed for MCP server '{srv_name}': {err}", file=sys.stderr)

    res = scan_repository(
        repo_root=repo,
        agent_id=args.agent_id,
        owner=args.owner,
        live_server_tools=live_tools,
        allow_poisoned=args.allow_poisoned,
    )
    paths = write_init_artifacts(repo, res)

    print(f"Prometheus initialized for agent '{res.config.agent.id}' (mode={res.config.agent.mode.value})")
    print(f"  Discovered files: {', '.join(res.discovered_files) or 'none'}")
    for label, p in paths.items():
        print(f"  Wrote {label}: {p}")

    if res.poisoning_findings:
        print(f"\n[!] Day-1 MCP Poisoning Linter flagged {len(res.poisoning_findings)} finding(s):")
        for f in res.poisoning_findings:
            print(f"  - [{f.severity.value.upper()}] {f.server_name}.{f.tool_name} ({f.rule_id}): {f.message}")
        if not args.allow_poisoned:
            print("  Quarantined CRITICAL/HIGH tools were excluded from prometheus.lock.")
            return 2
    return 0


def _cmd_lock(args: argparse.Namespace) -> int:
    lock_path = Path(args.lockfile)
    config_path = Path(args.config)
    config = AgentIaCConfig.load_file(config_path) if config_path.is_file() else None

    if args.manifest:
        manifest_data: Dict[str, List[Dict[str, Any]]] = json.loads(
            Path(args.manifest).read_text(encoding="utf-8")
        )
    elif args.probe and config is not None:
        manifest_data, probe_errs = probe_configured_servers(config)
        for srv_name, err in probe_errs.items():
            print(f"[warn] Live probe failed for MCP server '{srv_name}': {err}", file=sys.stderr)
    else:
        print("Error: provide --manifest <json> or --probe with prometheus.yaml.", file=sys.stderr)
        return 1

    servers_for_lock = {}
    for srv_name, tools in manifest_data.items():
        trust = (
            config.mcp_servers[srv_name].trust_tier
            if config and srv_name in config.mcp_servers
            else TrustTier.THIRD_PARTY
        )
        url = config.mcp_servers[srv_name].url if config and srv_name in config.mcp_servers else None
        servers_for_lock[srv_name] = (trust, url, tools)

    shadowing = detect_cross_server_shadowing(manifest_data)
    if args.update:
        new_lock, findings = build_lockfile_from_servers(servers_for_lock, allow_poisoned=args.allow_poisoned)
        new_lock.save_file(lock_path)
        print(f"Updated {lock_path} (sha256={new_lock.canonical_sha256()[:16]}...)")
        if findings:
            print(f"Poisoning warnings/quarantined items: {len(findings)}")
        return 0

    if not lock_path.is_file():
        print(f"Error: lockfile not found at {lock_path}. Run `prometheus init` first.", file=sys.stderr)
        return 1

    existing_lock = ManifestLockfile.load_file(lock_path)

    if args.diff:
        new_lock, poison_findings = build_lockfile_from_servers(servers_for_lock, allow_poisoned=True)
        diff_res = diff_lockfiles(existing_lock, new_lock)
        diff_res.drifts.extend(shadowing)
        diff_res.blocked_count += len(shadowing)
        # Always block CI on CRITICAL/HIGH Day-1 or rug-pull poisoning even on internal servers
        for pf in poison_findings:
            if pf.severity.value in ("critical", "high"):
                diff_res.drifts.append(
                    ManifestDriftItem(
                        server_name=pf.server_name,
                        tool_name=pf.tool_name,
                        kind=DriftKind.DAY1_POISONING,
                        action=DriftAction.BLOCK,
                        message=f"Poisoning detected ({pf.rule_id}): {pf.message}",
                    )
                )
                diff_res.blocked_count += 1
        diff_res.passed = diff_res.blocked_count == 0
        print(render_diff_markdown(diff_res))
        return 0 if diff_res.passed else 1

    # Live/CI verification mode
    all_passed = len(shadowing) == 0
    for s in shadowing:
        print(f"[BLOCK] {s.message}")
    for srv_name, tools in manifest_data.items():
        res = verify_tools_list(existing_lock, srv_name, tools)
        if not res.passed:
            all_passed = False
        print(render_diff_markdown(res))
    return 0 if all_passed else 1


def _cmd_replay(args: argparse.Namespace) -> int:
    config = AgentIaCConfig.load_file(Path(args.config))
    records = load_otel_or_ledger_records(Path(args.traces))
    report = replay_traces(config, records, simulate_enforce=args.simulate_enforce)

    if args.export == "cel":
        print(export_cel_policies(config))
        return 0
    if args.export == "cedar":
        print(export_cedar_policies(config))
        return 0

    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        print(f"Prometheus Policy Replay — agent='{config.agent.id}' (simulate_enforce={args.simulate_enforce})")
        print(f"  Replayed calls:        {report.total_replayed}")
        print(f"  Allowed:               {report.allowed_count}")
        print(f"  Blocked / Escalated:   {report.blocked_or_escalated_count} ({report.false_block_rate_pct}%)")
        print(f"  Ready to enforce:      {'YES' if report.ready_to_enforce else 'NO'}")
        if report.suggestions:
            print("\nCalibration Suggestions:")
            for s in report.suggestions:
                print(f"  - [{s.rule_id}] {s.server_name}.{s.tool_name}: {s.suggestion}")

    return 0 if report.ready_to_enforce or not args.strict else 1


def _cmd_ledger_verify(args: argparse.Namespace) -> int:
    signing_key = os.getenv("PROMETHEUS_LEDGER_SIGNING_KEY", "prometheus-ledger-signing-key").encode("utf-8")
    ledger = SignedDecisionLedger(Path(args.traces), signing_key=signing_key)
    ok, err = ledger.verify_chain()
    if ok:
        print(f"Ledger integrity VERIFIED ({len(ledger.load_records())} chained records).")
        return 0
    print(f"Ledger integrity FAILED: {err}", file=sys.stderr)
    return 1


def _cmd_top(args: argparse.Namespace) -> int:
    traces_path = Path(args.traces)
    if not traces_path.is_file():
        print(f"No trace ledger found at {traces_path} yet.")
        return 0

    lines = traces_path.read_text(encoding="utf-8").splitlines()
    recent = lines[-args.limit :]
    print(f"{'VERDICT':<14} {'SERVER.TOOL':<32} {'LATENCY':>9}  {'TRACEPARENT':<24}  {'DETAILS'}")
    print("-" * 105)
    for raw in recent:
        if not raw.strip():
            continue
        rec = json.loads(raw)
        verdict = str(rec.get("verdict", "")).upper()
        st = f"{rec.get('server_name', '')}.{rec.get('tool_name', '')}"[:31]
        lat = f"{rec.get('latency_ms', 0.0):.1f}ms"
        tp = str(rec.get("traceparent", ""))[:23]
        viols = rec.get("violations") or []
        detail = viols[0]["rule_id"] if viols else "ok"
        print(f"{verdict:<14} {st:<32} {lat:>9}  {tp:<24}  {detail}")

    if args.follow:
        with traces_path.open("r", encoding="utf-8") as fh:
            fh.seek(0, os.SEEK_END)
            try:
                while True:
                    line = fh.readline()
                    if not line:
                        time.sleep(0.25)
                        continue
                    rec = json.loads(line)
                    print(
                        f"{str(rec.get('verdict', '')).upper():<14} "
                        f"{rec.get('server_name', '')}.{rec.get('tool_name', ''):<20} "
                        f"{rec.get('latency_ms', 0.0):.1f}ms"
                    )
            except KeyboardInterrupt:
                pass
    return 0


def _cmd_compile(args: argparse.Namespace) -> int:
    config = AgentIaCConfig.load_file(Path(args.config))
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(config.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Compiled {args.config} -> {out_path} (policy_sha256={config.canonical_sha256()[:16]}...)")
    return 0


def _detect_sidecar_asset_name() -> Optional[str]:
    import platform

    sys_os = platform.system().lower()
    if sys_os not in ("linux", "darwin"):
        return None
    mach = platform.machine().lower()
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "arm64": "arm64",
        "aarch64": "arm64",
    }
    goarch = arch_map.get(mach)
    if not goarch:
        return None
    return f"prometheus-sidecar-{sys_os}-{goarch}"


def _download_verified_sidecar_binary(
    version: Optional[str] = None,
    cache_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
) -> Optional[Path]:
    """
    Downloads the matching static `prometheus-sidecar` binary from GitHub Releases (or
    `PROMETHEUS_SIDECAR_RELEASE_URL` enterprise mirror), verifies its SHA-256 digest
    against `checksums.txt` (failing closed on mismatch), and caches it locally.
    """
    import hashlib
    from prometheus import __version__

    ver = version or __version__
    asset = _detect_sidecar_asset_name()
    if not asset:
        return None

    target_dir = cache_dir or (Path.home() / ".prometheus" / "bin")
    cached = target_dir / f"{asset}-v{ver}"
    if cached.is_file() and os.access(cached, os.X_OK):
        return cached

    release_base = (
        base_url
        or os.getenv("PROMETHEUS_SIDECAR_RELEASE_URL")
        or f"https://github.com/Tony-Stark2025/prometheus-enterprise/releases/download/v{ver}"
    ).rstrip("/")

    checksums_url = f"{release_base}/checksums.txt"
    binary_url = f"{release_base}/{asset}"

    try:
        with urllib.request.urlopen(checksums_url, timeout=15) as resp:
            checksums_raw = resp.read(256 * 1024).decode("utf-8", errors="replace")
    except Exception:
        return None

    expected_sha: Optional[str] = None
    for line in checksums_raw.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and Path(parts[1]).name == asset:
            expected_sha = parts[0].lower()
            break
    if not expected_sha or len(expected_sha) != 64:
        return None

    try:
        with urllib.request.urlopen(binary_url, timeout=60) as resp:
            data = resp.read(64 * 1024 * 1024)
    except Exception:
        return None

    actual_sha = hashlib.sha256(data).hexdigest().lower()
    if actual_sha != expected_sha:
        print(
            f"Error: SHA-256 verification failed for {asset} (expected {expected_sha[:16]}..., got {actual_sha[:16]}...). Refusing to execute.",
            file=sys.stderr,
        )
        return None

    target_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = cached.with_suffix(".tmp")
    tmp_path.write_bytes(data)
    tmp_path.chmod(0o755)
    tmp_path.replace(cached)
    return cached


def _resolve_sidecar_binary(explicit_bin: Optional[str]) -> Optional[Path]:
    if explicit_bin:
        p = Path(explicit_bin)
        return p if p.is_file() else None
    env_bin = os.getenv("PROMETHEUS_SIDECAR_BIN")
    if env_bin:
        p = Path(env_bin)
        return p if p.is_file() else None
    found = shutil.which("prometheus-sidecar")
    if found:
        return Path(found)
    repo_sidecar = Path(__file__).resolve().parent.parent / "sidecar"
    local_bin = repo_sidecar / "bin" / "prometheus-sidecar"
    if local_bin.is_file():
        return local_bin
    if shutil.which("go") and (repo_sidecar / "cmd" / "prometheus-sidecar" / "main.go").is_file():
        local_bin.parent.mkdir(parents=True, exist_ok=True)
        res = subprocess.run(
            ["go", "build", "-o", str(local_bin), "./cmd/prometheus-sidecar"],
            cwd=str(repo_sidecar),
            capture_output=True,
            text=True,
        )
        if res.returncode == 0 and local_bin.is_file():
            return local_bin
    return _download_verified_sidecar_binary()


def _load_dotenv(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _cmd_run(args: argparse.Namespace) -> int:
    cmd = list(args.cmd or [])
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("Error: provide an agent command after `--`, e.g. `prometheus run -- python agent.py`", file=sys.stderr)
        return 2

    config_path = Path(args.config)
    config = AgentIaCConfig.load_file(config_path)
    compiled_path = Path(args.compiled_policy)
    compiled_path.parent.mkdir(parents=True, exist_ok=True)
    compiled_path.write_text(
        json.dumps(config.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    sidecar_bin = _resolve_sidecar_binary(args.sidecar_bin)
    if sidecar_bin is None:
        print("Error: prometheus-sidecar binary not found and `go` toolchain unavailable.", file=sys.stderr)
        return 1

    # Host process (sidecar) inherits real secrets; child agent process receives ONLY ghost handles!
    sidecar_cmd = [
        str(sidecar_bin),
        "--policy", str(compiled_path),
        "--lock", str(args.lockfile),
        "--traces", str(args.traces),
        "--ghost-env", str(args.ghost_env),
        "--addr", str(args.addr),
    ]
    sidecar_proc = subprocess.Popen(sidecar_cmd, env=os.environ.copy())

    try:
        # Wait up to 5s for /healthz
        health_url = f"http://{args.addr}/healthz"
        ready = False
        for _ in range(50):
            try:
                with urllib.request.urlopen(health_url, timeout=0.2) as resp:
                    if resp.status == 200:
                        ready = True
                        break
            except Exception:
                time.sleep(0.1)
        if not ready:
            print(f"Error: prometheus-sidecar failed to become healthy at {health_url}", file=sys.stderr)
            return 1

        # Build scrubbed child environment: strip every real secret referenced in local_dev_credentials
        child_env = os.environ.copy()
        for slot in config.local_dev_credentials.values():
            if slot.source.startswith("env://"):
                real_var = slot.source[len("env://") :]
                child_env.pop(real_var, None)

        # Inject safe format-preserving ghost handles + gateway base URLs from .env.agent
        ghost_vars = _load_dotenv(Path(args.ghost_env))
        for k, v in ghost_vars.items():
            if k.endswith("_BASE_URL") and "127.0.0.1" not in v and "localhost:8080" in v:
                v = v.replace("localhost:8080", args.addr)
            child_env[k] = v
        child_env["PROMETHEUS_GATEWAY_URL"] = f"http://{args.addr}"

        res = subprocess.run(cmd, env=child_env)
        return int(res.returncode)
    finally:
        sidecar_proc.terminate()
        try:
            sidecar_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            sidecar_proc.kill()


def _cmd_wrap(args: argparse.Namespace) -> int:
    cmd = list(args.cmd or [])
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("Error: provide a STDIO MCP command after `--`, e.g. `prometheus wrap --server fs -- npx @modelcontextprotocol/server-filesystem`", file=sys.stderr)
        return 2

    config = AgentIaCConfig.load_file(Path(args.config))
    lockfile = ManifestLockfile.load_file(Path(args.lockfile)) if Path(args.lockfile).is_file() else None
    signing_key = os.getenv("PROMETHEUS_LEDGER_SIGNING_KEY", "prometheus-ledger-signing-key").encode("utf-8")
    ledger = SignedDecisionLedger(Path(args.traces), signing_key=signing_key) if args.traces else None
    return wrap_stdio_mcp(args.server, cmd, config, lockfile, ledger=ledger)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prometheus",
        description="Prometheus Agent Control Loop — MCP Manifest Pinning, Shadow Policy Replay & Signed Audit Ledgers",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Scan repo MCP configs & env templates to generate prometheus.yaml & prometheus.lock")
    p_init.add_argument("--repo", default=".", help="Repository path to scan")
    p_init.add_argument("--agent-id", default=None, help="Explicit agent ID")
    p_init.add_argument("--owner", default="platform-team@example.com", help="Owning team email")
    p_init.add_argument("--manifest", default=None, help="Optional JSON file mapping server_name -> tools/list array")
    p_init.add_argument("--probe", action="store_true", help="Live-probe discovered HTTP/STDIO MCP servers for tools/list")
    p_init.add_argument("--probe-timeout", type=float, default=8.0, help="Per-server live probe timeout in seconds")
    p_init.add_argument("--allow-poisoned", action="store_true", help="Include tools even if poisoning lint flags them")
    p_init.set_defaults(func=_cmd_init)

    p_compile = sub.add_parser("compile", help="Compile prometheus.yaml into .prometheus/runtime_policy.json for Go sidecar")
    p_compile.add_argument("--config", default="prometheus.yaml")
    p_compile.add_argument("--out", default=".prometheus/runtime_policy.json")
    p_compile.set_defaults(func=_cmd_compile)

    p_run = sub.add_parser("run", help="Boot zero-secret Go sidecar, scrub real env secrets, inject .env.agent, and run agent")
    p_run.add_argument("--config", default="prometheus.yaml")
    p_run.add_argument("--lockfile", default="prometheus.lock")
    p_run.add_argument("--ghost-env", default=".env.agent")
    p_run.add_argument("--traces", default=".prometheus/traces.jsonl")
    p_run.add_argument("--compiled-policy", default=".prometheus/runtime_policy.json")
    p_run.add_argument("--addr", default="127.0.0.1:8080")
    p_run.add_argument("--sidecar-bin", default=None)
    p_run.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to run (prefix with --)")
    p_run.set_defaults(func=_cmd_run)

    p_wrap = sub.add_parser("wrap", help="Transparent STDIO MCP wrapper enforcing prometheus.lock & bounds for Cursor/Claude Desktop")
    p_wrap.add_argument("--server", required=True, help="MCP server name in prometheus.yaml / prometheus.lock")
    p_wrap.add_argument("--config", default="prometheus.yaml")
    p_wrap.add_argument("--lockfile", default="prometheus.lock")
    p_wrap.add_argument("--traces", default=".prometheus/traces.jsonl")
    p_wrap.add_argument("cmd", nargs=argparse.REMAINDER, help="STDIO MCP server command (prefix with --)")
    p_wrap.set_defaults(func=_cmd_wrap)

    p_lock = sub.add_parser("lock", help="Verify, diff, or update prometheus.lock MCP pins")
    p_lock.add_argument("--manifest", default=None, help="JSON file mapping server_name -> observed tools/list array")
    p_lock.add_argument("--probe", action="store_true", help="Live-probe MCP servers from prometheus.yaml instead of static JSON")
    p_lock.add_argument("--lockfile", default="prometheus.lock")
    p_lock.add_argument("--config", default="prometheus.yaml")
    p_lock.add_argument("--diff", action="store_true", help="Render PR-ready markdown diff against existing lockfile")
    p_lock.add_argument("--update", action="store_true", help="Update prometheus.lock with observed manifests")
    p_lock.add_argument("--allow-poisoned", action="store_true")
    p_lock.set_defaults(func=_cmd_lock)

    p_replay = sub.add_parser("replay", help="Replay recorded shadow traces (or OTel logs) against candidate prometheus.yaml")
    p_replay.add_argument("--config", default="prometheus.yaml")
    p_replay.add_argument("--traces", default=".prometheus/traces.jsonl")
    p_replay.add_argument("--simulate-enforce", action="store_true", default=True)
    p_replay.add_argument("--strict", action="store_true", help="Exit non-zero if any calls would be blocked")
    p_replay.add_argument("--export", choices=["cel", "cedar"], default=None, help="Export calibrated CEL (agentgateway) or Cedar (ToolHive/AgentCore) policies")
    p_replay.add_argument("--json", action="store_true", help="Output JSON report")
    p_replay.set_defaults(func=_cmd_replay)

    p_verify = sub.add_parser("ledger-verify", help="Verify HMAC chain integrity of a signed decision ledger")
    p_verify.add_argument("--traces", default=".prometheus/traces.jsonl")
    p_verify.set_defaults(func=_cmd_ledger_verify)

    p_top = sub.add_parser("top", help="Flight recorder view of recent/live agent tool decisions")
    p_top.add_argument("--traces", default=".prometheus/traces.jsonl")
    p_top.add_argument("--limit", type=int, default=25)
    p_top.add_argument("--follow", "-f", action="store_true")
    p_top.set_defaults(func=_cmd_top)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
