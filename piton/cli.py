"""
Unified Piton Control Loop CLI (`piton`).

Commands:
- `piton init [--repo .]` — Scan repo MCP configs & env templates, run Day-1 poisoning lint,
  and generate `piton.yaml` (shadow mode), `piton.lock`, and `.env.agent`.
- `piton lock [--diff | --update] [--manifest <json>]` — Verify or update split-hash MCP pins
  with GitHub PR-ready markdown diff output for CI gates.
- `piton replay --config piton.yaml --traces .piton/traces.jsonl [--simulate-enforce]`
  — Replay recorded shadow traces against candidate policies to reach 0% false blocks before enforcement.
- `piton ledger-verify --traces .piton/traces.jsonl` — Verify HMAC chain integrity of
  the version-pinned decision ledger.
- `piton top --traces .piton/traces.jsonl` — Stream/display live flight-recorder events.
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

from piton.iac.agent_config_lint import scan_agent_supply_chain
from piton.iac.lockfile import (
    DriftAction,
    DriftKind,
    ManifestDriftItem,
    build_lockfile_from_servers,
    detect_cross_server_shadowing,
    diff_lockfiles,
    render_diff_markdown,
    verify_tools_list,
)
from piton.iac.mcp_probe import probe_configured_servers, wrap_stdio_mcp
from piton.iac.scanner import scan_repository, write_init_artifacts
from piton.iac.replay import (
    SignedDecisionLedger,
    export_cedar_policies,
    export_cel_policies,
    load_otel_or_ledger_records,
    replay_traces,
)
from piton.iac.schema import AgentIaCConfig, ManifestLockfile, TrustTier


def _default_config_name() -> str:
    return "piton.yaml"


def _default_lock_name() -> str:
    return "piton.lock"


def _cmd_scan(args: argparse.Namespace) -> int:
    """
    Fast, zero-config static scan for AI coding-agent supply-chain attacks:
    - `.claude/settings.json` hook RCE (`curl|sh`, reverse shells, credential exfil, unsafe Bash wildcards)
    - `.vscode/tasks.json` `folderOpen` autorun RCE
    - `.cursor/rules/*`, `.cursorrules`, `CLAUDE.md`, `AGENTS.md`, skills/commands Unicode & prompt-injection poisoning
    """
    repo = Path(args.repo).resolve()
    cfg_scan = scan_agent_supply_chain(repo)

    if getattr(args, "json", False):
        print(cfg_scan.model_dump_json(indent=2))
        return 1 if cfg_scan.critical_or_high_count > 0 else 0

    print(f"Piton Supply-Chain Scan — repo='{repo.name}'")
    print(f"  Scanned agent files: {', '.join(cfg_scan.scanned_files) or 'none'}")
    if not cfg_scan.findings:
        print("  Status: CLEAN (0 findings)")
        return 0

    print(f"  Status: FLAGGED ({len(cfg_scan.findings)} finding(s), {cfg_scan.critical_or_high_count} CRITICAL/HIGH)")
    for f in cfg_scan.findings:
        print(f"  - [{f.severity.value.upper()}] {f.tool_name} ({f.field_path}) [{f.rule_id}]: {f.message}")
        if f.matched_snippet:
            print(f"      snippet: {f.matched_snippet}")
    return 1 if cfg_scan.critical_or_high_count > 0 else 0


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

    agent_cfg_scan = scan_agent_supply_chain(repo)
    print(f"Piton initialized for agent '{res.config.agent.id}' (mode={res.config.agent.mode.value})")
    all_discovered = list(dict.fromkeys(res.discovered_files + agent_cfg_scan.scanned_files))
    print(f"  Discovered files: {', '.join(all_discovered) or 'none'}")
    for label, p in paths.items():
        print(f"  Wrote {label}: {p}")

    all_findings = list(res.poisoning_findings) + list(agent_cfg_scan.findings)
    if all_findings:
        print(f"\n[!] Day-1 Supply-Chain & MCP Poisoning Linter flagged {len(all_findings)} finding(s):")
        for f in all_findings:
            target = f"{f.server_name}: {f.tool_name}" if f.server_name in ("agent-config", "agent-rules", "mcp-config") else f"{f.server_name}.{f.tool_name}"
            print(f"  - [{f.severity.value.upper()}] {target} ({f.rule_id}): {f.message}")
        if not args.allow_poisoned:
            if any(f.severity.value in ("critical", "high") for f in res.poisoning_findings):
                print("  Quarantined CRITICAL/HIGH MCP tools were excluded from piton.yaml and piton.lock.")
            return 2
    return 0


def _cmd_lock(args: argparse.Namespace) -> int:
    lock_path = Path(args.lockfile)
    config_path = Path(args.config)
    config = AgentIaCConfig.load_file(config_path) if config_path.is_file() else None
    probe_errs: Dict[str, str] = {}

    if args.manifest:
        manifest_path = Path(args.manifest)
        if not manifest_path.is_file():
            print(f"Error: manifest file not found at {manifest_path}.", file=sys.stderr)
            return 1
        manifest_data: Dict[str, List[Dict[str, Any]]] = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )
    elif args.probe and config is not None:
        manifest_data, probe_errs = probe_configured_servers(config, timeout=getattr(args, "probe_timeout", 8.0))
        for srv_name, err in probe_errs.items():
            print(f"[warn] Live probe failed for MCP server '{srv_name}': {err}", file=sys.stderr)
    else:
        print("Error: provide --manifest <json> or --probe with piton.yaml.", file=sys.stderr)
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
        if probe_errs:
            print("Error: refusing to update lockfile because one or more MCP servers failed to probe.", file=sys.stderr)
            return 1
        new_lock, findings = build_lockfile_from_servers(servers_for_lock, allow_poisoned=args.allow_poisoned)
        new_lock.save_file(lock_path)
        print(f"Updated {lock_path} (sha256={new_lock.canonical_sha256()[:16]}...)")
        if findings:
            print(f"Poisoning warnings/quarantined items: {len(findings)}")
        return 0

    if not lock_path.is_file():
        print(f"Error: lockfile not found at {lock_path}. Run `piton init` first.", file=sys.stderr)
        return 1

    existing_lock = ManifestLockfile.load_file(lock_path)

    if args.diff:
        new_lock, poison_findings = build_lockfile_from_servers(servers_for_lock, allow_poisoned=True)
        diff_res = diff_lockfiles(existing_lock, new_lock)
        diff_res.drifts.extend(shadowing)
        diff_res.blocked_count += len(shadowing)
        # Fail closed when a pinned server fails live probing
        for srv_name, err in probe_errs.items():
            if srv_name in existing_lock.servers:
                diff_res.drifts.append(
                    ManifestDriftItem(
                        server_name=srv_name,
                        tool_name="*",
                        kind=DriftKind.PROBE_ERROR,
                        action=DriftAction.BLOCK,
                        message=f"Live probe failed for pinned server '{srv_name}': {err}",
                    )
                )
                diff_res.blocked_count += 1
        # Include static coding-agent hook/skill/rules RCE findings when scanning repo
        if not getattr(args, "no_agent_scan", False):
            repo_dir = Path(getattr(args, "repo", ".") or ".").resolve()
            if repo_dir.is_dir():
                agent_scan = scan_agent_supply_chain(repo_dir)
                poison_findings.extend(agent_scan.findings)
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
    all_passed = len(shadowing) == 0 and not any(s in existing_lock.servers for s in probe_errs)
    for srv_name, err in probe_errs.items():
        if srv_name in existing_lock.servers:
            print(f"[BLOCK] Live probe failed for pinned server '{srv_name}': {err}")
    for s in shadowing:
        print(f"[BLOCK] {s.message}")
    for srv_name, tools in manifest_data.items():
        res = verify_tools_list(existing_lock, srv_name, tools)
        if not res.passed:
            all_passed = False
        print(render_diff_markdown(res))
    return 0 if all_passed else 1


def _cmd_replay(args: argparse.Namespace) -> int:
    cfg_path = Path(args.config)
    if not cfg_path.is_file():
        print(f"Error: config file not found at {cfg_path}. Run `piton init` first.", file=sys.stderr)
        return 1
    config = AgentIaCConfig.load_file(cfg_path)
    records = load_otel_or_ledger_records(Path(args.traces))
    report = replay_traces(config, records, simulate_enforce=args.simulate_enforce)

    if args.export in ("cel", "cedar"):
        if args.strict and not report.ready_to_enforce:
            print(
                f"Error: replay reported {report.blocked_or_escalated_count}/{report.total_replayed} "
                f"blocked/escalated calls ({report.false_block_rate_pct}%); refusing to export under --strict.",
                file=sys.stderr,
            )
            return 1
        if not report.ready_to_enforce and report.total_replayed > 0:
            print(
                f"[warn] Exporting current {cfg_path.name} with {report.blocked_or_escalated_count}/{report.total_replayed} "
                f"uncalibrated call(s) ({report.false_block_rate_pct}%); pass --strict to block uncalibrated exports.",
                file=sys.stderr,
            )
        print(export_cel_policies(config) if args.export == "cel" else export_cedar_policies(config))
        return 0

    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        print(f"Piton Policy Replay — agent='{config.agent.id}' (simulate_enforce={args.simulate_enforce})")
        print(f"  Replayed calls:        {report.total_replayed}")
        print(f"  Allowed:               {report.allowed_count}")
        print(f"  Blocked / Escalated:   {report.blocked_or_escalated_count} ({report.false_block_rate_pct}%)")
        readiness = "YES" if report.ready_to_enforce else "NO"
        if report.ready_to_enforce and report.total_replayed < 20:
            readiness += f" (low sample size: {report.total_replayed} calls; recommend >= 20)"
        print(f"  Ready to enforce:      {readiness}")
        if report.suggestions:
            print("\nCalibration Suggestions:")
            for s in report.suggestions:
                print(f"  - [{s.rule_id}] {s.server_name}.{s.tool_name}: {s.suggestion}")

    return 0 if report.ready_to_enforce or not args.strict else 1


def _cmd_ledger_verify(args: argparse.Namespace) -> int:
    signing_key = os.getenv("PITON_LEDGER_SIGNING_KEY", "piton-ledger-signing-key").encode("utf-8")
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
    cfg_path = Path(args.config)
    if not cfg_path.is_file():
        print(f"Error: config file not found at {cfg_path}. Run `piton init` first.", file=sys.stderr)
        return 1
    config = AgentIaCConfig.load_file(cfg_path)
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
    return f"piton-sidecar-{sys_os}-{goarch}"


def _download_verified_sidecar_binary(
    version: Optional[str] = None,
    cache_dir: Optional[Path] = None,
    base_url: Optional[str] = None,
) -> Optional[Path]:
    """
    Downloads the matching static `piton-sidecar` binary from GitHub Releases (or
    `PITON_SIDECAR_RELEASE_URL` enterprise mirror), verifies its SHA-256 digest
    against `checksums.txt` (failing closed on mismatch), and caches it locally.
    """
    import hashlib
    from piton import __version__

    ver = version or __version__
    asset = _detect_sidecar_asset_name()
    if not asset:
        return None

    target_dir = cache_dir or (Path.home() / ".piton" / "bin")
    cached = target_dir / f"{asset}-v{ver}"
    if cached.is_file() and os.access(cached, os.X_OK):
        return cached

    release_base = (
        base_url
        or os.getenv("PITON_SIDECAR_RELEASE_URL")
        or f"https://github.com/Tony-Stark2025/piton/releases/download/v{ver}"
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
    env_bin = os.getenv("PITON_SIDECAR_BIN")
    if env_bin:
        p = Path(env_bin)
        return p if p.is_file() else None
    found = shutil.which("piton-sidecar")
    if found:
        return Path(found)
    repo_sidecar = Path(__file__).resolve().parent.parent / "sidecar"
    local_bin = repo_sidecar / "bin" / "piton-sidecar"
    if local_bin.is_file():
        return local_bin
    if shutil.which("go") and (repo_sidecar / "cmd" / "piton-sidecar" / "main.go").is_file():
        local_bin.parent.mkdir(parents=True, exist_ok=True)
        res = subprocess.run(
            ["go", "build", "-o", str(local_bin), "./cmd/piton-sidecar"],
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
        print("Error: provide an agent command after `--`, e.g. `piton run -- python agent.py`", file=sys.stderr)
        return 2

    config_path = Path(args.config)
    if not config_path.is_file():
        print(f"Error: config file not found at {config_path}. Run `piton init` first.", file=sys.stderr)
        return 1
    config = AgentIaCConfig.load_file(config_path)
    compiled_path = Path(args.compiled_policy)
    compiled_path.parent.mkdir(parents=True, exist_ok=True)
    compiled_path.write_text(
        json.dumps(config.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    sidecar_bin = _resolve_sidecar_binary(args.sidecar_bin)
    if sidecar_bin is None:
        print("Error: piton-sidecar binary not found and `go` toolchain unavailable.", file=sys.stderr)
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
    if getattr(args, "collector_url", None):
        sidecar_cmd.extend(["--collector-url", str(args.collector_url)])
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
            print(f"Error: piton-sidecar failed to become healthy at {health_url}", file=sys.stderr)
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
        child_env["PITON_GATEWAY_URL"] = f"http://{args.addr}"

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
        print("Error: provide a STDIO MCP command after `--`, e.g. `piton wrap --enforce --server fs -- npx @modelcontextprotocol/server-filesystem`", file=sys.stderr)
        return 2

    cfg_path = Path(args.config)
    if not cfg_path.is_file():
        print(f"Error: config file not found at {cfg_path}. Run `piton init` first.", file=sys.stderr)
        return 1
    config = AgentIaCConfig.load_file(cfg_path)
    lockfile = ManifestLockfile.load_file(Path(args.lockfile)) if Path(args.lockfile).is_file() else None
    signing_key = os.getenv("PITON_LEDGER_SIGNING_KEY", "piton-ledger-signing-key").encode("utf-8")
    ledger = SignedDecisionLedger(Path(args.traces), signing_key=signing_key) if args.traces else None
    return wrap_stdio_mcp(
        args.server,
        cmd,
        config,
        lockfile,
        ledger=ledger,
        enforce_override=getattr(args, "enforce", False),
    )


def _cmd_control_plane(args: argparse.Namespace) -> int:
    from piton.control_plane.server import create_control_plane_server

    signing_key = os.getenv("PITON_LEDGER_SIGNING_KEY", "piton-ledger-signing-key").encode("utf-8")
    api_key = os.getenv("PITON_CONTROL_API_KEY", "")
    slack_webhook = args.slack_webhook or os.getenv("PITON_SLACK_WEBHOOK_URL", "")
    slack_secret = os.getenv("PITON_SLACK_SIGNING_SECRET", "")

    httpd, store = create_control_plane_server(
        host=args.host,
        port=args.port,
        db_path=args.db,
        signing_key=signing_key,
        api_key=api_key,
        slack_webhook_url=slack_webhook,
        slack_signing_secret=slack_secret,
    )
    print(
        f"Piton Control Plane listening on http://{args.host}:{args.port} "
        f"(db={args.db} slack_webhook={bool(slack_webhook)} api_key={bool(api_key)})"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Piton Control Plane...")
    finally:
        httpd.server_close()
        store.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    from piton import __version__

    cfg_default = _default_config_name()
    lock_default = _default_lock_name()

    parser = argparse.ArgumentParser(
        prog="piton",
        description="Piton — Lockfile and static supply-chain scanner for MCP servers, Claude Code hooks, and Cursor rules.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"piton {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Zero-config scan for Claude Code hook RCE, VS Code folderOpen autorun & poisoned Cursor/skill rules")
    p_scan.add_argument("--repo", default=".", help="Repository path to scan")
    p_scan.add_argument("--json", action="store_true", help="Output JSON findings")
    p_scan.set_defaults(func=_cmd_scan)

    p_init = sub.add_parser("init", help="Scan repo MCP configs, coding-agent hooks & env templates to generate piton.yaml & piton.lock")
    p_init.add_argument("--repo", default=".", help="Repository path to scan")
    p_init.add_argument("--agent-id", default=None, help="Explicit agent ID")
    p_init.add_argument("--owner", default="platform-team@example.com", help="Owning team email")
    p_init.add_argument("--manifest", default=None, help="Optional JSON file mapping server_name -> tools/list array")
    p_init.add_argument("--probe", action="store_true", help="Live-probe discovered HTTP/STDIO MCP servers for tools/list")
    p_init.add_argument("--probe-timeout", type=float, default=8.0, help="Per-server live probe timeout in seconds")
    p_init.add_argument("--allow-poisoned", action="store_true", help="Include tools even if poisoning lint flags them")
    p_init.set_defaults(func=_cmd_init)

    p_compile = sub.add_parser("compile", help="Compile piton.yaml into .piton/runtime_policy.json for Go sidecar")
    p_compile.add_argument("--config", default=cfg_default)
    p_compile.add_argument("--out", default=".piton/runtime_policy.json")
    p_compile.set_defaults(func=_cmd_compile)

    p_run = sub.add_parser("run", help="Boot zero-secret Go sidecar, scrub real env secrets, inject .env.agent, and run agent")
    p_run.add_argument("--config", default=cfg_default)
    p_run.add_argument("--lockfile", default=lock_default)
    p_run.add_argument("--ghost-env", default=".env.agent")
    p_run.add_argument("--traces", default=".piton/traces.jsonl")
    p_run.add_argument("--compiled-policy", default=".piton/runtime_policy.json")
    p_run.add_argument("--addr", default="127.0.0.1:8080")
    p_run.add_argument("--collector-url", default=os.getenv("PITON_COLLECTOR_URL", ""), help="Optional Control Plane URL for fleet ledger & MRTR approvals")
    p_run.add_argument("--sidecar-bin", default=None)
    p_run.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to run (prefix with --)")
    p_run.set_defaults(func=_cmd_run)

    p_wrap = sub.add_parser("wrap", help="Transparent STDIO MCP wrapper enforcing piton.lock & bounds for Cursor/Claude Code")
    p_wrap.add_argument("--server", required=True, help="MCP server name in piton.yaml / piton.lock")
    p_wrap.add_argument("--config", default=cfg_default)
    p_wrap.add_argument("--lockfile", default=lock_default)
    p_wrap.add_argument("--traces", default=".piton/traces.jsonl")
    p_wrap.add_argument("--enforce", action="store_true", help="Hard-block rug pulls & bound violations even if piton.yaml is in shadow mode")
    p_wrap.add_argument("cmd", nargs=argparse.REMAINDER, help="STDIO MCP server command (prefix with --)")
    p_wrap.set_defaults(func=_cmd_wrap)

    p_cp = sub.add_parser("control-plane", help="Run central Fleet Ledger Collector, MRTR Slack/Webhook Approval Bridge & Governance UI")
    p_cp.add_argument("--host", default="127.0.0.1")
    p_cp.add_argument("--port", type=int, default=8090)
    p_cp.add_argument("--db", default=".piton/control_plane.db")
    p_cp.add_argument("--slack-webhook", default="", help="Optional Slack Incoming Webhook URL for MRTR Block Kit prompts")
    p_cp.set_defaults(func=_cmd_control_plane)

    p_lock = sub.add_parser("lock", help="Verify, diff, or update split-hash MCP pins & agent hook/skill supply-chain checks")
    p_lock.add_argument("--repo", default=".", help="Repository path to also lint for coding-agent hook/skill poisoning")
    p_lock.add_argument("--no-agent-scan", action="store_true", help="Skip static repo hook/rule scan (e.g. when piton scan already ran)")
    p_lock.add_argument("--manifest", default=None, help="JSON file mapping server_name -> observed tools/list array")
    p_lock.add_argument("--probe", action="store_true", help="Live-probe MCP servers from config instead of static JSON")
    p_lock.add_argument("--probe-timeout", type=float, default=8.0, help="Per-server live probe timeout in seconds")
    p_lock.add_argument("--lockfile", default=lock_default)
    p_lock.add_argument("--config", default=cfg_default)
    p_lock.add_argument("--diff", action="store_true", help="Render PR-ready markdown diff against existing lockfile")
    p_lock.add_argument("--update", action="store_true", help="Update lockfile with observed manifests")
    p_lock.add_argument("--allow-poisoned", action="store_true")
    p_lock.set_defaults(func=_cmd_lock)

    p_replay = sub.add_parser("replay", help="Replay recorded shadow traces (or OTel logs) against candidate policy")
    p_replay.add_argument("--config", default=cfg_default)
    p_replay.add_argument("--traces", default=".piton/traces.jsonl")
    p_replay.add_argument("--simulate-enforce", action="store_true", default=True)
    p_replay.add_argument("--strict", action="store_true", help="Exit non-zero if any calls would be blocked")
    p_replay.add_argument("--export", choices=["cel", "cedar"], default=None, help="Export calibrated CEL (agentgateway) or Cedar (ToolHive/AgentCore) policies")
    p_replay.add_argument("--json", action="store_true", help="Output JSON report")
    p_replay.set_defaults(func=_cmd_replay)

    p_verify = sub.add_parser("ledger-verify", help="Verify HMAC chain integrity of a signed decision ledger")
    p_verify.add_argument("--traces", default=".piton/traces.jsonl")
    p_verify.set_defaults(func=_cmd_ledger_verify)

    p_top = sub.add_parser("top", help="Flight recorder view of recent/live agent tool decisions")
    p_top.add_argument("--traces", default=".piton/traces.jsonl")
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
