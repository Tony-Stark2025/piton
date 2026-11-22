"""
Live MCP Server Introspection (`prometheus init --probe` / `prometheus snapshot`)
and STDIO MCP Wrapper (`prometheus wrap -- <stdio-cmd>`).

Eliminates the `observed_manifest.json` manual dead end:
- Probes live HTTP Streamable MCP servers (handling both JSON and `text/event-stream` SSE)
- Probes local STDIO MCP servers (Cursor / Claude Desktop style `initialize` -> `tools/list`)
- Provides a transparent STDIO JSON-RPC shim (`wrap_stdio_mcp`) that enforces `prometheus.lock`
  split-hash rug-pull pinning, Day-1 poisoning lint, and parameter bounds in-flight for
  Cursor / Claude Desktop / Claude Code STDIO MCP servers without code changes!
"""

import json
import os
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.request

from prometheus.iac.lockfile import verify_tools_list
from prometheus.iac.replay import (
    DecisionVerdict,
    SignedDecisionLedger,
    evaluate_tool_call_against_policy,
)
from prometheus.iac.schema import AgentIaCConfig, EnforcementMode, ManifestLockfile


def parse_sse_jsonrpc_messages(raw_body: str) -> List[Dict[str, Any]]:
    """Extracts JSON-RPC payloads from MCP `2026-07-28` `text/event-stream` SSE responses."""
    messages: List[Dict[str, Any]] = []
    data_buf: List[str] = []
    for line in raw_body.splitlines():
        if line.startswith("data:"):
            data_buf.append(line[5:].lstrip())
        elif line.strip() == "" and data_buf:
            chunk = "\n".join(data_buf).strip()
            data_buf = []
            if chunk and chunk != "[DONE]":
                try:
                    parsed = json.loads(chunk)
                    if isinstance(parsed, dict):
                        messages.append(parsed)
                except Exception:
                    pass
    if data_buf:
        chunk = "\n".join(data_buf).strip()
        if chunk and chunk != "[DONE]":
            try:
                parsed = json.loads(chunk)
                if isinstance(parsed, dict):
                    messages.append(parsed)
            except Exception:
                pass
    return messages


def extract_tools_from_rpc_body(raw_body: str, content_type: str = "") -> List[Dict[str, Any]]:
    """Extracts `result.tools` from either standard JSON or `text/event-stream` SSE MCP responses."""
    candidates: List[Dict[str, Any]] = []
    if "text/event-stream" in content_type.lower() or raw_body.lstrip().startswith("event:") or raw_body.lstrip().startswith("data:"):
        candidates.extend(parse_sse_jsonrpc_messages(raw_body))
    else:
        try:
            parsed = json.loads(raw_body)
            if isinstance(parsed, dict):
                candidates.append(parsed)
        except Exception:
            candidates.extend(parse_sse_jsonrpc_messages(raw_body))

    for msg in candidates:
        res = msg.get("result")
        if isinstance(res, dict) and isinstance(res.get("tools"), list):
            return [t for t in res["tools"] if isinstance(t, dict)]
    return []


def probe_http_mcp_tools(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 8.0,
) -> List[Dict[str, Any]]:
    """Queries a live HTTP / Streamable-HTTP MCP server for `tools/list`."""
    req_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/list",
    }
    if headers:
        req_headers.update(headers)

    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST", headers=req_headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        ctype = resp.headers.get("Content-Type", "")
        return extract_tools_from_rpc_body(raw, ctype)


def probe_stdio_mcp_tools(
    command: str,
    args: Optional[List[str]] = None,
    env: Optional[Dict[str, str]] = None,
    timeout: float = 8.0,
) -> List[Dict[str, Any]]:
    """
    Launches a local STDIO MCP server (no shell=True!), performs MCP `initialize` + `tools/list`,
    captures advertised tools, and cleanly terminates the subprocess.
    """
    argv = [command, *(args or [])]
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env or os.environ.copy(),
        text=True,
    )
    assert proc.stdin is not None and proc.stdout is not None

    try:
        init_msg = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "capabilities": {},
                    "clientInfo": {"name": "prometheus-probe", "version": "1.0.0"},
                },
            }
        )
        list_msg = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        proc.stdin.write(init_msg + "\n")
        proc.stdin.write(list_msg + "\n")
        proc.stdin.flush()

        tools_found: List[Dict[str, Any]] = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception:
                continue
            if isinstance(msg, dict) and msg.get("id") == 2:
                res = msg.get("result")
                if isinstance(res, dict) and isinstance(res.get("tools"), list):
                    tools_found = [t for t in res["tools"] if isinstance(t, dict)]
                break
        return tools_found
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


def probe_configured_servers(
    config: AgentIaCConfig,
    timeout: float = 8.0,
) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, str]]:
    """Probes all HTTP and STDIO MCP servers declared in `prometheus.yaml`."""
    manifests: Dict[str, List[Dict[str, Any]]] = {}
    errors: Dict[str, str] = {}
    for srv_name, srv in config.mcp_servers.items():
        try:
            if srv.url:
                manifests[srv_name] = probe_http_mcp_tools(srv.url, timeout=timeout)
            elif srv.command:
                manifests[srv_name] = probe_stdio_mcp_tools(srv.command, srv.args, timeout=timeout)
        except Exception as exc:
            errors[srv_name] = str(exc)
    return manifests, errors


def wrap_stdio_mcp(
    server_name: str,
    cmd: List[str],
    config: AgentIaCConfig,
    lockfile: Optional[ManifestLockfile],
    ledger: Optional[SignedDecisionLedger] = None,
    stdin_stream=None,
    stdout_stream=None,
) -> int:
    """
    Transparent STDIO JSON-RPC wrapper for Cursor / Claude Desktop / Claude Code MCP servers.
    - Intercepts client->server `tools/call` and enforces `prometheus.yaml` parameter bounds
      (writing signed ledger records).
    - Intercepts server->client `tools/list` responses and enforces `prometheus.lock` split-hash
      pinning + Day-1 poisoning lint (blocking third-party rug pulls with JSON-RPC -32001!).
    """
    client_in = stdin_stream or sys.stdin
    client_out = stdout_stream or sys.stdout

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
    )
    assert proc.stdin is not None and proc.stdout is not None

    out_lock = threading.Lock()
    pending_list_ids = set()

    def write_client(obj: Dict[str, Any]) -> None:
        with out_lock:
            client_out.write(json.dumps(obj) + "\n")
            client_out.flush()

    def pump_upstream() -> None:
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            line = raw_line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception:
                continue
            if isinstance(msg, dict) and msg.get("id") in pending_list_ids:
                pending_list_ids.discard(msg.get("id"))
                res = msg.get("result")
                if lockfile is not None and isinstance(res, dict) and isinstance(res.get("tools"), list):
                    tools = [t for t in res["tools"] if isinstance(t, dict)]
                    ver = verify_tools_list(lockfile, server_name, tools)
                    if not ver.passed and config.agent.mode == EnforcementMode.ENFORCE:
                        write_client(
                            {
                                "jsonrpc": "2.0",
                                "id": msg.get("id"),
                                "error": {
                                    "code": -32001,
                                    "message": "Prometheus STDIO Lockfile Rug-Pull Blocked",
                                    "data": ver.model_dump(mode="json"),
                                },
                            }
                        )
                        continue
            write_client(msg)

    reader_thread = threading.Thread(target=pump_upstream, daemon=True)
    reader_thread.start()

    try:
        for raw_line in client_in:
            line = raw_line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except Exception:
                continue
            if not isinstance(req, dict):
                write_client({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Batch JSON-RPC not permitted"}})
                continue

            method = req.get("method")
            req_id = req.get("id")
            if method == "tools/list":
                pending_list_ids.add(req_id)

            if method == "tools/call":
                params = req.get("params") or {}
                tool_name = str(params.get("name") or "")
                args = params.get("arguments") or {}
                if not isinstance(args, dict):
                    args = {}
                ev = evaluate_tool_call_against_policy(
                    config,
                    server_name,
                    tool_name,
                    args,
                    obo_principal=os.getenv("PROMETHEUS_LOCAL_PRINCIPAL", "user:local-dev"),
                    idempotency_key=args.get("idempotency_key") or f"stdio-{req_id}",
                )
                if ledger is not None:
                    ledger.append_decision(
                        config,
                        lockfile,
                        traceparent=f"00-stdio-{req_id}-01",
                        server_name=server_name,
                        tool_name=tool_name,
                        raw_arguments=args,
                        evaluation=ev,
                        obo_principal=os.getenv("PROMETHEUS_LOCAL_PRINCIPAL", "user:local-dev"),
                        idempotency_key=args.get("idempotency_key") or f"stdio-{req_id}",
                    )
                if ev.verdict in (DecisionVerdict.DENY, DecisionVerdict.MRTR_ESCALATE):
                    code = -32001 if ev.verdict == DecisionVerdict.DENY else -32002
                    write_client(
                        {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {
                                "code": code,
                                "message": "Prometheus STDIO Policy Enforcement",
                                "data": ev.model_dump(mode="json"),
                            },
                        }
                    )
                    continue

            proc.stdin.write(json.dumps(req) + "\n")
            proc.stdin.flush()
    finally:
        if proc.stdin:
            proc.stdin.close()
        reader_thread.join(timeout=2)
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
    return 0
