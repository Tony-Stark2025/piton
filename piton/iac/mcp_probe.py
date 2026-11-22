"""
Live MCP Server Introspection (`piton init --probe` / `piton lock --probe`)
and STDIO MCP Wrapper (`piton wrap -- <stdio-cmd>`).

Real-world MCP protocol support (Streamable HTTP 2025-03-26 / 2026-07-28 & STDIO):
- Full `initialize` -> `Mcp-Session-Id` -> `notifications/initialized` handshake
- Paginated `tools/list` traversal (`nextCursor`, bounded to prevent DoS loops)
- Dual `application/json` and `text/event-stream` SSE response parsing
- Non-blocking timeout enforcement on STDIO subprocess reads
- Transparent STDIO JSON-RPC wrapper (`wrap_stdio_mcp`) for Cursor / Claude Desktop / Claude Code
  preserving string/int IDs, passing notifications cleanly, enforcing `piton.lock`
  split-hash pinning + Day-1 poisoning lint, and recording signed ledger entries.
"""

import json
import os
import queue
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from piton.iac.lockfile import verify_tools_list
from piton.iac.replay import (
    DecisionVerdict,
    SignedDecisionLedger,
    evaluate_tool_call_against_policy,
)
from piton.iac.schema import AgentIaCConfig, EnforcementMode, ManifestLockfile

MAX_TOOL_LIST_PAGES = 25


def parse_sse_jsonrpc_messages(raw_body: str) -> List[Dict[str, Any]]:
    """Extracts JSON-RPC payloads from MCP `text/event-stream` SSE responses."""
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


def extract_tools_page_from_rpc_body(
    raw_body: str, content_type: str = ""
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Extracts `(tools, nextCursor)` from either standard JSON or `text/event-stream` SSE MCP responses.
    """
    candidates: List[Dict[str, Any]] = []
    stripped = raw_body.lstrip()
    if (
        "text/event-stream" in content_type.lower()
        or stripped.startswith("event:")
        or stripped.startswith("data:")
    ):
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
            tools = [t for t in res["tools"] if isinstance(t, dict)]
            next_cursor = res.get("nextCursor")
            if not isinstance(next_cursor, str) or not next_cursor:
                next_cursor = None
            return tools, next_cursor
    return [], None


def extract_tools_from_rpc_body(raw_body: str, content_type: str = "") -> List[Dict[str, Any]]:
    """Extracts `result.tools` from either standard JSON or `text/event-stream` SSE MCP responses."""
    tools, _ = extract_tools_page_from_rpc_body(raw_body, content_type)
    return tools


def _http_post_jsonrpc(
    url: str,
    payload: Dict[str, Any],
    headers: Dict[str, str],
    timeout: float,
) -> Tuple[str, str, Dict[str, str]]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers=headers,
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(10 * 1024 * 1024).decode("utf-8", errors="replace")
        ctype = resp.headers.get("Content-Type", "")
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        return raw, ctype, resp_headers


def probe_http_mcp_tools(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 8.0,
) -> List[Dict[str, Any]]:
    """
    Queries a live HTTP / Streamable-HTTP MCP server for `tools/list`:
    1. Performs best-effort `initialize` handshake to acquire `Mcp-Session-Id` (for stateful Streamable HTTP servers).
    2. Sends `notifications/initialized` when a session was established.
    3. Traverses all `tools/list` pages via `nextCursor` (up to MAX_TOOL_LIST_PAGES).
    """
    base_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-03-26",
    }
    if headers:
        base_headers.update(headers)

    session_id: Optional[str] = None
    # Step 1: Best-effort MCP Streamable HTTP initialize handshake
    try:
        init_headers = {**base_headers, "Mcp-Method": "initialize"}
        _, _, init_resp_headers = _http_post_jsonrpc(
            url,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "piton-probe", "version": "1.0.0"},
                },
            },
            init_headers,
            timeout=timeout,
        )
        session_id = init_resp_headers.get("mcp-session-id")
    except Exception:
        # Stateless JSON-RPC servers that only implement tools/list are still supported.
        session_id = None

    if session_id:
        base_headers["Mcp-Session-Id"] = session_id
        try:
            _http_post_jsonrpc(
                url,
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {**base_headers, "Mcp-Method": "notifications/initialized"},
                timeout=timeout,
            )
        except Exception:
            pass

    # Step 2: Paginated tools/list traversal
    all_tools: List[Dict[str, Any]] = []
    seen_names = set()
    cursor: Optional[str] = None
    seen_cursors = set()

    for page_idx in range(MAX_TOOL_LIST_PAGES):
        params: Dict[str, Any] = {}
        if cursor is not None:
            params["cursor"] = cursor
        list_headers = {**base_headers, "Mcp-Method": "tools/list"}
        raw, ctype, _ = _http_post_jsonrpc(
            url,
            {
                "jsonrpc": "2.0",
                "id": 2 + page_idx,
                "method": "tools/list",
                "params": params,
            },
            list_headers,
            timeout=timeout,
        )
        page_tools, next_cursor = extract_tools_page_from_rpc_body(raw, ctype)
        for tool in page_tools:
            tname = str(tool.get("name") or "")
            if tname and tname in seen_names:
                continue
            if tname:
                seen_names.add(tname)
            all_tools.append(tool)
        if not next_cursor or next_cursor in seen_cursors:
            break
        seen_cursors.add(next_cursor)
        cursor = next_cursor

    return all_tools


def probe_stdio_mcp_tools(
    command: str,
    args: Optional[List[str]] = None,
    env: Optional[Dict[str, str]] = None,
    timeout: float = 8.0,
) -> List[Dict[str, Any]]:
    """
    Launches a local STDIO MCP server (no shell=True!), performs MCP `initialize` ->
    `notifications/initialized` -> paginated `tools/list`, enforces non-blocking read
    timeouts, and cleanly terminates the subprocess.
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

    line_queue: "queue.Queue[Optional[str]]" = queue.Queue()

    def _reader() -> None:
        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                line_queue.put(line)
        finally:
            line_queue.put(None)

    reader = threading.Thread(target=_reader, daemon=True)
    reader.start()

    def _read_response(expected_id: Any, deadline: float) -> Optional[Dict[str, Any]]:
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                return None
            try:
                raw = line_queue.get(timeout=remaining)
            except queue.Empty:
                return None
            if raw is None:
                return None
            raw = raw.strip()
            if not raw:
                continue
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            if isinstance(msg, dict) and msg.get("id") == expected_id:
                return msg

    try:
        deadline = time.time() + timeout

        # 1. MCP initialize
        init_msg = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "piton-probe", "version": "1.0.0"},
                },
            }
        )
        proc.stdin.write(init_msg + "\n")
        proc.stdin.flush()
        _read_response(1, deadline)

        # 2. MCP notifications/initialized
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        proc.stdin.flush()

        # 3. Paginated tools/list
        all_tools: List[Dict[str, Any]] = []
        seen_names = set()
        cursor: Optional[str] = None
        seen_cursors = set()

        for page_idx in range(MAX_TOOL_LIST_PAGES):
            req_id = 2 + page_idx
            params: Dict[str, Any] = {}
            if cursor is not None:
                params["cursor"] = cursor
            proc.stdin.write(
                json.dumps({"jsonrpc": "2.0", "id": req_id, "method": "tools/list", "params": params}) + "\n"
            )
            proc.stdin.flush()

            resp = _read_response(req_id, deadline)
            if not resp:
                break
            res = resp.get("result")
            if not isinstance(res, dict) or not isinstance(res.get("tools"), list):
                break
            for tool in res["tools"]:
                if not isinstance(tool, dict):
                    continue
                tname = str(tool.get("name") or "")
                if tname and tname in seen_names:
                    continue
                if tname:
                    seen_names.add(tname)
                all_tools.append(tool)
            next_cursor = res.get("nextCursor")
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen_cursors:
                break
            seen_cursors.add(next_cursor)
            cursor = next_cursor

        return all_tools
    finally:
        if proc.stdin:
            try:
                proc.stdin.close()
            except Exception:
                pass
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


def probe_configured_servers(
    config: AgentIaCConfig,
    timeout: float = 8.0,
) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, str]]:
    """Probes all HTTP and STDIO MCP servers declared in `piton.yaml`."""
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


def _canonical_rpc_id(rpc_id: Any) -> str:
    """Preserves type distinction between string '1' and integer 1 JSON-RPC IDs."""
    return f"{type(rpc_id).__name__}:{rpc_id}"


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
    - Preserves string/integer JSON-RPC IDs and forwards notifications cleanly.
    - Intercepts client->server `tools/call` and enforces `piton.yaml` parameter bounds
      (writing signed ledger records).
    - Intercepts server->client `tools/list` responses (including paginated pages) and enforces
      `piton.lock` split-hash pinning + Day-1 poisoning lint (blocking third-party rug pulls
      with JSON-RPC -32001).
    - Warns on `notifications/tools/list_changed` dynamic tool-mutation attempts.
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
    state_lock = threading.Lock()
    pending_list_ids: set[str] = set()

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
            if not isinstance(msg, dict):
                continue

            if msg.get("method") == "notifications/tools/list_changed":
                sys.stderr.write(
                    f"[piton-wrap] WARNING: server '{server_name}' emitted notifications/tools/list_changed; "
                    "subsequent tools/list responses will be verified against piton.lock.\n"
                )
                sys.stderr.flush()

            has_id = "id" in msg and msg.get("id") is not None
            id_key = _canonical_rpc_id(msg.get("id")) if has_id else ""
            is_list_resp = False
            if has_id:
                with state_lock:
                    if id_key in pending_list_ids:
                        pending_list_ids.discard(id_key)
                        is_list_resp = True

            if is_list_resp:
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
                                    "message": "Piton STDIO Lockfile Rug-Pull Blocked",
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
                write_client(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32600, "message": "Batch JSON-RPC not permitted"},
                    }
                )
                continue

            method = req.get("method")
            has_id = "id" in req and req.get("id") is not None
            req_id = req.get("id")

            # Forward JSON-RPC notifications (e.g. notifications/initialized) untouched
            if not has_id:
                proc.stdin.write(json.dumps(req) + "\n")
                proc.stdin.flush()
                continue

            if method == "tools/list":
                with state_lock:
                    pending_list_ids.add(_canonical_rpc_id(req_id))

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
                    obo_principal=os.getenv("PITON_LOCAL_PRINCIPAL", "user:local-dev"),
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
                        obo_principal=os.getenv("PITON_LOCAL_PRINCIPAL", "user:local-dev"),
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
                                "message": "Piton STDIO Policy Enforcement",
                                "data": ev.model_dump(mode="json"),
                            },
                        }
                    )
                    continue

            proc.stdin.write(json.dumps(req) + "\n")
            proc.stdin.flush()
    finally:
        if proc.stdin:
            try:
                proc.stdin.close()
            except Exception:
                pass
        reader_thread.join(timeout=2)
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
    return 0
