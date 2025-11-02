#!/usr/bin/env python3
"""
MCP Glue — v5
 - WebSocket request => immediate processing UID => background CAI hunt
 - Results saved to results/<uid>.json (client polls HTTP /result/<uid>)
 - Live passthrough of CAI stdout/stderr to console
 - Robust JSON extraction for boxed outputs and nested braces
"""

import asyncio
import json
import re
import os
import sys
import time
import uuid
from typing import Optional, Tuple, Any

import websockets
import aiofiles
from aiohttp import web

# === CONFIG ===
CAI_BIN = os.path.expanduser("~/cai/cai_env/bin/cai")   # path to cai binary
AI_MODEL = "deepseek/deepseek-chat"
WS_PORT = 9876         # WebSocket port (requests)
HTTP_PORT = WS_PORT + 1  # HTTP result polling port
HOST = "0.0.0.0"

# Timeouts
STARTUP_DRAIN_TIMEOUT = 5.0
AGENT_SWITCH_TIMEOUT = 3.0
HUNT_TIMEOUT = 300.0   # 5 minutes max runtime per hunt

# Results directory
RESULTS_DIR = "results"
os.makedirs(RESULTS_DIR, exist_ok=True)

# ---------------------------
# Robust JSON extraction helpers
# ---------------------------

def strip_box_and_numbers(text: str) -> str:
    """Remove leading box characters, vertical bars, and numeric prefixes from each line."""
    lines = text.splitlines()
    cleaned = []
    for ln in lines:
        # Remove common box-drawing and leading pipes/spaces
        ln = re.sub(r'^[\s\|\u2500-\u257f\u2502\u2500\u2514\u2510\u2518\u250c]*', '', ln)
        # Remove leading line numbers like " 12 " or "12   "
        ln = re.sub(r'^\s*\d+\s+', '', ln)
        # Remove caret 'CAI>' prefixes if present
        ln = re.sub(r'^\s*CAI>\s*', '', ln)
        cleaned.append(ln)
    return "\n".join(cleaned)

def find_matching_bracket(text: str, open_pos: int) -> int:
    """
    Given index of '[' or '{', find matching closing bracket index.
    Ignores brackets inside strings and handles escapes.
    Returns -1 if not found.
    """
    if open_pos < 0 or open_pos >= len(text):
        return -1
    open_ch = text[open_pos]
    close_ch = ']' if open_ch == '[' else '}'
    stack = []
    i = open_pos
    in_string = False
    esc = False
    while i < len(text):
        ch = text[i]
        if esc:
            esc = False
        elif ch == '\\':
            esc = True
        elif ch == '"':
            in_string = not in_string
        elif not in_string:
            if ch == open_ch:
                stack.append(ch)
            elif ch == close_ch:
                if not stack:
                    return -1
                stack.pop()
                if len(stack) == 0:
                    return i
        i += 1
    return -1

def extract_json_blocks_from_text(raw: str) -> Tuple[Optional[Any], str]:
    """
    Try to extract JSON (array or object) from raw CAI output.
    Returns (parsed_json_or_None, cleaned_text_used_for_parsing).
    """
    if not raw or raw.strip() == "":
        return None, ""

    cleaned = strip_box_and_numbers(raw)

    # Find first array or object and use bracket matching
    candidates = []
    arr_pos = cleaned.find('[')
    obj_pos = cleaned.find('{')

    if arr_pos != -1:
        arr_end = find_matching_bracket(cleaned, arr_pos)
        if arr_end != -1:
            candidates.append(cleaned[arr_pos:arr_end+1])
    if obj_pos != -1:
        obj_end = find_matching_bracket(cleaned, obj_pos)
        if obj_end != -1:
            candidates.append(cleaned[obj_pos:obj_end+1])

    # fallback regex extractions if bracket matching fails
    if not candidates:
        m = re.search(r'(\[\s*{.*?}\s*\])', cleaned, flags=re.DOTALL)
        if m:
            candidates.append(m.group(1))
        else:
            m2 = re.search(r'(\{(?:.|\n)*\})', cleaned, flags=re.DOTALL)
            if m2:
                candidates.append(m2.group(1))

    # Try parse each candidate
    for cand in candidates:
        cand_str = cand.strip()
        cand_str = cand_str.replace('\x1b', '')  # strip ESC starts if any
        cand_str = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', cand_str)
        # remove trailing commas before closing brackets
        cand_try = re.sub(r',(\s*[\]\}])', r'\1', cand_str)
        try:
            parsed = json.loads(cand_try)
            return parsed, cand_try
        except Exception:
            try:
                parsed = json.loads(cand_str)
                return parsed, cand_str
            except Exception:
                # try removing leading line numbers in candidate
                cand2 = re.sub(r'^\s*\d+\s+', '', cand_str, flags=re.M)
                try:
                    parsed = json.loads(cand2)
                    return parsed, cand2
                except Exception:
                    continue

    # final fallback: extract inner JSON objects and return list
    objs = re.findall(r'(\{(?:[^{}]|\n)*\})', cleaned, flags=re.DOTALL)
    parsed_objs = []
    for o in objs:
        try:
            parsed_objs.append(json.loads(o))
        except Exception:
            pass
    if parsed_objs:
        return parsed_objs, json.dumps(parsed_objs)

    return None, cleaned

# ---------------------------
# Async IO helpers
# ---------------------------
async def start_cai():
    if not os.path.isfile(CAI_BIN):
        raise RuntimeError(f"CAI binary not found at {CAI_BIN}")
    print(f"[MCP] Launching CAI (async) -> {CAI_BIN}")
    proc = await asyncio.create_subprocess_exec(
        CAI_BIN, "--model", AI_MODEL, "--json", "--no-interactive",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    return proc

async def drain_stream(reader: asyncio.StreamReader, timeout: float = 1.0) -> str:
    out = ""
    start = time.time()
    while time.time() - start < timeout:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=0.5)
        except asyncio.TimeoutError:
            break
        if not line:
            break
        out += line.decode(errors='ignore')
        if any(p in out for p in ["CAI>", "Bug Bounter", "JSON_MODE_READY"]):
            break
    return out

async def send_cmd(proc: asyncio.subprocess.Process, cmd: str, drain_timeout: float = 2.0):
    if proc.stdin is None:
        raise RuntimeError("CAI stdin is None")
    print(f"[MCP] -> CAI: {cmd.strip()}")
    proc.stdin.write((cmd + "\n").encode())
    await proc.stdin.drain()
    out = await drain_stream(proc.stdout, timeout=drain_timeout)
    return out, None

async def hunt_plugin(proc: asyncio.subprocess.Process, slug: str, version: str) -> str:
    """
    Send the hunt command to CAI, stream its stdout live and return the raw collected output.
    """
    cmd = (
        f"Hunt CVEs for WordPress plugin {slug} version {version}. "
        "Return ONLY JSON array with keys: cve, severity, desc, poc, bounty."
    )
    print(f"[MCP] Starting hunt (timeout={HUNT_TIMEOUT}s)...")
    await send_cmd(proc, cmd, drain_timeout=0.2)

    output = ""
    start = time.time()
    while time.time() - start < HUNT_TIMEOUT:
        line = await proc.stdout.readline()
        if not line:
            await asyncio.sleep(0.05)
            continue
        chunk = line.decode(errors='ignore')
        output += chunk
        # realtime passthrough to console
        sys.stdout.write(chunk)
        sys.stdout.flush()

        # quick check — if we can already extract JSON, break early
        if ('[' in output and ']' in output) or ('{' in output and '}' in output):
            parsed, cleaned = extract_json_blocks_from_text(output)
            if parsed is not None:
                return cleaned
    if time.time() - start >= HUNT_TIMEOUT:
        output += "\n[WARN] Timeout reached — no JSON from CAI."
    return output

async def stream_stderr(reader: asyncio.StreamReader):
    """Single continuous stderr reader to avoid concurrent-read issues."""
    while True:
        line = await reader.readline()
        if not line:
            await asyncio.sleep(0.05)
            continue
        sys.stdout.write(line.decode(errors='ignore'))
        sys.stdout.flush()

# ---------------------------
# Result save/load helpers
# ---------------------------
async def save_result_to_file(uid: str, data: dict) -> str:
    path = os.path.join(RESULTS_DIR, f"{uid}.json")
    async with aiofiles.open(path, "w") as f:
        await f.write(json.dumps(data, indent=2))
    return path

async def load_result_file(uid: str) -> Optional[str]:
    path = os.path.join(RESULTS_DIR, f"{uid}.json")
    if not os.path.exists(path):
        return None
    async with aiofiles.open(path, "r") as f:
        return await f.read()

# ---------------------------
# WebSocket handler (requests)
# ---------------------------
CAI_PROC: Optional[asyncio.subprocess.Process] = None

async def handle_ws(ws, path):
    client_ip = ws.remote_address[0]
    print(f"[MCP] WS Client connected: {client_ip}")
    try:
        async for msg in ws:
            try:
                data = json.loads(msg)
            except Exception:
                await ws.send(json.dumps({"type": "response", "error": "invalid json"}))
                continue

            if data.get("type") != "request":
                await ws.send(json.dumps({"type": "response", "error": "unsupported message type"}))
                continue

            rid = data.get("request_id", "1")
            params = data.get("params", {})
            slug = (params.get("slug") or "").strip()
            version = (params.get("version") or "").strip()
            if not slug or not version:
                await ws.send(json.dumps({"type": "response", "request_id": rid, "error": "missing slug/version"}))
                continue

            # create UID and immediately reply so client can poll
            uid = str(uuid.uuid4())
            await ws.send(json.dumps({
                "type": "response",
                "status": "processing",
                "uid": uid,
                "request_id": rid,
                "plugin": slug,
                "version": version
            }))

            # process in background
            async def do_hunt_and_save():
                try:
                    raw = await hunt_plugin(CAI_PROC, slug, version)
                    parsed_json, cleaned = extract_json_blocks_from_text(raw)
                    # normalize parsed_json to a list of CVE-like dicts
                    cves = []
                    if parsed_json is None:
                        cves = [{"id": "NO_JSON_FOUND", "title": raw[:1000]}]
                    else:
                        parsed_list = []
                        if isinstance(parsed_json, dict):
                            if "items" in parsed_json and isinstance(parsed_json["items"], list):
                                parsed_list = parsed_json["items"]
                            else:
                                parsed_list = [parsed_json]
                        elif isinstance(parsed_json, list):
                            parsed_list = parsed_json
                        else:
                            try:
                                parsed_list = list(parsed_json)
                            except Exception:
                                parsed_list = [parsed_json]

                        for e in parsed_list:
                            if not isinstance(e, dict):
                                continue
                            if "items" in e and isinstance(e["items"], list):
                                items = e["items"]
                            else:
                                items = [e]
                            for it in items:
                                if not isinstance(it, dict):
                                    continue
                                cve_id = it.get("cve")
                                if isinstance(cve_id, str) and cve_id.strip().upper() in ("N/A", "NA", "NONE", "UNKNOWN"):
                                    cve_id = None
                                cves.append({
                                    "id": cve_id or "CVE-UNKNOWN",
                                    "severity": it.get("severity", "Unknown"),
                                    "title": it.get("desc") or it.get("title") or "",
                                    "poc": it.get("poc", ""),
                                    "bounty": it.get("bounty", "Unknown")
                                })

                        if not cves:
                            cves = [{"id": "PARSE_EMPTY", "title": str(parsed_json)[:1000]}]

                    result_data = {
                        "uid": uid,
                        "request_id": rid,
                        "plugin": slug,
                        "version": version,
                        "cves": cves,
                        "raw": raw[:8000],
                        "timestamp": time.time(),
                        "source": "cai-pipe-async-v5"
                    }
                    await save_result_to_file(uid, result_data)
                    print(f"[MCP] Saved result for uid={uid}")
                except Exception as e:
                    # ensure we save a failure diagnostic so client won't wait forever
                    errdata = {
                        "uid": uid,
                        "request_id": rid,
                        "plugin": slug,
                        "version": version,
                        "error": str(e),
                        "raw_partial": "",
                        "timestamp": time.time(),
                        "source": "cai-pipe-async-v5"
                    }
                    await save_result_to_file(uid, errdata)
                    print(f"[MCP] Error during hunt for uid={uid}: {e}")

            asyncio.create_task(do_hunt_and_save())

    except websockets.ConnectionClosed:
        print(f"[MCP] WS Disconnected: {client_ip}")

# ---------------------------
# HTTP result polling endpoints
# ---------------------------
async def handle_result(request):
    uid = request.match_info.get("uid")
    if not uid:
        return web.Response(text=json.dumps({"status": "invalid"}), content_type="application/json")
    data = await load_result_file(uid)
    if data is None:
        return web.Response(text=json.dumps({"status": "pending"}), content_type="application/json")
    return web.Response(text=data, content_type="application/json")

async def start_http_server():
    app = web.Application()
    app.add_routes([web.get('/result/{uid}', handle_result)])
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, HOST, HTTP_PORT)
    await site.start()
    print(f"[MCP] Result HTTP server listening on http://{HOST}:{HTTP_PORT}/result/<uid>")

# ---------------------------
# Main startup
# ---------------------------
async def main():
    global CAI_PROC
    print("[MCP] Starting (async main)...")
    CAI_PROC = await start_cai()

    # single dedicated stderr reader
    asyncio.create_task(stream_stderr(CAI_PROC.stderr))

    # drain initial stdout to get prompt/banner
    stdout_init = await drain_stream(CAI_PROC.stdout, timeout=STARTUP_DRAIN_TIMEOUT)
    if stdout_init:
        print("[MCP][CAI startup]:", stdout_init.strip()[:400])

    # ensure model + agent selected
    await send_cmd(CAI_PROC, f"/model {AI_MODEL}", drain_timeout=4.0)
    await send_cmd(CAI_PROC, "/agent bug_bounter_agent", drain_timeout=AGENT_SWITCH_TIMEOUT)

    # best-effort JSON mode check
    out, _ = await send_cmd(CAI_PROC, "echo JSON_MODE_READY", drain_timeout=1.0)
    if "JSON_MODE_READY" in out:
        print("[MCP] JSON MODE CONFIRMED")
    else:
        print("[MCP] JSON MODE not confirmed (continuing)")

    # start HTTP result server
    await start_http_server()

    # start WebSocket server
    ws_server = await websockets.serve(handle_ws, HOST, WS_PORT)
    print(f"[MCP] WebSocket server listening on ws://{HOST}:{WS_PORT}")

    # run forever
    await ws_server.wait_closed()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[MCP] Shutting down...")
        if CAI_PROC:
            try:
                CAI_PROC.terminate()
            except Exception:
                pass
