#!/usr/bin/env python3
"""
Async MCP Glue — safer non-blocking subprocess + websockets
"""

import asyncio
import json
import re
import os
import sys
import time
import websockets

# === CONFIG ===
CAI_BIN = os.path.expanduser("~/cai/cai_env/bin/cai")
AI_MODEL = "deepseek/deepseek-chat"
PORT = 9876
KALI_IP = "192.168.1.20"

# Timeouts
STARTUP_DRAIN_TIMEOUT = 30.0
AGENT_SWITCH_TIMEOUT = 30.0
HUNT_TIMEOUT = 1000.0

async def start_cai():
    if not os.path.isfile(CAI_BIN):
        raise RuntimeError(f"CAI binary not found at {CAI_BIN}")
    print("[MCP] Launching CAI (async)...")
    proc = await asyncio.create_subprocess_exec(
        CAI_BIN, "--model", AI_MODEL, "--json", "--no-interactive",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    return proc

async def drain_stream(reader: asyncio.StreamReader, timeout=1.0):
    """Read available lines for up to `timeout` seconds, return concat'd output."""
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
        # optional break if prompt seen
        if "CAI>" in out or "Bug Bounter" in out or "JSON_MODE_READY" in out:
            break
    return out

async def send_cmd(proc, cmd, drain_timeout=2.0):
    """Send a line to CAI and drain stdout for a bit"""
    if proc.stdin is None:
        raise RuntimeError("CAI stdin is None")
    print(f"[MCP] -> CAI: {cmd.strip()}")
    proc.stdin.write((cmd + "\n").encode())
    await proc.stdin.drain()
    out = await drain_stream(proc.stdout, timeout=drain_timeout)
    err = await drain_stream(proc.stderr, timeout=0.2)
    return out, err

async def hunt_plugin(proc, slug, version):
    """Send hunt command to CAI and capture JSON-like output (non-blocking)."""
    cmd = f"Hunt CVEs for WordPress plugin {slug} version {version}. Return ONLY JSON array with keys: cve, severity, desc, poc, bounty."
    await send_cmd(proc, cmd, drain_timeout=0.2)  # prime
    output = ""
    # read for up to HUNT_TIMEOUT seconds
    start = time.time()
    while time.time() - start < HUNT_TIMEOUT:
        line = await proc.stdout.readline()
        if not line:
            await asyncio.sleep(0.05)
            continue
        s = line.decode(errors='ignore')
        output += s
        # try to detect JSON array start
        if re.search(r'\[\s*{', output):
            # try to find end bracket for a JSON array
            if ']' in output:
                break
    return output.strip()

# global to hold proc for handler
CAI_PROC = None

async def handle_ws(ws, path):
    client_ip = ws.remote_address[0]
    print(f"[MCP] Client connected: {client_ip}")
    try:
        async for message in ws:
            try:
                msg = json.loads(message)
            except Exception:
                await ws.send(json.dumps({"type":"response","error":"invalid json"}))
                continue
            if msg.get("type") != "request":
                await ws.send(json.dumps({"type":"response","error":"unsupported message type"}))
                continue
            rid = msg.get("request_id","1")
            params = msg.get("params",{})
            slug = (params.get("slug") or "").strip()
            version = (params.get("version") or "").strip()
            if not slug or not version:
                await ws.send(json.dumps({"type":"response","request_id":rid,"error":"missing slug/version"}))
                continue
            print(f"[MCP] Hunting {slug} v{version} (rid={rid})")
            raw = await hunt_plugin(CAI_PROC, slug, version)
            # extract JSON array
            jmatch = re.search(r'(\[\s*{.*?\}\s*\])', raw, re.DOTALL)
            cves = []
            if jmatch:
                try:
                    parsed = json.loads(jmatch.group(1))
                    for c in parsed:
                        cves.append({
                            "id": c.get("cve","CVE-UNKNOWN"),
                            "severity": c.get("severity","Unknown"),
                            "title": c.get("desc",""),
                            "poc": c.get("poc",""),
                            "bounty": c.get("bounty","Unknown"),
                        })
                except Exception as e:
                    cves = [{"id":"JSON_PARSE_ERR","title":str(e),"raw": raw[:300]}]
            else:
                cves = [{"id":"NO_JSON","title":raw[:400]}]
            response = {"type":"response","request_id":rid,"plugin":slug,"version":version,"cves":cves,"source":"cai-pipe-async"}
            await ws.send(json.dumps(response))
    except websockets.ConnectionClosed:
        print(f"[MCP] Disconnected: {client_ip}")

async def main():
    global CAI_PROC
    print("[MCP] Starting (async main)...")
    CAI_PROC = await start_cai()
    # drain initial output
    stdout_init = await drain_stream(CAI_PROC.stdout, timeout=STARTUP_DRAIN_TIMEOUT)
    stderr_init = await drain_stream(CAI_PROC.stderr, timeout=0.5)
    if stderr_init:
        print("[MCP][CAI stderr initial]:", stderr_init.strip()[:200])

    # switch agent
    out, err = await send_cmd(CAI_PROC, "/agent wp_hunter_agent", drain_timeout=AGENT_SWITCH_TIMEOUT)
    print("[MCP] Agent switch output (truncated):", out.strip()[:200])

    # send small check
    out, err = await send_cmd(CAI_PROC, "echo JSON_MODE_READY", drain_timeout=1.0)
    if "JSON_MODE_READY" in out:
        print("[MCP] JSON MODE CONFIRMED")
    else:
        print("[MCP] JSON MODE not confirmed (continuing)")

    # start websocket server
    server = await websockets.serve(handle_ws, "0.0.0.0", PORT)
    print(f"[MCP] WebSocket server listening on 0.0.0.0:{PORT}")
    print(f"[MCP] Connect: ws://{KALI_IP}:{PORT}")
    await server.wait_closed()  # run forever

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[MCP] Shutting down...")
        if CAI_PROC:
            CAI_PROC.terminate()
