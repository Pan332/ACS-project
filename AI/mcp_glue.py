#!/usr/bin/env python3
"""
Async MCP Glue — with forced model switching to deepseek
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
HUNT_TIMEOUT = 300.0  # Reduced from 1000 to 300 seconds

# Track current agent to avoid unnecessary switches
current_agent = None
current_model = None

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

async def drain_stream(reader: asyncio.StreamReader, timeout=1.0, verbose=True):
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
        decoded = line.decode(errors='ignore')
        out += decoded
        if verbose:
            print(f"[CAI STDOUT] {decoded.strip()}")
        # optional break if prompt seen
        if "CAI>" in out or "Bug Bounter" in out or "JSON_MODE_READY" in out:
            break
    return out

async def send_cmd(proc, cmd, drain_timeout=2.0, verbose=True):
    """Send a line to CAI and drain stdout for a bit"""
    if proc.stdin is None:
        raise RuntimeError("CAI stdin is None")
    print(f"[MCP] -> CAI: {cmd.strip()}")
    proc.stdin.write((cmd + "\n").encode())
    await proc.stdin.drain()
    out = await drain_stream(proc.stdout, timeout=drain_timeout, verbose=verbose)
    err = await drain_stream(proc.stderr, timeout=0.2, verbose=verbose)
    return out, err

async def switch_model(proc, model_name):
    """Switch to specified model"""
    global current_model

    if current_model == model_name:
        print(f"[MCP] Model {model_name} already active, skipping switch")
        return True

    print(f"[MCP] Switching to model: {model_name}")
    out, err = await send_cmd(proc, f"/model {model_name}", drain_timeout=AGENT_SWITCH_TIMEOUT, verbose=True)

    current_model = model_name
    print(f"[MCP] Model context set to: {model_name}")
    return True

async def switch_agent(proc, agent_name):
    """Switch to specified agent with proper output handling"""
    global current_agent

    if current_agent == agent_name:
        print(f"[MCP] Agent {agent_name} already active, skipping switch")
        return True

    print(f"[MCP] Switching to agent: {agent_name}")

    # Clear any existing output
    try:
        await drain_stream(proc.stdout, timeout=0.5, verbose=False)
    except:
        pass

    # Send the switch command
    if proc.stdin:
        proc.stdin.write(f"/agent {agent_name}\n".encode())
        await proc.stdin.drain()

    # Wait and read the response properly
    output = ""
    start_time = time.time()
    while time.time() - start_time < AGENT_SWITCH_TIMEOUT:
        try:
            chunk = await asyncio.wait_for(proc.stdout.read(1024), timeout=1.0)
            if chunk:
                decoded = chunk.decode('utf-8', errors='ignore')
                output += decoded
                print(f"[AGENT SWITCH] {decoded.strip()}")

                # Check for success indicators
                if "Switched to agent" in output or agent_name in output:
                    current_agent = agent_name
                    print(f"[MCP] Agent switch successful: {agent_name}")
                    return True
                # Check for failure
                if "not found" in output or "error" in output.lower():
                    print(f"[MCP] Agent switch failed: {output}")
                    return False
            else:
                await asyncio.sleep(0.1)
        except asyncio.TimeoutError:
            # If we have output and it's been a while, check if switch worked
            if output and len(output) > 50:
                current_agent = agent_name
                print(f"[MCP] Agent switch assumed successful: {agent_name}")
                return True
            continue

    # Timeout - assume it worked
    current_agent = agent_name
    print(f"[MCP] Agent switch timeout, assuming: {agent_name}")
    return True

async def execute_cai_command(proc, command):
    """
    Execute a CAI command. `command` can be:
      - dict  -> will be serialized to JSON and sent as structured command
      - str   -> will be sent as a natural-language line (backwards compatibility)
    Returns the raw captured output from CAI.
    """
    # Clear any buffered output first
    try:
        while True:
            await asyncio.wait_for(proc.stdout.read(1024), timeout=0.05)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        pass

    # If command is a dict, send structured JSON (this is what interactive CAI expects)
    if isinstance(command, dict):
        payload = json.dumps(command, ensure_ascii=False)
        to_send = payload + "\n"
        print(f"[MCP] Sending structured JSON to CAI: {payload}")
    else:
        to_send = str(command) + "\n"
        print(f"[MCP] Sending NL command to CAI: {command}")

    if proc.stdin:
        proc.stdin.write(to_send.encode())
        await proc.stdin.drain()

    output = ""
    start_time = time.time()
    response_complete = False
    lines_since_last_output = 0

    # More robust output monitoring
    while time.time() - start_time < HUNT_TIMEOUT and not response_complete:
        try:
            chunk = await asyncio.wait_for(proc.stdout.read(4096), timeout=2.0)
            if chunk:
                decoded = chunk.decode('utf-8', errors='ignore')
                output += decoded
                print(f"[CAI OUTPUT CHUNK] {decoded.strip()}")

                # Reset counter when we get output
                lines_since_last_output = 0

                # Look for completion patterns in the actual CAI output format
                completion_indicators = [
                    '"type": "response"',   # direct JSON response
                    'Current: I:',          # Cost/usage info
                    'Session: $',           # Session info
                    'Context:',             # Context usage
                    'CAI>',                 # Prompt ready
                    '╰─',                   # Box footer characters
                    'Total: I:',            # Total usage
                ]

                if any(indicator in decoded for indicator in completion_indicators):
                    # small delay to capture trailing fragments
                    await asyncio.sleep(1.0)
                    # If we've seen a JSON response, we can stop sooner
                    if '"type": "response"' in output or '"cves":' in output:
                        response_complete = True
                        break
                    # otherwise allow the loop to continue a bit more
            else:
                lines_since_last_output += 1
                if lines_since_last_output > 10 and len(output) > 100:
                    response_complete = True
                    break
                await asyncio.sleep(0.1)

        except asyncio.TimeoutError:
            lines_since_last_output += 1
            if lines_since_last_output > 5 and len(output) > 500:
                response_complete = True
                break
            continue

    print(f"[MCP] Command execution completed, output length: {len(output)}")
    return output

def extract_cves_from_output(raw):
    """Extract CVEs from CAI output using multiple strategies"""
    cves = []
    raw_response = ""

    # Strategy 1: Look for the complete JSON response object with "type":"response"
    json_pattern = r'\{\s*"type"\s*:\s*"response".*?"cves"\s*:\s*\[.*?\].*?\}'
    match = re.search(json_pattern, raw, re.DOTALL | re.IGNORECASE)

    if match:
        try:
            json_str = match.group(0)
            # Clean undesirable characters
            json_str = re.sub(r'[^\x09\x0A\x0D\x20-\x7E]', '', json_str)
            parsed = json.loads(json_str)
            if "cves" in parsed and isinstance(parsed["cves"], list):
                for cve in parsed["cves"]:
                    cves.append({
                        "id": cve.get("cve") or cve.get("id") or cve.get("CVE") or "AI-Detected",
                        "severity": cve.get("severity", "Unknown"),
                        "title": cve.get("desc") or cve.get("title", ""),
                        "poc": cve.get("poc", "")
                    })
                raw_response = parsed.get("raw", "Analysis completed")
                print(f"[MCP] Extracted {len(cves)} CVEs from JSON response")
                return cves, raw_response
        except json.JSONDecodeError as e:
            print(f"[MCP] JSON decode failed: {e}")

    # Strategy 2: Find CVE strings in the free text
    cve_pattern = r'CVE-\d{4}-\d+'
    found_cves = re.findall(cve_pattern, raw)
    if found_cves:
        for cve_id in set(found_cves):
            severity = "Medium"
            desc = f"Vulnerability found: {cve_id}"
            severity_match = re.search(rf'{re.escape(cve_id)}.*?(High|Medium|Low|Critical)', raw, re.IGNORECASE)
            if severity_match:
                severity = severity_match.group(1)
            cves.append({
                "id": cve_id,
                "severity": severity,
                "title": desc,
                "poc": "Check raw output for details"
            })
        raw_response = "Multiple CVEs detected in security analysis"
        print(f"[MCP] Extracted {len(cves)} CVEs from text analysis")
        return cves, raw_response

    # Strategy 3: No CVEs found
    # === MEANING B: REMOVE the fake NO-CVES-FOUND result ===
    # Return an empty list instead of a synthetic CVE object.
    print("[MCP] No CVEs found in analysis")
    return [], "Security analysis completed"

async def scan_url(proc, url):
    """Perform full WordPress scan for URL analysis using structured JSON command."""
    command_data = {
        "url": url,
        "analysis_type": "full_wordpress_scan"
    }
    return await execute_cai_command(proc, command_data)

# global to hold proc for handler
CAI_PROC = None

async def handle_ws(ws, path):
    client_ip = ws.remote_address[0]
    print(f"[MCP] Client connected: {client_ip}")
    try:
        async for message in ws:
            try:
                msg = json.loads(message)
                print(f"[MCP] Received: {msg}")
            except Exception as e:
                print(f"[MCP] JSON parse error: {e}")
                await ws.send(json.dumps({"type":"response","error":"invalid json"}))
                continue

            if msg.get("type") != "request":
                await ws.send(json.dumps({"type":"response","error":"unsupported message type"}))
                continue

            rid = msg.get("request_id","1")
            params = msg.get("params",{})
            analysis_type = params.get("analysis_type", "")

            print(f"[MCP] Processing request {rid}, analysis_type: {analysis_type}")

            # Ensure correct model
            await switch_model(CAI_PROC, AI_MODEL)

            raw = ""
            # Determine which agent to use based on request type
            if "layer3" in rid or "plugin_cve_analysis" in analysis_type:
                await switch_agent(CAI_PROC, "frontline_agent")
                slug = (params.get("slug") or "").strip()
                version = (params.get("version") or "").strip()

                if not slug:
                    await ws.send(json.dumps({"type":"response","request_id":rid,"error":"missing slug"}))
                    continue

                print(f"[MCP] Hunting plugin {slug} v{version} (rid={rid})")

                command_data = {
                    "slug": slug,
                    "version": version,
                    "analysis_type": "plugin_cve_analysis"
                }

                raw = await execute_cai_command(CAI_PROC, command_data)

            elif "url" in rid or "full_wordpress_scan" in analysis_type:
                await switch_agent(CAI_PROC, "wp_hunter_agent")
                url = (params.get("url") or "").strip()

                if not url:
                    await ws.send(json.dumps({"type":"response","request_id":rid,"error":"missing url"}))
                    continue

                print(f"[MCP] Scanning URL {url} (rid={rid})")
                raw = await scan_url(CAI_PROC, url)

            else:
                await switch_agent(CAI_PROC, "frontline_agent")
                slug = (params.get("slug") or "").strip()
                version = (params.get("version") or "").strip()

                if slug:
                    print(f"[MCP] Default hunting plugin {slug} v{version} (rid={rid})")
                    command_data = {
                        "slug": slug,
                        "version": version,
                        "analysis_type": "plugin_cve_analysis"
                    }
                    raw = await execute_cai_command(CAI_PROC, command_data)
                else:
                    await ws.send(json.dumps({"type":"response","request_id":rid,"error":"unknown request type"}))
                    continue

            print(f"[MCP] Raw output received: {raw[:500]}...")

            # DEBUG: lengths and samples
            print(f"[MCP DEBUG] Raw length: {len(raw)}")
            if len(raw) > 1000:
                print(f"[MCP DEBUG] First 1000 chars: {raw[:1000]}")
                print(f"[MCP DEBUG] Last 500 chars: {raw[-500:]}")
            else:
                print(f"[MCP DEBUG] Full output: {raw}")

            cves, raw_response = extract_cves_from_output(raw)

            response = {
                "type": "response",
                "request_id": rid,
                "cves": cves,
                "raw": raw_response,
                "source": "cai-pipe-async",
                "agent_used": current_agent,
                "model_used": current_model
            }

            print(f"[MCP] FINAL - Sending response with {len(cves)} CVEs")
            print(f"[MCP] Response preview: {json.dumps(response)[:200]}...")

            try:
                await ws.send(json.dumps(response))
                print(f"[MCP] ✅ SUCCESS: Response sent for request {rid}")
            except Exception as e:
                print(f"[MCP] ❌ ERROR sending response: {e}")

    except websockets.ConnectionClosed:
        print(f"[MCP] Disconnected: {client_ip}")
    except Exception as e:
        print(f"[MCP] Handler error: {e}")

async def main():
    global CAI_PROC
    print("[MCP] Starting (async main)...")
    CAI_PROC = await start_cai()

    # drain initial output with verbose logging
    print("[MCP] Draining initial output...")
    stdout_init = await drain_stream(CAI_PROC.stdout, timeout=STARTUP_DRAIN_TIMEOUT, verbose=True)
    stderr_init = await drain_stream(CAI_PROC.stderr, timeout=0.5, verbose=True)

    # Force model switch to deepseek first
    await switch_model(CAI_PROC, AI_MODEL)

    # Start with frontline_agent as default
    await switch_agent(CAI_PROC, "frontline_agent")

    # send small check
    print("[MCP] Sending readiness check...")
    out, err = await send_cmd(CAI_PROC, "echo JSON_MODE_READY", drain_timeout=1.0, verbose=True)

    # start websocket server
    server = await websockets.serve(handle_ws, "0.0.0.0", PORT)
    print(f"[MCP] WebSocket server listening on 0.0.0.0:{PORT}")
    print(f"[MCP] Connect: ws://{KALI_IP}:{PORT}")
    print(f"[MCP] Ready for requests...")
    await server.wait_closed()  # run forever

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[MCP] Shutting down...")
        if CAI_PROC:
            CAI_PROC.terminate()
