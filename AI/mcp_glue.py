#!/usr/bin/env python3
"""
Async MCP Glue — Fixed output capture for AI responses
"""

import asyncio
import json
import re
import os
import sys
import time
import websockets


def sanitize_raw_output(raw: str) -> str:
    """Clean common interactive/boxed prefixes so JSON can be extracted.

    Removes lines with box-drawing characters, leading '[CAI OUTPUT]' prefixes,
    line numbers, and stray vertical bars so patterns like JSON objects/arrays
    can be matched robustly.
    """
    if not raw:
        return raw

    # Remove ANSI escape sequences
    raw = re.sub(r"\x1B\[[0-9;]*[A-Za-z]", "", raw)

    # Remove boxed border lines (╭─, ╰─ etc.) and lines made only of box chars
    raw = "\n".join([ln for ln in raw.splitlines() if not re.match(r"^[\s╭╮╯╰─═]+$", ln)])

    # Remove leading '[CAI OUTPUT]' or similar prefixes up to the first '│' if present
    raw = re.sub(r"^\s*\[[^\]]+\]\s*│\s*", "", raw, flags=re.MULTILINE)

    # Remove leading numeric line markers like '   1 ' or ' 10 ' at line starts
    raw = re.sub(r"^\s*\d+\s+", "", raw, flags=re.MULTILINE)

    # Remove leftover vertical bars or gutters at line starts
    raw = re.sub(r"^\s*[│|>\|]+\s*", "", raw, flags=re.MULTILINE)

    # Trim excessive whitespace
    raw = raw.strip()
    return raw

# === CONFIG ===
CAI_BIN = os.path.expanduser("~/cai/cai_env/bin/cai")
AI_MODEL = "deepseek/deepseek-chat"
PORT = 9876
KALI_IP = "192.168.1.20"

# Timeouts
STARTUP_DRAIN_TIMEOUT = 30.0
AGENT_SWITCH_TIMEOUT = 30.0
HUNT_TIMEOUT = 1000.0

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
    """Switch to specified agent if not already active"""
    global current_agent
    
    if current_agent == agent_name:
        print(f"[MCP] Agent {agent_name} already active, skipping switch")
        return True
        
    print(f"[MCP] Switching to agent: {agent_name}")
    out, err = await send_cmd(proc, f"/agent {agent_name}", drain_timeout=AGENT_SWITCH_TIMEOUT, verbose=True)
    
    # Just accept whatever happens and update current agent
    current_agent = agent_name
    print(f"[MCP] Agent context set to: {agent_name}")
    return True

async def hunt_plugin(proc, slug, version):
    """Send hunt command to CAI and capture ALL output (non-blocking)."""
    cmd = f"Hunt CVEs for WordPress plugin {slug} version {version}. Return ONLY JSON array with keys: cve, severity, desc, poc."
    await send_cmd(proc, cmd, drain_timeout=0.2, verbose=True)  # prime
    output = ""
    # read for up to HUNT_TIMEOUT seconds
    start = time.time()
    while time.time() - start < HUNT_TIMEOUT:
        line = await proc.stdout.readline()
        if not line:
            await asyncio.sleep(0.05)
            continue
        s = line.decode(errors='ignore')
        print(f"[CAI OUTPUT] {s.strip()}")
        output += s
        # try to detect JSON array start
        if re.search(r'\[\s*{', output):
            # try to find end bracket for a JSON array
            if ']' in output:
                break
        # Also break on any JSON-like structure
        if re.search(r'\{"type":\s*"response"', output):
            break
    return output.strip()

async def scan_url(proc, url):
    """Perform full WordPress scan for URL analysis with COMPLETE output capture."""
    cmd = f"Perform full WordPress security scan on {url}. Return ONLY JSON with vulnerabilities found."
    await send_cmd(proc, cmd, drain_timeout=0.2, verbose=True)
    
    output = ""
    start = time.time()
    last_activity = start
    
    print(f"[MCP] Starting scan for {url}, waiting for AI analysis...")
    
    # Wait a moment for the AI to start processing
    await asyncio.sleep(2.0)
    
    # Use buffered reading to capture ALL output
    while time.time() - start < HUNT_TIMEOUT:
        try:
            # Read larger chunks to capture complete output
            chunk = await asyncio.wait_for(proc.stdout.read(8192), timeout=10.0)
            if chunk:
                decoded = chunk.decode(errors='ignore')
                output += decoded
                print(f"[CAI CHUNK] Received {len(decoded)} chars")
                last_activity = time.time()
                
                # Check for completion markers in the accumulated output
                if re.search(r'\{"type":\s*"response".*"cves".*\}', output, re.DOTALL):
                    print("[MCP] Found complete JSON response in output")
                    break
                    
                # Check for analysis completion
                if "Current:" in decoded and "Session:" in decoded and len(output) > 50000:
                    print("[MCP] Detected analysis completion with stats")
                    break
                    
                # Check for final CAI prompt with substantial content
                if "CAI>" in decoded and len(output) > 30000:
                    print("[MCP] CAI prompt detected with substantial output, breaking")
                    break
                    
            else:
                # No data available, check if we should continue waiting
                if time.time() - last_activity > 20.0:
                    print(f"[MCP] No activity for 20s, breaking after {time.time() - start:.1f}s")
                    break
                await asyncio.sleep(0.5)
                
        except asyncio.TimeoutError:
            # Check if we have enough output already
            if len(output) > 50000:
                print(f"[MCP] Timeout but have {len(output)} chars, breaking")
                break
            continue
        except Exception as e:
            print(f"[MCP] Error reading output: {e}")
            break
    
    print(f"[MCP] Scan completed after {time.time() - start:.1f}s, total output: {len(output)} chars")
    
    # Save debug output to file
    debug_file = f"/tmp/cai_scan_{int(time.time())}.txt"
    try:
        with open(debug_file, 'w') as f:
            f.write(output)
        print(f"[MCP] Full output saved to: {debug_file}")
    except Exception as e:
        print(f"[MCP] Could not save debug file: {e}")
    
    return output

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
            
            # Ensure we're using the correct model first
            await switch_model(CAI_PROC, AI_MODEL)
            
            # Determine which agent to use based on request type
            if "layer3" in rid or "plugin_cve_analysis" in analysis_type:
                # Layer3 request - use frontline_agent for CVE analysis
                await switch_agent(CAI_PROC, "frontline_agent")
                slug = (params.get("slug") or "").strip()
                version = (params.get("version") or "").strip()
                
                if not slug:
                    await ws.send(json.dumps({"type":"response","request_id":rid,"error":"missing slug"}))
                    continue
                    
                print(f"[MCP] Hunting plugin {slug} v{version} (rid={rid})")
                raw = await hunt_plugin(CAI_PROC, slug, version)
                
            elif "url" in rid or "full_wordpress_scan" in analysis_type:
                # URL analysis request - use wp_hunter_agent for full scans
                await switch_agent(CAI_PROC, "wp_hunter_agent")
                url = (params.get("url") or "").strip()
                
                if not url:
                    await ws.send(json.dumps({"type":"response","request_id":rid,"error":"missing url"}))
                    continue
                    
                print(f"[MCP] Scanning URL {url} (rid={rid})")
                raw = await scan_url(CAI_PROC, url)
                
            else:
                # Default to frontline_agent for unknown types
                await switch_agent(CAI_PROC, "frontline_agent")
                slug = (params.get("slug") or "").strip()
                version = (params.get("version") or "").strip()
                
                if slug:
                    print(f"[MCP] Default hunting plugin {slug} v{version} (rid={rid})")
                    raw = await hunt_plugin(CAI_PROC, slug, version)
                else:
                    await ws.send(json.dumps({"type":"response","request_id":rid,"error":"unknown request type"}))
                    continue
            
            print(f"[MCP] Raw output received: {len(raw)} total characters")
            
            # DEBUG: Check what we actually received
            if len(raw) > 1000:
                print(f"[MCP DEBUG] First 500 chars: {raw[:500]}")
                print(f"[MCP DEBUG] Last 500 chars: {raw[-500:]}")
            
            # Try multiple JSON extraction patterns — sanitize decorated output first
            cves = []
            raw_response = ""

            cleaned_raw = sanitize_raw_output(raw)
            if len(cleaned_raw) < len(raw):
                print(f"[MCP] Sanitized output length: {len(cleaned_raw)} (original {len(raw)})")

            # If the cleaned output starts with JSON object/array, try parsing directly
            json_found = False
            try:
                start_char = cleaned_raw.lstrip()[0] if cleaned_raw.lstrip() else ''
            except Exception:
                start_char = ''

            if start_char in ['{', '[']:
                try:
                    parsed_full = json.loads(cleaned_raw)
                    print("[MCP] Parsed full cleaned output as JSON")
                    if isinstance(parsed_full, dict) and "cves" in parsed_full:
                        for c in parsed_full["cves"]:
                            cves.append({
                                "id": c.get("cve", c.get("id", "AI-Detected")),
                                "severity": c.get("severity", "Unknown"),
                                "title": c.get("desc", c.get("title", "")),
                                "poc": c.get("poc", "")
                            })
                        raw_response = parsed_full.get("raw", "Analysis completed")
                        json_found = True
                    elif isinstance(parsed_full, list):
                        for c in parsed_full:
                            cves.append({
                                "id": c.get("cve", c.get("id", "AI-Detected")),
                                "severity": c.get("severity", "Unknown"),
                                "title": c.get("desc", c.get("title", "")),
                                "poc": c.get("poc", "")
                            })
                        json_found = True
                except json.JSONDecodeError:
                    # fall back to pattern search below
                    pass

            # Pattern search fallback: look for embedded JSON snippets inside cleaned_raw
            if not json_found:
                # Pattern 1: Look for the ACTUAL JSON in your output
                json_patterns = [
                    r'\{[^{}]*"type"[^{}]*"response"[^{}]*"cves"[^}]*\}',  # Compact response
                    r'\{"type":\s*"response".*?"cves".*?\}',  # Basic response with cves
                    r'\[\s*\{.*?"cve".*?\}\s*\]',  # Just the CVEs array
                ]

                for pattern in json_patterns:
                    json_match = re.search(pattern, cleaned_raw, re.DOTALL)
                    if json_match:
                        try:
                            json_str = json_match.group(0)
                            print(f"[MCP] Found JSON with pattern: {pattern[:50]}...")
                            # Normalize whitespace
                            cleaned = re.sub(r'\s+', ' ', json_str)
                            parsed = json.loads(cleaned)

                            if "cves" in parsed:
                                for c in parsed["cves"]:
                                    cves.append({
                                        "id": c.get("cve", c.get("id", "AI-Detected")),
                                        "severity": c.get("severity", "Unknown"),
                                        "title": c.get("desc", c.get("title", "")),
                                        "poc": c.get("poc", "")
                                    })
                                raw_response = parsed.get("raw", "Analysis completed")
                                print(f"[MCP] Successfully extracted {len(cves)} CVEs")
                                json_found = True
                                break

                        except json.JSONDecodeError as e:
                            print(f"[MCP] JSON decode error: {e}")
                            continue
            
            # If no structured JSON found, extract security findings from raw text
            if not json_found:
                print("[MCP] No structured JSON found, extracting from raw analysis...")
                
                # Extract WordPress findings
                if "wordpress" in raw.lower() or "wp-" in raw.lower():
                    # Extract version information
                    version_matches = re.findall(r'(?:wordpress|wp)[^0-9]*([0-9]+\.[0-9]+\.[0-9]+)', raw, re.IGNORECASE)
                    for version in set(version_matches):
                        cves.append({
                            "id": f"WP-{version}",
                            "severity": "High",
                            "title": f"WordPress {version} detected - check for version-specific vulnerabilities",
                            "poc": f"WordPress version {version} may contain known CVEs"
                        })
                
                # Extract theme information
                theme_matches = re.findall(r'theme[^:]*:[^0-9]*([0-9]+\.[0-9]+)', raw, re.IGNORECASE)
                for theme_ver in set(theme_matches):
                    cves.append({
                        "id": f"Theme-{theme_ver}",
                        "severity": "Medium", 
                        "title": f"Theme version {theme_ver} detected",
                        "poc": "Check theme for known vulnerabilities"
                    })
                
                # Extract CVE mentions
                cve_matches = re.findall(r'CVE-\d{4}-\d+', raw)
                for cve_id in set(cve_matches):
                    cves.append({
                        "id": cve_id,
                        "severity": "High",
                        "title": f"Vulnerability mentioned: {cve_id}",
                        "poc": "Refer to CVE database for details"
                    })
            
            # Final fallback if nothing found
            if not cves:
                cves = [{
                    "id": "SCAN-COMPLETED",
                    "severity": "Info",
                    "title": "Security scan completed",
                    "poc": "Review the detailed analysis output"
                }]
                raw_response = f"Scan completed. Found {len(raw)} characters of analysis data."
            
            response = {
                "type": "response",
                "request_id": rid,
                "cves": cves,
                "raw": raw_response,
                "source": "cai-pipe-async",
                "agent_used": current_agent,
                "model_used": current_model,
                "output_size": len(raw)
            }
            
            print(f"[MCP] FINAL - Sending response with {len(cves)} findings")
            print(f"[MCP] Response: {json.dumps(response, indent=2)}")
            
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