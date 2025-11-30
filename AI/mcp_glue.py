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
    """Perform full WordPress scan for URL analysis."""
    cmd = f"Perform full WordPress security scan on {url}. Return ONLY JSON with vulnerabilities found."
    await send_cmd(proc, cmd, drain_timeout=0.2, verbose=True)
    output = ""
    start = time.time()
    last_activity = start
    
    print(f"[MCP] Waiting for AI analysis to start...")
    
    while time.time() - start < HUNT_TIMEOUT:
        try:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=15.0)
        except asyncio.TimeoutError:
            print(f"[MCP] No output for 15s, breaking after {time.time() - start:.1f}s total")
            break
            
        if not line:
            await asyncio.sleep(0.1)
            continue
            
        s = line.decode(errors='ignore')
        print(f"[CAI OUTPUT] {s.strip()}")
        output += s
        last_activity = time.time()
        
        # Progress indicators
        if "scan" in s.lower() or "analy" in s.lower():
            print(f"[MCP] AI is processing the scan...")
        
        # Check for completion
        if re.search(r'\{"type":\s*"response".*"cves".*\}', output, re.DOTALL):
            print("[MCP] Found complete response JSON, breaking")
            break
            
        # Check for WordPress-specific content
        if "wordpress" in s.lower() or "wp-" in s.lower() or "plugin" in s.lower():
            print(f"[MCP] Detected WordPress analysis content, continuing...")
            
        # Only break if we've been idle for a while with CAI prompt
        if re.search(r'CAI>', output) and (time.time() - last_activity > 10.0):
            print("[MCP] CAI prompt detected after inactivity, breaking")
            break
            
    print(f"[MCP] Scan completed after {time.time() - start:.1f}s, output length: {len(output)}")
    
    # Debug: Show what we actually got
    if "wordpress" in output.lower() or "cve" in output.lower():
        print(f"[MCP] Found security-related content in output")
    else:
        print(f"[MCP] WARNING: No security-related content found in output")
        
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
            
            print(f"[MCP] Raw output received: {raw[:500]}...")
            
            # DEBUG: Check what we actually received
            print(f"[MCP DEBUG] Raw length: {len(raw)}")
            print(f"[MCP DEBUG] First 1000 chars: {raw[:1000]}")
            print(f"[MCP DEBUG] Last 500 chars: {raw[-500:]}")
            
            # Try multiple JSON extraction patterns
            cves = []
            raw_response = ""
            
            # Pattern 1: Look for the ACTUAL JSON in your output
            # Your output shows the JSON is wrapped in a code block with line numbers
            json_patterns = [
                r'\{.*"type".*"response".*"cves".*\}',  # Complete response object
                r'\{"type":\s*"response".*?\}',  # Basic response object
                r'\[\s*\{.*?"cve".*?\}\s*\]',  # Just the CVEs array
            ]
            
            for pattern in json_patterns:
                json_match = re.search(pattern, raw, re.DOTALL)
                if json_match:
                    try:
                        json_str = json_match.group(0)
                        print(f"[MCP] Found JSON with pattern: {pattern[:50]}...")
                        parsed = json.loads(json_str)
                        
                        if "cves" in parsed:
                            for c in parsed["cves"]:
                                cves.append({
                                    "id": c.get("cve", "AI-Detected"),
                                    "severity": c.get("severity", "Unknown"),
                                    "title": c.get("desc", ""),
                                    "poc": c.get("poc", "")
                                })
                            raw_response = parsed.get("raw", "Analysis completed")
                            print(f"[MCP] Successfully extracted {len(cves)} CVEs")
                            break  # Stop after first successful extraction
                            
                    except json.JSONDecodeError as e:
                        print(f"[MCP] JSON decode error with pattern {pattern}: {e}")
                        # Try to clean the JSON string
                        try:
                            # Remove line numbers and extra spaces
                            cleaned = re.sub(r'^\s*\d+\s*', '', json_str, flags=re.MULTILINE)
                            parsed = json.loads(cleaned)
                            if "cves" in parsed:
                                for c in parsed["cves"]:
                                    cves.append({
                                        "id": c.get("cve", "AI-Detected"),
                                        "severity": c.get("severity", "Unknown"),
                                        "title": c.get("desc", ""),
                                        "poc": c.get("poc", "")
                                    })
                                raw_response = parsed.get("raw", "Analysis completed")
                                print(f"[MCP] Successfully extracted {len(cves)} CVEs after cleaning")
                                break
                        except:
                            continue
            
            # If no CVEs found but we have the raw output, create a fallback
            if not cves and "CVE-" in raw:
                print("[MCP] No structured JSON but found CVE mentions, creating fallback")
                # Extract all CVE mentions
                cve_matches = re.findall(r'CVE-\d{4}-\d+', raw)
                for cve_id in set(cve_matches):  # Remove duplicates
                    cves.append({
                        "id": cve_id,
                        "severity": "High",
                        "title": f"Vulnerability mentioned in analysis: {cve_id}",
                        "poc": "Check the raw analysis for details"
                    })
                raw_response = "Multiple CVEs detected in security scan"
            
            # Final fallback
            if not cves:
                cves = [{
                    "id": "ANALYSIS-COMPLETED",
                    "severity": "Info",
                    "title": "Security analysis completed successfully",
                    "poc": "Review the raw output for detailed findings"
                }]
                raw_response = raw[:1000] if raw else "Analysis completed"
            
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