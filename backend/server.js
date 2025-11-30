import crypto from "crypto";
import fetch from "node-fetch";
import express from "express";
import cors from "cors";
import { spawn, exec } from "child_process";
import WebSocket from "ws";
import http from "http";
import fs from "fs";
import path from "path";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 4000;
const AI_WS_URL = "ws://192.168.40.130:9876";
const SCAN_DIR = path.join(process.cwd(), "scans");

if (!fs.existsSync(SCAN_DIR)) fs.mkdirSync(SCAN_DIR);

/* ============================================================
   SHARED FUNCTIONS
============================================================ */

const extractJSON = (raw) => {
  console.log("[DEBUG] Raw output length:", raw.length);
  
  // First, try to find the main JSON object by looking for the start and end
  const jsonStart = raw.indexOf('{');
  const jsonEnd = raw.lastIndexOf('}');
  
  if (jsonStart === -1 || jsonEnd === -1) {
    console.log("[DEBUG] No JSON structure found");
    return null;
  }
  
  const jsonString = raw.substring(jsonStart, jsonEnd + 1);
  console.log("[DEBUG] Extracted JSON length:", jsonString.length);
  
  try {
    const parsed = JSON.parse(jsonString);
    console.log("[DEBUG] Successfully parsed JSON");
    console.log("[DEBUG] JSON keys:", Object.keys(parsed));
    return parsed;
  } catch (e) {
    console.log("[DEBUG] JSON parse error:", e.message);
    
    // Alternative approach: look for specific WPScan patterns
    const patterns = [
      /"plugins":\s*\{[^}]*\}/,
      /"version":\s*\{[^}]*\}/
    ];
    
    for (const pattern of patterns) {
      const match = raw.match(pattern);
      if (match) {
        console.log("[DEBUG] Found pattern match");
        // If we find plugin data, construct a minimal valid JSON
        try {
          return {
            plugins: {},
            version: null,
            ...JSON.parse(`{${match[0]}}`)
          };
        } catch (parseError) {
          continue;
        }
      }
    }
    
    return null;
  }
};

const checkDocker = () => {
  return new Promise((resolve) => {
    exec("docker --version", (error) => resolve(!error));
  });
};

const detectVersionFromUrl = async (targetUrl, slug) => {
  try {
    const readmeUrl = `${targetUrl}/wp-content/plugins/${slug}/readme.txt`;
    const response = await fetch(readmeUrl);
    if (!response.ok) return null;
    
    const text = await response.text();
    const m = text.match(/Stable tag:\s*([0-9.]+)/i);
    if (m) return m[1];
    
    const hash = crypto.createHash("sha256").update(text).digest("hex");
    const HASH_DB = {
      "45f9f9c04d0b5f7950a0ee30b7d2608d182cbfcb20b7cc15448a8fa2f1187773": "5.1"
    };
    return HASH_DB[hash] || "Unknown";
  } catch {
    return "Unknown";
  }
};

/* ============================================================
   DUAL JSON FORMAT SUPPORT
============================================================ */

// Free Mode Response Format (Original)
const generateFreeModeResponse = (results, url, apiMode) => {
  return {
    ok: true,
    plugins: results.plugins || [],
    wordpress: results.wordpress || { detected: false },
    api_mode: apiMode,
    scan_info: {
      plugins_found: results.plugins?.length || 0,
      wordpress_detected: results.wordpress?.detected || false
    }
  };
};

// Premium Mode Response Format (New Enhanced Format)
const generatePremiumModeResponse = (results, url, apiKey) => {
  const vulnerablePlugins = results.plugins?.filter(p => 
    p.native_wpscan_vulns?.length > 0 || 
    p.custom_analysis?.hit === true
  ) || [];

  const cleanPlugins = results.plugins?.filter(p => 
    !p.native_wpscan_vulns?.length && 
    p.custom_analysis?.hit !== true
  ) || [];

  // Frontend-compatible plugins array
  const pluginsArray = results.plugins?.map(plugin => ({
    slug: plugin.slug,
    version: plugin.version,
    confidence: plugin.confidence,
    source: plugin.source,
    vulnerable: plugin.native_wpscan_vulns?.length > 0 || plugin.custom_analysis?.hit === true
  })) || [];

  const detailedResponse = {
    ok: true,  // Frontend compatibility
    status: "success",
    scan_id: `premium_scan_${Date.now()}`,
    target: url,
    timestamp: new Date().toISOString(),
    mode: "premium",
    
    plugins: pluginsArray,  // Frontend compatibility
    
    summary: {
      total_plugins_scanned: results.plugins?.length || 0,
      vulnerable_plugins: vulnerablePlugins.length,
      clean_plugins: cleanPlugins.length,
      wordpress_vulnerabilities: results.wordpress?.vulnerabilities?.length || 0,
      risk_level: vulnerablePlugins.length > 0 ? "HIGH" : "LOW",
      scan_duration: "N/A"
    },

    vulnerabilities: vulnerablePlugins.map(plugin => ({
      plugin: plugin.slug,
      version: plugin.version,
      confidence: plugin.confidence,
      risk_score: calculateRiskScore(plugin),
      findings: [
        ...(plugin.native_wpscan_vulns || []).map(vuln => ({
          source: "WPScan Database",
          type: "vulnerability",
          cve: vuln.id || "Unknown",
          severity: vuln.severity || "High",
          title: vuln.title || "Unknown vulnerability",
          fixed_in: vuln.fixed_in || "Unknown",
          references: vuln.references || []
        })),
        ...(plugin.custom_analysis?.hit ? [{
          source: plugin.custom_analysis.source,
          type: "custom_analysis",
          cve: plugin.custom_analysis.cve || "AI-Detected",
          severity: plugin.custom_analysis.severity || "High",
          title: plugin.custom_analysis.description || "Potential vulnerability detected",
          layer: plugin.custom_analysis.layer
        }] : [])
      ]
    })),

    wordpress_core: results.wordpress ? {
      version: results.wordpress.version,
      status: results.wordpress.status,
      vulnerabilities: results.wordpress.vulnerabilities?.map(vuln => ({
        cve: vuln.id,
        severity: vuln.severity,
        title: vuln.title,
        fixed_in: vuln.fixed_in,
        references: vuln.references
      })) || []
    } : null,

    clean_plugins: cleanPlugins.map(plugin => ({
      plugin: plugin.slug,
      version: plugin.version,
      confidence: plugin.confidence,
      status: "clean"
    })),

    metadata: {
      api_used: "VMScan Premium",
      detection_method: "Aggressive Enumeration",
      layers_applied: ["WPScan DB", "Local Rules", "External APIs", "AI Analysis"],
      timestamp: new Date().toISOString()
    }
  };

  return detailedResponse;
};

// Helper function to calculate risk score
const calculateRiskScore = (plugin) => {
  let score = 0;
  
  if (plugin.native_wpscan_vulns?.length > 0) {
    score += plugin.native_wpscan_vulns.length * 25;
    
    const highSeverityCount = plugin.native_wpscan_vulns.filter(v => 
      v.severity?.toLowerCase() === 'high'
    ).length;
    score += highSeverityCount * 15;
  }
  
  if (plugin.custom_analysis?.hit) {
    score += 30;
    if (plugin.custom_analysis.severity?.toLowerCase().includes('high')) {
      score += 20;
    }
  }
  
  return Math.min(score, 100);
};

// --- CORE LOGIC: Multi-Layer Analysis with Verbose Logging ---
const analyzePluginRisk = async (slug, version) => {
  if (!version || version === "Unknown") {
    console.log(`   [Skip] ${slug} - No version detected`);
    return { slug, version, risk: "Unknown Version", source: "Skipped" };
  }

  const versionClean = version.trim();
  console.log(`   [Analyze] checking ${slug} v${versionClean} across 3 Layers...`);

  // LAYER 1: Local Database
  const localRules = {
    "social-warfare": { "3.5.2": { cve: "CVE-2019-9978", severity: "High (RCE)" } },
    "wp-time-capsule": { "1.21.15": { cve: "CVE-2020-8772", severity: "Critical" } },
    "contact-form-7": { "5.1": { cve: "CVE-2020-35489", severity: "High" } },
    "akismet": { "4.1.0": { cve: "CVE-2021-24276", severity: "Medium" } },
  };

  if (localRules[slug] && localRules[slug][versionClean]) {
    console.log(`   ✅ [Layer 1] HIT! Found in Local DB`);
    return { 
      hit: true, 
      source: "Layer 1 (Local)", 
      ...localRules[slug][versionClean] 
    };
  } else {
    console.log(`   ❌ [Layer 1] Miss`);
  }

  // LAYER 2: External APIs
  try {
    const apiSources = [
      `https://cve.circl.lu/api/vulnerability/browse/${slug}`
    ];

    for (const endpoint of apiSources) {
       console.log(`   ⏳ [Layer 2] Querying API: ${endpoint.split('/')[2]}...`);
       const apiRes = await fetch(endpoint);
       
       if (apiRes.ok) {
         const data = await apiRes.json();
         const vulns = data.results || data.data || data.vulnerabilities || [];
         
         const hit = vulns.find(v => v.summary && v.summary.includes(versionClean));
         
         if (hit) {
           console.log(`   ✅ [Layer 2] HIT! Found via API (${hit.id})`);
           return { 
             hit: true, 
             source: "Layer 2 (External API)", 
             cve: hit.id, 
             severity: "High (API Detected)",
             description: hit.summary ? hit.summary.substring(0, 100) + "..." : "No description"
           };
         }
       }
    }
    console.log(`   ❌ [Layer 2] Miss`);
  } catch (e) {
    console.error(`   ⚠️ [Layer 2] Error: ${e.message}`);
  }

  // LAYER 3: AI Agent
  try {
    console.log(`   ⏳ [Layer 3] Connecting to AI Agent (${AI_WS_URL})...`);
    
    const aiResult = await new Promise((resolve) => {
      const ws = new WebSocket(AI_WS_URL);
      let isDone = false;
      
      const timeout = setTimeout(() => { 
        if (!isDone) {
          ws.close(); 
          resolve(null);
          console.log(`   ⚠️ [Layer 3] Timeout`);
        }
      }, 300000);

      ws.on("open", () => {
        ws.send(JSON.stringify({
          type: "request",
          request_id: `risk_${slug}_${Date.now()}`,
          params: { slug, version: versionClean }
        }));
      });

      ws.on("message", (msg) => {
        try {
          const data = JSON.parse(msg.toString());
          if (data.type === "response" && !isDone) {
            isDone = true;
            clearTimeout(timeout);
            ws.close();
            resolve(data);
          }
        } catch (e) { console.error("AI Parse Error"); }
      });
      
      ws.on("error", () => {
        if (!isDone) { isDone = true; clearTimeout(timeout); resolve(null); }
      });
    });

    if (aiResult && aiResult.cves && aiResult.cves.length > 0) {
      console.log(`   ✅ [Layer 3] HIT! AI confirmed vulnerability`);
      return { 
        hit: true, 
        source: "Layer 3 (AI Agent)", 
        cve: aiResult.cves[0].id || aiResult.cves[0], 
        severity: "AI Detected" 
      };
    } else {
      console.log(`   ❌ [Layer 3] Miss (AI found nothing)`);
    }

  } catch (e) {
    console.error(`   ⚠️ [Layer 3] Connection Failed: ${e.message}`);
  }

  console.log(`   🟢 [Clean] No known vulnerabilities found.`);
  return { hit: false, status: "Clean", message: "No CVEs found in 3 layers" };
};

// Extracted local rules so other endpoints can reuse them
const LOCAL_RULES = {
  "social-warfare": { "3.5.2": { cve: "CVE-2019-9978", severity: "High (RCE)" } },
  "wp-time-capsule": { "1.21.15": { cve: "CVE-2020-8772", severity: "Critical" } },
  "contact-form-7": { "5.1": { cve: "CVE-2020-35489", severity: "High" } },
  "akismet": { "4.1.0": { cve: "CVE-2021-24276", severity: "Medium" } },
};

// Layer-specific check helpers (used by frontend Analyze button)
const checkLayer1 = (slug, version) => {
  const v = (version || "").toString().trim();
  if (LOCAL_RULES[slug] && LOCAL_RULES[slug][v]) {
    return { hit: true, source: "Layer 1 (Local)", ...LOCAL_RULES[slug][v], layer: 1 };
  }
  return { hit: false, source: "Layer 1 (Local)", layer: 1 };
};

const checkLayer2 = async (slug, version) => {
  try {
    const endpoint = `https://cve.circl.lu/api/vulnerability/browse/${slug}`;
    const apiRes = await fetch(endpoint);
    if (!apiRes.ok) return { hit: false, source: "Layer 2 (External API)", layer: 2 };
    const data = await apiRes.json();
    const vulns = data.results || data.data || data.vulnerabilities || [];
    const hit = vulns.find(v => v.summary && version && v.summary.includes(version.toString().trim()));
    if (hit) {
      return { hit: true, source: "Layer 2 (External API)", cve: hit.id || hit.CVE || hit.cve, severity: hit.severity || "High (API Detected)", description: hit.summary || "", layer: 2 };
    }
    return { hit: false, source: "Layer 2 (External API)", layer: 2 };
  } catch (e) {
    return { hit: false, source: "Layer 2 (External API)", layer: 2, error: e.message };
  }
};

const checkLayer3 = async (slug, version) => {
  try {
    const aiResult = await new Promise((resolve) => {
      const ws = new WebSocket(AI_WS_URL);
      let done = false;
      const timeout = setTimeout(() => { if (!done) { done = true; ws.close(); resolve(null); } }, 300000);
      ws.on("open", () => {
      ws.send(JSON.stringify({ type: "request", request_id: `risk_${slug}_${Date.now()}`, params: { slug, version, analysis_type: "plugin_cve_analysis" } }));
    });
      ws.on("message", (msg) => {
        try {
          const data = JSON.parse(msg.toString());
          if (!done && data.type === "response") { done = true; clearTimeout(timeout); ws.close(); resolve(data); }
        } catch (e) { /* ignore parse errors */ }
      });
      ws.on("error", () => { if (!done) { done = true; clearTimeout(timeout); resolve(null); } });
    });
    if (aiResult && aiResult.cves && aiResult.cves.length > 0) {
      return { hit: true, source: "Layer 3 (AI Agent)", cve: aiResult.cves[0].id || aiResult.cves[0], severity: "AI Detected", layer: 3 };
    }
    return { hit: false, source: "Layer 3 (AI Agent)", layer: 3 };
  } catch (e) {
    return { hit: false, source: "Layer 3 (AI Agent)", layer: 3, error: e.message };
  }
};

// Layer endpoints used by frontend Analyze button
app.get('/cve/layer1', async (req, res) => {
  const { slug, version } = req.query;
  if (!slug || !version) return res.status(400).json({ ok: false, error: 'Missing slug or version' });
  const result = checkLayer1(slug, version);
  return res.json({ ok: true, ...result });
});

app.get('/cve/layer2', async (req, res) => {
  const { slug, version } = req.query;
  if (!slug || !version) return res.status(400).json({ ok: false, error: 'Missing slug or version' });
  const result = await checkLayer2(slug, version);
  return res.json({ ok: true, ...result });
});

app.get('/cve/layer3', async (req, res) => {
  const { slug, version } = req.query;
  if (!slug || !version) return res.status(400).json({ ok: false, error: 'Missing slug or version' });
  const result = await checkLayer3(slug, version);
  return res.json({ ok: true, ...result });
});

// Combined analyze endpoint that runs layers in sequence (used by fuzz analyze)
app.get('/cve/analyze', async (req, res) => {
  const { slug, version } = req.query;
  if (!slug || !version) return res.status(400).json({ ok: false, error: 'Missing slug or version' });

  const analysis = [];
  const l1 = checkLayer1(slug, version);
  analysis.push(l1);
  if (l1.hit) return res.json({ ok: true, analysis: { final_result: l1, layers: analysis } });

  const l2 = await checkLayer2(slug, version);
  analysis.push(l2);
  if (l2.hit) return res.json({ ok: true, analysis: { final_result: l2, layers: analysis } });

  const l3 = await checkLayer3(slug, version);
  analysis.push(l3);
  if (l3.hit) return res.json({ ok: true, analysis: { final_result: l3, layers: analysis } });

  return res.json({ ok: true, analysis: { final_result: { hit: false, source: 'none' }, layers: analysis } });
});

/* ============================================================
   MAIN PLUGINS ROUTE WITH DUAL JSON FORMAT
============================================================ */
app.get("/plugins", async (req, res) => {
  const { url, apiKey, format = "auto" } = req.query;
  
  if (!url || !url.startsWith("http")) {
    return res.status(400).json({ error: "Valid URL starting with http required" });
  }

  console.log(`[WPScan] Running scan on ${url}, API Key: ${apiKey ? "Provided" : "Not provided"}`);
  const hasDocker = await checkDocker();
  
  if (!hasDocker) {
    return res.json({ 
      ok: true, 
      plugins: [],
      warning: "Docker not available",
      data: await fallbackPluginDetection(url)
    });
  }

  // Determine scan mode and format
  const isPremiumMode = apiKey && apiKey.trim();
  const responseFormat = format === "premium" ? "premium" : (isPremiumMode ? "premium" : "free");

  console.log(`[WPScan] Mode: ${isPremiumMode ? "PREMIUM" : "FREE"}, Format: ${responseFormat}`);

  // Build WPScan command based on mode
  const args = [
    "run", "--rm", "wpscanteam/wpscan",
    "--url", url,
    "--format", "json",
    "--no-banner",
    "--random-user-agent"
  ];

  if (isPremiumMode) {
    args.push("--api-token", apiKey.trim());
    args.push("--enumerate", "ap");
    args.push("--detection-mode", "aggressive");
    args.push("--max-threads", "15");
    args.push("--request-timeout", "3000");
    console.log(`[WPScan] PREMIUM MODE: Full aggressive enumeration`);
  } else {
    args.push("--enumerate", "ap");
    args.push("--plugins-detection", "aggressive");
    args.push("--max-threads", "15");
    args.push("--request-timeout", "3000");
    console.log(`[WPScan] FREE MODE: Basic vulnerability scan`);
  }

  console.log(`[WPScan] Command: docker ${args.join(' ')}`);

  const proc = spawn("docker", args);
  let stdout = "";
  let stderr = "";

  proc.stdout.on("data", (data) => {
    const chunk = data.toString();
    stdout += chunk;
    if (stdout.length < 500) {
      console.log("[WPScan][stdout]", chunk.substring(0, 200));
    }
  });

  proc.stderr.on("data", (data) => {
    const chunk = data.toString();
    stderr += chunk;
    console.log("[WPScan][stderr]", chunk);
  });

  proc.on("close", async (code) => {
  console.log(`[WPScan] Process exited with code ${code}`);
  
  // Handle API token errors specifically for premium mode
  if (isPremiumMode && code === 5) {
    const errorOutput = stdout + stderr;
    if (errorOutput.includes("Invalid API Token") || errorOutput.includes("API token")) {
      console.log("[WPScan] API Token error detected");
      return res.json({
        ok: false,
        error: "Invalid WPScan API Token",
        details: "The provided API token is invalid or has expired",
        solution: "Get a valid API token from https://wpscan.com/register"
      });
    }
  }
  
  if (code !== 0) {
    if (stderr.includes("Cannot connect to the Docker daemon")) {
      return res.json({ 
        ok: false, 
        error: "Docker daemon not running. Start Docker Desktop.",
        code: code
      });
    }
    
    if (stderr.includes("The target is not running WordPress")) {
      return res.json(generateFreeModeResponse(
        { plugins: [], wordpress: { detected: false } }, 
        url, 
        isPremiumMode ? "premium" : "free"
      ));
    }
  }

  const json = extractJSON(stdout + "\n" + stderr);
  
  if (!json) {
    console.log("[WPScan] Failed to extract JSON from output");
    return res.json(generateFreeModeResponse(
      { plugins: [], wordpress: { detected: false } }, 
      url, 
      isPremiumMode ? "premium" : "free"
    ));
  }

  // Check if plugins object is empty due to API error
  if (isPremiumMode && json.plugins && Object.keys(json.plugins).length === 0) {
    console.log("[WPScan] Empty plugins object detected, checking for API errors");
    
    // Look for API error messages in the output
    if (json.vuln_api && json.vuln_api.error) {
      console.log("[WPScan] API Error:", json.vuln_api.error);
      
      // Fall back to free mode scanning without API
      console.log("[WPScan] Falling back to free mode scanning...");
      const freeArgs = [
        "run", "--rm", "wpscanteam/wpscan",
        "--url", url,
        "--format", "json",
        "--no-banner",
        "--random-user-agent",
        "--enumerate", "ap",
        "--plugins-detection", "aggressive",
        "--max-threads", "15",
        "--request-timeout", "3000"
      ];
      
      console.log(`[WPScan] Fallback command: docker ${freeArgs.join(' ')}`);
      
      try {
        const fallbackResult = await new Promise((resolve) => {
          const fallbackProc = spawn("docker", freeArgs);
          let fallbackStdout = "";
          let fallbackStderr = "";
          
          fallbackProc.stdout.on("data", (data) => fallbackStdout += data.toString());
          fallbackProc.stderr.on("data", (data) => fallbackStderr += data.toString());
          
          fallbackProc.on("close", (fallbackCode) => {
            console.log(`[WPScan] Fallback process exited with code ${fallbackCode}`);
            if (fallbackCode === 0) {
              const fallbackJson = extractJSON(fallbackStdout + "\n" + fallbackStderr);
              resolve(fallbackJson);
            } else {
              resolve(null);
            }
          });
        });
        
        if (fallbackResult) {
          console.log("[WPScan] Fallback scan successful, using free mode data");
          json.plugins = fallbackResult.plugins || {};
          json.version = fallbackResult.version || json.version;
        }
      } catch (fallbackError) {
        console.log("[WPScan] Fallback scan failed:", fallbackError.message);
      }
    }
  }

  // Process detected plugins
  const detectedPlugins = [];
  if (json.plugins && Object.keys(json.plugins).length > 0) {
    console.log("[DEBUG] Processing plugins object:", Object.keys(json.plugins));
    
    // Handle both object format: {"plugin1": {...}, "plugin2": {...}}
    if (typeof json.plugins === 'object' && !Array.isArray(json.plugins)) {
      // Object format (original WPScan)
      for (const [slug, info] of Object.entries(json.plugins)) {
        console.log(`[DEBUG] Processing plugin: ${slug}`, info);
        detectedPlugins.push({
          slug: slug,
          version: info.version?.number || info.version || "Unknown",
          confidence: info.confidence || 100,
          source: isPremiumMode ? "wpscan_premium" : "wpscan_free",
          wpscan_vulns: info.vulnerabilities || [],
          found_by: info.found_by || []
        });
      }
    } else if (Array.isArray(json.plugins)) {
      // Array format (alternative format)
      for (const plugin of json.plugins) {
        detectedPlugins.push({
          slug: plugin.slug || plugin.name || "unknown",
          version: plugin.version?.number || plugin.version || "Unknown",
          confidence: plugin.confidence || 100,
          source: isPremiumMode ? "wpscan_premium" : "wpscan_free",
          wpscan_vulns: plugin.vulnerabilities || [],
          found_by: plugin.found_by || []
        });
      }
    }
    console.log(`[WPScan] Found ${detectedPlugins.length} plugins`);
  } else {
    console.log("[WPScan] No plugins found in scan results");
    console.log("[DEBUG] json.plugins value:", json.plugins);
    console.log("[DEBUG] json.plugins type:", typeof json.plugins);
    
    if (isPremiumMode && detectedPlugins.length === 0) {
      console.log("[WPScan] Premium mode found no plugins, trying enhanced detection...");
      const enhancedPlugins = await enhancedPluginDetection(url);
      detectedPlugins.push(...enhancedPlugins);
    }
  }

  // Analyze plugins
  let analysisResults = [];
  if (detectedPlugins.length > 0) {
    if (isPremiumMode) {
      console.log(`[Premium Analysis] Checking ${detectedPlugins.length} plugins against Layer 1-3...`);
      
      for (let i = 0; i < detectedPlugins.length; i += 2) {
        const batch = detectedPlugins.slice(i, i + 2);
        const batchResults = await Promise.all(batch.map(async (p) => {
          const riskReport = await analyzePluginRisk(p.slug, p.version);
          
          return {
            slug: p.slug,
            version: p.version,
            confidence: p.confidence,
            source: p.source,
            native_wpscan_vulns: p.wpscan_vulns,
            custom_analysis: riskReport
          };
        }));
        
        analysisResults.push(...batchResults);
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    } else {
      console.log(`[Free Analysis] Basic analysis for ${detectedPlugins.length} plugins`);
      analysisResults = detectedPlugins.map(p => ({
        slug: p.slug,
        version: p.version,
        confidence: p.confidence,
        source: p.source,
        native_wpscan_vulns: p.wpscan_vulns,
        custom_analysis: { hit: false, status: "Free mode - limited analysis" }
      }));
    }
  }

  // Prepare WordPress info
  const wordpressInfo = json.version ? {
    version: json.version.number || json.version,
    status: json.version.status || "unknown",
    vulnerabilities: json.version.vulnerabilities || [],
    detected: true
  } : (json.wordpress_version ? {
    version: json.wordpress_version,
    status: "detected",
    vulnerabilities: [],
    detected: true
  } : {
    detected: false,
    message: "WordPress version not detected"
  });

  // Generate appropriate response format
  const results = {
    plugins: analysisResults,
    wordpress: wordpressInfo
  };

  let response;
  if (responseFormat === "premium") {
    response = generatePremiumModeResponse(results, url, apiKey);
    // Add 'found' flag for frontend compatibility
    response.found = (response.vulnerabilities && response.vulnerabilities.length > 0) || (response.wordpress_core && response.wordpress_core.vulnerabilities && response.wordpress_core.vulnerabilities.length > 0);
  } else {
    response = generateFreeModeResponse(results, url, isPremiumMode ? "premium" : "free");
    response.found = response.plugins && response.plugins.length > 0;
  }

  // Save report (create copy without circular references for JSON serialization)
  const filename = path.join(SCAN_DIR, `scan_${isPremiumMode ? 'premium' : 'free'}_${Date.now()}.json`);
  const reportToSave = JSON.parse(JSON.stringify(response)); // Deep clone to remove circular refs
  fs.writeFileSync(filename, JSON.stringify(reportToSave, null, 2));
  console.log(`[WPScan] Report saved to ${filename}`);
  console.log(`[WPScan] Response summary - Mode: ${responseFormat}, Found: ${response.found}, Vulnerabilities: ${response.vulnerabilities ? response.vulnerabilities.length : 0}`);

  res.json(response);
  });

  proc.on("error", (error) => {
    console.error("[WPScan] Process error:", error);
    res.json({ 
      ok: false, 
      error: `WPScan process failed: ${error.message}`,
      solution: "Make sure Docker is running and try: docker pull wpscanteam/wpscan"
    });
  });
});
/* ============================================================
   FFUF ROUTE
============================================================ */
app.get("/fuzz", async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing URL" });

  const hasDocker = await checkDocker();
  if (!hasDocker) return res.status(500).json({ error: "Docker is not running" });

  const wordlistDir = "C:/Users/WIN11 64BIT/Downloads/ACS project/backend/wordlists";
  const wordlistPath = path.join(wordlistDir, "plugins.txt");

  const targetUrl = url.replace(/\/$/, "");
  const fuzzUrl = `${targetUrl}/wp-content/plugins/FUZZ/`;

  console.log(`[FFUF] Scanning: ${fuzzUrl}`);

  const args = [
    "run", "--rm",
    "-v", `${wordlistDir}:/wordlists`,
    "trickest/ffuf:latest",
    "-u", fuzzUrl,
    "-w", "/wordlists/plugins.txt:FUZZ",
    "-mc", "200,301,302,403,500",
    "-t", "20",
    "-o", "/tmp/ffuf.json",
    "-of", "json"
  ];

  const proc = spawn("docker", args);
  let stdout = "";
  let stderr = "";

  proc.stdout.on("data", (d) => stdout += d.toString());
  proc.stderr.on("data", (d) => stderr += d.toString());

  proc.on("close", async (code) => {
    console.log(`[FFUF] Process completed with code: ${code}`);
    
    try {
      let foundPlugins = [];

      const cleanStdout = stdout.replace(/\u001b\[2K/g, '').replace(/\u001b\[[0-9;]*m/g, '');
      const cleanStderr = stderr.replace(/\u001b\[2K/g, '').replace(/\u001b\[[0-9;]*m/g, '');
      
      const combinedOutput = cleanStdout + cleanStderr;
      const lines = combinedOutput.split('\n');
      
      for (const line of lines) {
        if (!line.trim() || line.includes(':: Method') || line.includes('_______')) continue;
        
        if (line.includes('[Status:') && line.includes(']')) {
          const bracketIndex = line.indexOf('[');
          if (bracketIndex > 0) {
            const pluginPart = line.substring(0, bracketIndex).trim();
            const pluginMatch = pluginPart.match(/^([a-zA-Z0-9_.-]+)/);
            if (pluginMatch && pluginMatch[1]) {
              const plugin = pluginMatch[1].trim();
              if (plugin && plugin !== 'FUZZ' && plugin.length > 1 && plugin.length < 50 && !plugin.includes(' ') && !foundPlugins.includes(plugin)) {
                foundPlugins.push(plugin);
              }
            }
          }
        }
      }

      console.log(`[FFUF] Final found plugins:`, foundPlugins);

      const analysisResults = [];
      for (const plugin of foundPlugins) {
        try {
          console.log(`[FFUF] Analyzing: ${plugin}`);
          const version = await detectVersionFromUrl(targetUrl, plugin);
          const risk = await analyzePluginRisk(plugin, version || "Unknown");
          
          analysisResults.push({
            slug: plugin,
            version: version || "Unknown", 
            analysis: risk,
            vulnerable: risk.hit || false,
            source: "FFUF Discovery"
          });

          await new Promise(r => setTimeout(r, 300));
        } catch (e) {
          console.log(`[FFUF] Error analyzing ${plugin}:`, e.message);
          analysisResults.push({
            slug: plugin,
            version: "Error",
            analysis: { error: e.message },
            vulnerable: false,
            source: "FFUF Discovery"
          });
        }
      }

      const report = {
        target: url,
        timestamp: new Date().toISOString(),
        tool: "FFUF Directory Bruteforce",
        fuzz_url: fuzzUrl,
        wordlist: "plugins.txt",
        scan_summary: {
          total_plugins_found: foundPlugins.length,
          analyzed_plugins: analysisResults.length,
          vulnerable_plugins: analysisResults.filter(item => item.vulnerable).length,
          scan_duration: "N/A",
          status_codes_found: ["403", "500"]
        },
        raw_ffuf_output: {
          stdout: cleanStdout,
          stderr: cleanStderr
        },
        discovered_plugins: foundPlugins,
        detailed_analysis: analysisResults
      };

      const filename = `ffuf_scan_${Date.now()}.json`;
      const filepath = path.join(SCAN_DIR, filename);
      
      fs.writeFileSync(filepath, JSON.stringify(report, null, 2));
      console.log(`[FFUF] Scan report saved to: ${filepath}`);

      res.json({
        ok: true,
        found: analysisResults.length,
        data: analysisResults,
        plugins: foundPlugins,
        summary: {
          total_found: analysisResults.length,
          vulnerable: analysisResults.filter(item => item.vulnerable).length
        },
        report_file: filename,
        scan_saved: true
      });

    } catch (e) {
      console.error(`[FFUF] Processing error:`, e);
      res.json({
        ok: false,
        error: "Processing failed",
        details: e.message
      });
    }
  });

  proc.on("error", (err) => {
    console.error(`[FFUF] Process error:`, err);
    res.json({ ok: false, error: "Docker process failed", details: err.message });
  });
});

const enhancedPluginDetection = async (url) => {
  console.log(`[Enhanced Detection] Scanning ${url} for plugins...`);
  const plugins = [];
  
  try {
    const commonPlugins = [
      'akismet', 'contact-form-7', 'yoast-seo', 'wordfence', 
      'woocommerce', 'elementor', 'jetpack', 'all-in-one-seo-pack',
      'wp-super-cache', 'really-simple-ssl', 'google-site-kit',
      'litespeed-cache', 'redirection', 'broken-link-checker',
      'social-warfare', 'wp-time-capsule', 'iwp-client',
      'wp-advanced-search', 'wp-file-upload'
    ];
    
    for (const plugin of commonPlugins) {
      try {
        const pluginUrl = `${url}/wp-content/plugins/${plugin}/`;
        const response = await fetch(pluginUrl, { 
          method: 'HEAD',
          timeout: 5000 
        });
        
        if (response.status === 200 || response.status === 403) {
          let version = "Unknown";
          try {
            // Try multiple methods to detect version
            const readmeResponse = await fetch(`${pluginUrl}readme.txt`);
            if (readmeResponse.status === 200) {
              const text = await readmeResponse.text();
              const versionMatch = text.match(/Stable tag:\s*([0-9.]+)/i);
              if (versionMatch) version = versionMatch[1];
            }
            
            // If no version from readme, try the plugin file
            if (version === "Unknown") {
              const pluginFileResponse = await fetch(`${pluginUrl}${plugin}.php`);
              if (pluginFileResponse.status === 200) {
                const pluginText = await pluginFileResponse.text();
                const versionMatch = pluginText.match(/Version:\s*([0-9.]+)/i);
                if (versionMatch) version = versionMatch[1];
              }
            }
          } catch (e) {
            // Couldn't read version info, but plugin exists
          }
          
          plugins.push({
            slug: plugin,
            version: version,
            confidence: 80,
            source: "enhanced_detection",
            found_by: ["directory_enumeration"]
          });
        }
        await new Promise(resolve => setTimeout(resolve, 200));
      } catch (e) {
        // Plugin not found or error, continue
      }
    }
    
    console.log(`[Enhanced Detection] Found ${plugins.length} plugins`);
    return plugins;
    
  } catch (error) {
    console.error(`[Enhanced Detection] Error: ${error.message}`);
    return [];
  }
};

// Add missing fallbackPluginDetection function
const fallbackPluginDetection = async (url) => {
  console.log(`[Fallback Detection] Scanning ${url} for plugins...`);
  // Implement basic plugin detection logic here
  return [];
};

/* ============================================================
   EXISTING ROUTES
============================================================ */
app.get("/hashdb", async (req, res) => {
  const { url, slug } = req.query;
  if (!url || !slug)
    return res.status(400).json({ error: "Missing parameters" });

  try {
    const response = await fetch(
      `${url}/wp-content/plugins/${slug}/readme.txt`
    );

    if (!response.ok)
      return res.json({ found: false, error: "Readme not found" });

    const text = await response.text();
    const m = text.match(/Stable tag:\s*([0-9.]+)/i);

    if (m) return res.json({ found: true, version: m[1], source: "regex" });

    const hash = crypto.createHash("sha256").update(text).digest("hex");

    const HASH_DB = {
      "45f9f9c04d0b5f7950a0ee30b7d2608d182cbfcb20b7cc15448a8fa2f1187773": "5.1",
    };

    if (HASH_DB[hash])
      return res.json({ found: true, version: HASH_DB[hash], source: "hash" });

    return res.json({ found: false });
  } catch (e) {
    res.json({ found: false, error: e.message });
  }
});

// ... keep the rest of your existing routes (analyze/url, health, etc.)

app.get("/analyze/url", async (req, res) => {
  const { url } = req.query;
  if (!url) return res.json({ success: false, error: "Missing URL" });
  console.log(`[AI URL] Analyzing ${url}`);
  try {
    const ws = new WebSocket(AI_WS_URL);
    let progress = [];
    return new Promise((resolve) => {
      const timeout = setTimeout(() => {
        ws.close();
        resolve(res.json({ success: false, error: "Timeout (1200s)", progress }));
      }, 1200000);
      ws.on("open", () => {
        ws.send(JSON.stringify({ type: "request", request_id: "url_" + Date.now(), params: { url, analysis_type: "full_wordpress_scan" } }));
      });
      ws.on("message", (msg) => {
        try {
          const response = JSON.parse(msg.toString());
          if (response.type === "progress") progress.push(response.message);
          else if (response.type === "response") {
            clearTimeout(timeout);
            ws.close();
            resolve(res.json({ success: true, url, analysis: response.cves || [], raw_findings: response.raw || "", progress }));
          }
        } catch (e) {
          // ignore non-JSON fragments (CAI prints decorative text)
          console.warn("[analyze/url] non-JSON message ignored");
        }
      });
      ws.on("error", (err) => {
        clearTimeout(timeout);
        resolve(res.json({ success: false, error: err.message }));
      });
    });
  } catch (e) {
    res.json({ success: false, error: e.message });
  }
});


app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

/* ============================================================
   SERVER START
============================================================ */
const server = http.createServer(app);
server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

server.on("upgrade", (req, socket, head) => {
  socket.destroy();
});