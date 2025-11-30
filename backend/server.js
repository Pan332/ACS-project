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
  // FIXED: Better JSON extraction with regex
  const jsonMatch = raw.match(/\{[\s\S]*\}/);
  if (!jsonMatch) return null;
  try {
    return JSON.parse(jsonMatch[0]);
  } catch {
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

// --- CORE LOGIC: Multi-Layer Analysis with Verbose Logging ---
const analyzePluginRisk = async (slug, version) => {
  // 0. Sanity Check
  if (!version || version === "Unknown") {
    console.log(`   [Skip] ${slug} - No version detected`);
    return { slug, version, risk: "Unknown Version", source: "Skipped" };
  }

  const versionClean = version.trim();
  console.log(`   [Analyze] checking ${slug} v${versionClean} across 3 Layers...`);

  // ============================================================
  // LAYER 1: Local Database (Hardcoded Rules)
  // ============================================================
  // เหตุผล: เร็วที่สุด ไม่ต้องต่อเน็ต เช็คของตาย
  const localRules = {
    "social-warfare": { "3.5.2": { cve: "CVE-2019-9978", severity: "High (RCE)" } }, // ตัวอย่างที่คุณเจอ
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

  // ============================================================
  // LAYER 2: External APIs (CIRCL.LU / CVE.LIVE)
  // ============================================================
  // เหตุผล: ฐานข้อมูลกว้างกว่า ครอบคลุม CVE สาธารณะ
  try {
    const apiSources = [
      `https://cve.circl.lu/api/vulnerability/browse/${slug}` // Source 1
    ];

    for (const endpoint of apiSources) {
       console.log(`   ⏳ [Layer 2] Querying API: ${endpoint.split('/')[2]}...`);
       const apiRes = await fetch(endpoint);
       
       if (apiRes.ok) {
         const data = await apiRes.json();
         // รองรับโครงสร้างข้อมูลที่ต่างกันของแต่ละ API
         const vulns = data.results || data.data || data.vulnerabilities || [];
         
         // ค้นหาว่ามี version ของเราอยู่ในรายการไหม
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

  // ============================================================
  // LAYER 3: AI Agent (WebSocket)
  // ============================================================
  // เหตุผล: ใช้ AI วิเคราะห์ความสัมพันธ์ หรือหา Zero-day pattern ที่ Database ยังไม่อัปเดต
  try {
    console.log(`   ⏳ [Layer 3] Connecting to AI Agent (${AI_WS_URL})...`);
    
    const aiResult = await new Promise((resolve) => {
      const ws = new WebSocket(AI_WS_URL);
      let isDone = false;
      
      // Timeout 5 วินาทีต่อ 1 Plugin เพื่อไม่ให้รอนานเกินไป
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

  // Final: ถ้าไม่เจอเลย
  console.log(`   🟢 [Clean] No known vulnerabilities found.`);
  return { hit: false, status: "Clean", message: "No CVEs found in 3 layers" };
};

/* ============================================================
   ROUTE 1: WPScan (Fixed command structure)
============================================================ */
app.get("/plugins", async (req, res) => {
  const { url, apiKey } = req.query;
  
  if (!url || !url.startsWith("http")) {
    return res.status(400).json({ error: "Valid URL starting with http required" });
  }

  console.log(`[WPScan] Running scan on ${url}`);
  const hasDocker = await checkDocker();
  if (!hasDocker) {
    console.log("[WPScan] Docker not available, using fallback");
    return res.json({ 
      ok: true, 
      plugins: [],
      warning: "Docker not available - using fallback detection",
      data: await fallbackPluginDetection(url)
    });
  }

  // CORRECTED WPScan command structure
  const args = [
    "run", "--rm", "wpscanteam/wpscan",
    "--url", url,
    "--enumerate", "ap", // v = vulnerable plugins, p = all plugins
    "--format", "json",
    "--no-banner",
    "--random-user-agent",
    "--max-threads", "10"
  ];

  // Handle API key properly
  if (apiKey && apiKey.trim()) {
    // Remove any --no-api flag and add API token
    const noApiIndex = args.indexOf("--no-api");
    if (noApiIndex !== -1) args.splice(noApiIndex, 1);
    
    args.push("--detection-mode", "aggressive");
    args.push("--api-token", apiKey.trim());
    console.log(`[WPScan] Using premium API mode`);
  } else {
    // Free mode - use passive detection to avoid API limits
    args.push("--plugins-detection", "aggressive");
    console.log(`[WPScan] Using free mode`);
  }

  console.log(`[WPScan] Command: docker ${args.join(' ')}`);

  const proc = spawn("docker", args);
  let stdout = "";
  let stderr = "";

  proc.stdout.on("data", (data) => {
    const chunk = data.toString();
    stdout += chunk;
    // Log first part for debugging
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
    
    // Handle common errors
    if (code !== 0) {
      if (stderr.includes("Cannot connect to the Docker daemon")) {
        return res.json({ 
          ok: false, 
          error: "Docker daemon not running. Start Docker Desktop.",
          code: code
        });
      }
      
      if (stderr.includes("The target is not running WordPress")) {
        return res.json({ 
          ok: true, 
          plugins: [],
          warning: "Target does not appear to be running WordPress",
          wordpress: { detected: false }
        });
      }
      
      if (stderr.includes("No such image")) {
        return res.json({ 
          ok: false, 
          error: "WPScan Docker image not found. Run: docker pull wpscanteam/wpscan",
          code: code
        });
      }
    }

    const json = extractJSON(stdout + "\n" + stderr);
    
    if (!json) {
      console.log("[WPScan] Failed to extract JSON from output");
      console.log("[WPScan] stdout preview:", stdout.substring(0, 300));
      console.log("[WPScan] stderr preview:", stderr.substring(0, 300));
      
      return res.json({ 
        ok: true, 
        plugins: [],
        warning: "WPScan output could not be parsed, using fallback detection",
        data: await fallbackPluginDetection(url)
      });
    }

    // Process detected plugins
    const detectedPlugins = [];
    if (json.plugins && Object.keys(json.plugins).length > 0) {
      for (const [slug, info] of Object.entries(json.plugins)) {
        detectedPlugins.push({
          slug: slug,
          version: info.version?.number || "Unknown",
          confidence: info.confidence || 100,
          source: apiKey ? "wpscan_premium" : "wpscan_free",
          wpscan_vulns: info.vulnerabilities || [],
          found_by: info.found_by || []
        });
      }
      console.log(`[WPScan] Found ${detectedPlugins.length} plugins`);
    } else {
      console.log("[WPScan] No plugins found in scan results");
    }

    // Analyze plugins with our custom layers
    let analysisResults = [];
    if (detectedPlugins.length > 0) {
      console.log(`[Analysis] Checking ${detectedPlugins.length} plugins against Layer 1-3...`);
      
      // Process plugins in small batches
      const BATCH_SIZE = 3;
      for (let i = 0; i < detectedPlugins.length; i += BATCH_SIZE) {
        const batch = detectedPlugins.slice(i, i + BATCH_SIZE);
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
        // Small delay between batches
        if (i + BATCH_SIZE < detectedPlugins.length) {
          await new Promise(resolve => setTimeout(resolve, 800));
        }
      }
    }

    // Prepare WordPress info
    const wordpressInfo = json.version ? {
      wordpress_version: json.version.number,
      wordpress_status: json.version.status,
      wordpress_vulnerabilities: json.version.vulnerabilities || [],
      detected: true
    } : {
      detected: false,
      message: "WordPress version not detected"
    };

    // Save report
    const report = {
      target: url,
      timestamp: new Date().toISOString(),
      tool: "WPScan + Custom Layers",
      wordpress: wordpressInfo,
      results: analysisResults
    };
    
    const filename = path.join(SCAN_DIR, `wpscan_${Date.now()}.json`);
    fs.writeFileSync(filename, JSON.stringify(report, null, 2));
    console.log(`[WPScan] Report saved to ${filename}`);

    res.json({ 
      ok: true, 
      plugins: analysisResults,
      wordpress: wordpressInfo,
      api_mode: apiKey ? "premium" : "free",
      scan_info: {
        plugins_found: analysisResults.length,
        wordpress_detected: wordpressInfo.detected
      }
    });
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
   FFUF ROUTE - WITH SCAN FILE SAVING
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

      // CLEAN ANSI ESCAPE CODES
      const cleanStdout = stdout.replace(/\u001b\[2K/g, '').replace(/\u001b\[[0-9;]*m/g, '');
      const cleanStderr = stderr.replace(/\u001b\[2K/g, '').replace(/\u001b\[[0-9;]*m/g, '');
      
      // COMBINE BOTH STDOUT AND STDERR
      const combinedOutput = cleanStdout + cleanStderr;
      const lines = combinedOutput.split('\n');
      
      for (const line of lines) {
        if (!line.trim() || line.includes(':: Method') || line.includes('_______')) continue;
        
        // Look for plugin result lines
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

      // Analyze found plugins
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

      // SAVE COMPREHENSIVE REPORT TO SCANS FOLDER
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
          status_codes_found: ["403", "500"] // Based on your results
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

      // Return response to frontend
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

/* ============================================================
   EXISTING ROUTES (Keep your original routes 2-6)
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

/* ============================================================
   ENHANCED CORE LOGIC: Complete 3-layer analysis flow
============================================================ */
const analyzePluginWithLayers = async (slug, version) => {
  if (!version || version === "Unknown") {
    return { 
      slug, 
      version, 
      status: "skipped", 
      reason: "Unknown version", 
      risk_level: "unknown" 
    };
  }

  console.log(`[CVE Flow] Starting 3-layer analysis for ${slug} v${version}`);
  
  const analysisResult = {
    slug,
    version,
    layers: [],
    final_result: null,
    risk_level: "clean"
  };

  // Layer 1: Local Database
  console.log(`[Layer 1] Checking local rules for ${slug}...`);
  const layer1Result = await checkLayer1(slug, version);
  analysisResult.layers.push({
    name: "Layer 1 - Local Rules",
    result: layer1Result
  });

  if (layer1Result.hit) {
    analysisResult.final_result = layer1Result;
    analysisResult.risk_level = "high";
    console.log(`[CVE Flow] ✅ Vulnerability found in Layer 1: ${layer1Result.cve}`);
    return analysisResult;
  }

  // Layer 2: External APIs
  console.log(`[Layer 2] Querying external APIs for ${slug}...`);
  const layer2Result = await checkLayer2(slug, version);
  analysisResult.layers.push({
    name: "Layer 2 - External APIs", 
    result: layer2Result
  });

  if (layer2Result.hit) {
    analysisResult.final_result = layer2Result;
    analysisResult.risk_level = "high";
    console.log(`[CVE Flow] ✅ Vulnerability found in Layer 2: ${layer2Result.cve}`);
    return analysisResult;
  }

  // Layer 3: AI Agent
  console.log(`[Layer 3] Activating AI agent for ${slug}...`);
  const layer3Result = await checkLayer3(slug, version);
  analysisResult.layers.push({
    name: "Layer 3 - AI Agent",
    result: layer3Result
  });

  if (layer3Result.hit) {
    analysisResult.final_result = layer3Result;
    analysisResult.risk_level = "high"; 
    console.log(`[CVE Flow] ✅ Vulnerability found in Layer 3: ${layer3Result.cves?.length || 'unknown'} CVEs`);
    return analysisResult;
  }

  // No vulnerabilities found
  analysisResult.final_result = {
    hit: false,
    status: "clean",
    message: "No vulnerabilities detected across all 3 layers"
  };
  console.log(`[CVE Flow] ✅ No vulnerabilities found for ${slug} v${version}`);
  
  return analysisResult;
};

// Individual layer functions
const checkLayer1 = async (slug, version) => {
  const localRules = {
    "contact-form-7": {
      "5.1": { cve: "CVE-2020-35489", severity: "High", description: "Unauthenticated SQL Injection" },
    },
    "akismet": {
      "4.1.0": { cve: "CVE-2021-24276", severity: "Medium", description: "Cross-Site Scripting" },
    },
    "social-warfare": {
      "3.5.2": { cve: "CVE-2019-9978", severity: "High", description: "Remote Code Execution" }
    },
    "wp-advanced-search": {
      "3.3.3": { cve: "CVE-2020-10899", severity: "Medium", description: "SQL Injection" }
    }
  };

  if (localRules[slug] && localRules[slug][version]) {
    return {
      hit: true,
      source: "Local Database",
      ...localRules[slug][version],
      layer: 1
    };
  }

  return { hit: false, layer: 1, message: "No local rules matched" };
};

const checkLayer2 = async (slug, version) => {
  const sources = [
    { name: "CIRCL", url: `https://cve.circl.lu/api/search/${slug}` },
    { name: "CVE Live", url: `https://api.cve.live/v1/products/${slug}` }
  ];

  for (const source of sources) {
    try {
      console.log(`[Layer 2] Checking ${source.name} API...`);
      const response = await fetch(source.url, { timeout: 10000 });
      
      if (response.ok) {
        const data = await response.json();
        const vulns = data.results || data.data || data.vulnerabilities || [];
        
        // Look for version-specific vulnerabilities
        const versionHit = vulns.find(v => 
          v.summary && v.summary.includes(version)
        );
        
        if (versionHit) {
          return {
            hit: true,
            source: `Layer 2 - ${source.name}`,
            cve: versionHit.id,
            severity: "High",
            description: versionHit.summary?.substring(0, 200) || "No description",
            layer: 2
          };
        }

        // Look for any vulnerabilities for this plugin
        const pluginHit = vulns.find(v => 
          v.summary && v.summary.toLowerCase().includes(slug.toLowerCase())
        );

        if (pluginHit) {
          return {
            hit: true,
            source: `Layer 2 - ${source.name}`,
            cve: pluginHit.id,
            severity: "Medium",
            description: `Plugin vulnerability: ${pluginHit.summary?.substring(0, 200) || "Unknown"}`,
            layer: 2,
            note: "Version-specific match not found, but plugin has known vulnerabilities"
          };
        }
      }
    } catch (error) {
      console.log(`[Layer 2] ${source.name} API error:`, error.message);
    }
  }

  return { hit: false, layer: 2, message: "No vulnerabilities found in external APIs" };
};

const checkLayer3 = async (slug, version, targetUrl = null) => {
  return new Promise((resolve) => {
    console.log(`[Layer 3] Connecting to AI agent at ${AI_WS_URL}...`);
    
    const ws = new WebSocket(AI_WS_URL);
    let progress = [];
    let resolved = false;

    const timeout = setTimeout(() => {
      if (!resolved) {
        ws.close();
        resolve({
          hit: false,
          layer: 3,
          error: "AI agent timeout (20m)",
          progress: progress
        });
        resolved = true;
      }
    }, 1200000);

    ws.on('open', () => {
      console.log(`[Layer 3] Connected, sending analysis request for ${slug} v${version}`);
      progress.push("Connected to AI agent");
      
      // Build proper request with context
      const requestData = {
        type: "request",
        request_id: `layer3_${slug}_${Date.now()}`,
        params: {
          slug: slug,
          version: version,
          analysis_type: "plugin_cve_analysis"
        }
      };

      // Add target URL if available for context
      if (targetUrl) {
        requestData.params.target_url = targetUrl;
        requestData.params.analysis_type = "targeted_plugin_analysis";
      }

      ws.send(JSON.stringify(requestData));
    });

    ws.on('message', (data) => {
      try {
        const response = JSON.parse(data.toString());
        
        if (response.type === "progress") {
          progress.push(response.message);
          console.log(`[Layer 3 Progress] ${response.message}`);
        }
        else if (response.type === "response") {
          clearTimeout(timeout);
          ws.close();
          
          if (!resolved) {
            const result = {
              hit: response.cves && response.cves.length > 0,
              layer: 3,
              source: "AI Agent",
              cves: response.cves || [],
              raw_response: response.raw || "",
              progress: progress
            };
            
            if (result.hit) {
              result.severity = "High";
              result.cve = result.cves[0]?.id || "AI-Detected";
              result.description = `AI detected ${result.cves.length} potential vulnerabilities`;
            }
            
            console.log(`[Layer 3] AI analysis complete: ${result.hit ? 'Vulnerabilities found' : 'No vulnerabilities'}`);
            resolve(result);
            resolved = true;
          }
        }
      } catch (error) {
        console.log(`[Layer 3] Message parse error:`, error.message);
      }
    });

    ws.on('error', (error) => {
      if (!resolved) {
        clearTimeout(timeout);
        resolve({
          hit: false,
          layer: 3,
          error: `AI connection failed: ${error.message}`,
          progress: progress
        });
        resolved = true;
      }
    });

    ws.on('close', () => {
      if (!resolved) {
        clearTimeout(timeout);
        resolve({
          hit: false, 
          layer: 3,
          error: "AI connection closed unexpectedly",
          progress: progress
        });
        resolved = true;
      }
    });
  });
};

/* ============================================================
   UPDATED WPScan ROUTE with Complete 3-Layer Flow
============================================================ */
app.get("/plugins", async (req, res) => {
  const { url, apiKey } = req.query;
  
  if (!url || !url.startsWith("http")) {
    return res.status(400).json({ error: "Valid URL starting with http required" });
  }

  console.log(`[WPScan] Running scan on ${url}`);
  const hasDocker = await checkDocker();
  if (!hasDocker) {
    return res.json({ 
      ok: true, 
      plugins: [],
      warning: "Docker not available",
      data: await fallbackPluginDetection(url)
    });
  }

  const args = [
    "run", "--rm", "wpscanteam/wpscan",
    "--url", url,
    "--enumerate", "ap",
    "--format", "json", 
    "--no-banner",
    "--random-user-agent",
    "--max-threads", "10"
  ];

  if (apiKey && apiKey.trim()) {
    args.push("--api-token", apiKey.trim());
    console.log(`[WPScan] Using premium API mode`);
  } else {
    args.push("--plugins-detection", "aggressive");
    console.log(`[WPScan] Using free mode`);
  }

  const proc = spawn("docker", args);
  let stdout = "";
  let stderr = "";

  proc.stdout.on("data", (data) => stdout += data.toString());
  proc.stderr.on("data", (data) => stderr += data.toString());

  proc.on("close", async (code) => {
    console.log(`[WPScan] Process exited with code ${code}`);
    
    const json = extractJSON(stdout + "\n" + stderr);
    if (!json) {
      return res.json({ 
        ok: false, 
        error: "Failed to parse WPScan JSON"
      });
    }

    // Process detected plugins
    const detectedPlugins = [];
    if (json.plugins && Object.keys(json.plugins).length > 0) {
      for (const [slug, info] of Object.entries(json.plugins)) {
        detectedPlugins.push({
          slug: slug,
          version: info.version?.number || "Unknown",
          confidence: info.confidence || 100,
          source: apiKey ? "wpscan_premium" : "wpscan_free",
          wpscan_vulns: info.vulnerabilities || []
        });
      }
      console.log(`[WPScan] Found ${detectedPlugins.length} plugins`);
    }

    // 🚀 NEW: Run complete 3-layer analysis on all found plugins
    console.log(`[CVE Flow] Starting 3-layer CVE analysis for ${detectedPlugins.length} plugins...`);
    
    const analysisResults = [];
    for (let i = 0; i < detectedPlugins.length; i++) {
      const plugin = detectedPlugins[i];
      console.log(`\n[${i+1}/${detectedPlugins.length}] Analyzing: ${plugin.slug} v${plugin.version}`);
      
      const completeAnalysis = await analyzePluginWithLayers(plugin.slug, plugin.version);
      
      analysisResults.push({
        ...plugin,
        complete_analysis: completeAnalysis,
        risk_level: completeAnalysis.risk_level,
        vulnerable: completeAnalysis.final_result?.hit || false
      });

      // Brief pause between plugins to avoid rate limits
      if (i < detectedPlugins.length - 1) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    // Generate summary
    const vulnerablePlugins = analysisResults.filter(p => p.vulnerable);
    const cleanPlugins = analysisResults.filter(p => !p.vulnerable);
    
    console.log(`\n[SUMMARY] Vulnerable: ${vulnerablePlugins.length}, Clean: ${cleanPlugins.length}`);

    // Save comprehensive report
    const report = {
      target: url,
      timestamp: new Date().toISOString(),
      scan_mode: apiKey ? "premium" : "free",
      summary: {
        total_plugins: analysisResults.length,
        vulnerable_plugins: vulnerablePlugins.length,
        clean_plugins: cleanPlugins.length,
        risk_level: vulnerablePlugins.length > 0 ? "HIGH" : "LOW"
      },
      wordpress: json.version ? {
        version: json.version.number,
        status: json.version.status,
        vulnerabilities: json.version.vulnerabilities || []
      } : null,
      results: analysisResults
    };
    
    const filename = path.join(SCAN_DIR, `complete_scan_${Date.now()}.json`);
    fs.writeFileSync(filename, JSON.stringify(report, null, 2));
    console.log(`[Report] Saved complete analysis to: ${filename}`);

    res.json({ 
      ok: true, 
      plugins: analysisResults,
      summary: report.summary,
      wordpress: report.wordpress,
      api_mode: apiKey ? "premium" : "free",
      report_file: path.basename(filename)
    });
  });

  proc.on("error", (error) => {
    console.error("[WPScan] Process error:", error);
    res.json({ ok: false, error: `WPScan failed: ${error.message}` });
  });
});

/* ============================================================
   INDIVIDUAL LAYER ENDPOINTS (for manual testing)
============================================================ */
app.get("/cve/analyze", async (req, res) => {
  const { slug, version } = req.query;
  
  if (!slug || !version) {
    return res.status(400).json({ error: "Missing slug or version parameters" });
  }

  console.log(`[Manual Analysis] Requested for ${slug} v${version}`);
  
  try {
    const result = await analyzePluginWithLayers(slug, version);
    res.json({ ok: true, analysis: result });
  } catch (error) {
    res.json({ ok: false, error: error.message });
  }
});

// Keep your existing individual layer endpoints for backward compatibility
app.get("/cve/layer1", async (req, res) => {
  const { slug, version } = req.query;
  if (!slug || !version) return res.json({ hit: false, error: "Missing params" });
  
  const result = await checkLayer1(slug, version);
  res.json(result);
});

app.get("/cve/layer2", async (req, res) => {
  const { slug, version } = req.query;
  if (!slug || !version) return res.json({ hit: false, error: "Missing params" });
  
  const result = await checkLayer2(slug, version);
  res.json(result);
});

app.get("/cve/layer3", async (req, res) => {
  const { slug, version } = req.query;
  if (!slug || !version) return res.json({ hit: false, error: "Missing params" });
  
  const result = await checkLayer3(slug, version);
  res.json(result);
});

app.get("/analyze/url", async (req, res) => {
  const { url } = req.query;
  if (!url) return res.json({ success: false, error: "Missing URL" });
  console.log(`[AI URL] Analyzing ${url}`);
  try {
    const ws = new WebSocket("ws://192.168.40.130:9876");
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
        const response = JSON.parse(msg.toString());
        if (response.type === "progress") progress.push(response.message);
        else if (response.type === "response") {
          clearTimeout(timeout);
          ws.close();
          resolve(res.json({ success: true, url, analysis: response.cves || [], raw_findings: response.raw || "", progress }));
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

// WebSocket upgrade handler - only destroy if you don't need WebSocket server functionality
server.on("upgrade", (req, socket, head) => {
  socket.destroy();
});