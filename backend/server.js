// server.js — ESM, Docker-Ready, Improved Version
import crypto from "crypto";
import fetch from "node-fetch";
import express from "express";
import cors from "cors";
import { spawn } from "child_process";
import WebSocket from "ws";

const app = express();
app.use(cors());
app.use(express.json());

// ---------- CONFIG ----------
const PORT = Number(process.env.PORT || 4000);
const WPSCAN_DOCKER_IMAGE = process.env.WPSCAN_DOCKER_IMAGE || "wpscanteam/wpscan";
const WPSCAN_USE_NETWORK_HOST = process.env.WPSCAN_NETWORK_HOST === "true";
const WPSCAN_API_KEY = process.env.WPSCAN_API_KEY || process.env.WPSCAN_API_TOKEN || "";
const MCP_WS = process.env.MCP_WS || "ws://192.168.40.130:9876";
const MCP_HTTP = process.env.MCP_HTTP || "http://192.168.40.130:9877";
const MCP_POLL_INTERVAL = Number(process.env.MCP_POLL_INTERVAL || 3000);
const MCP_POLL_MAX = Number(process.env.MCP_POLL_MAX || 60);
const WPSCAN_TIMEOUT_MS = Number(process.env.WPSCAN_TIMEOUT_MS || 1_200_000);

// ---------- HASH DB ----------
const HASH_DB = {
  "contact-form-7": {
    readme_hash: "45f9f9c04d0b5f7950a0ee30b7d2608d182cbfcb20b7cc15448a8fa2f1187773",
    version: "5.1"
  }
};

// ---------- HELPERS ----------
const safeJsonParse = (txt) => {
  try {
    return JSON.parse(txt);
  } catch {
    return null;
  }
};

const dockerHost = (url) => {
  try {
    const u = new URL(url);
    if (["localhost", "127.0.0.1"].includes(u.hostname)) {
      u.hostname = "host.docker.internal";
      return u.toString();
    }
  } catch {}
  return url;
};

const extractSlug = (url) => {
  const m = url.match(/\/wp-content\/plugins\/([^\/?#]+)/i);
  return m ? m[1] : null;
};

/**
 * Try to identify a plugin's version by fetching its readme and comparing hashes or parsing content.
 * Returns an object { slug, version, source }.
 */
async function identifyPluginFromSlug(siteUrl, slug) {
  const readmeUrl = `${siteUrl.replace(/\/$/, "")}/wp-content/plugins/${slug}/readme.txt`;
  try {
    const resp = await fetch(readmeUrl, { timeout: 10000 });
    if (!resp.ok) {
      return { slug, version: null, source: "detected" };
    }
    const text = await resp.text();
    const hash = crypto.createHash("sha256").update(text).digest("hex");
    const matchEntry = Object.entries(HASH_DB).find(([name, info]) => info.readme_hash === hash);
    if (matchEntry) {
      const [name, info] = matchEntry;
      return { slug: name, version: info.version, source: "hash-db" };
    }
    // If not in hash DB, look for a "Stable tag: X.Y" or similar version hint in readme
    const stableMatch = text.match(/Stable tag:\s*([0-9.]+)/i);
    if (stableMatch) {
      return { slug, version: stableMatch[1], source: "readme" };
    }
    return { slug, version: null, source: "detected" };
  } catch {
    return { slug, version: null, source: "detected" };
  }
}

// ---------- WPScan Docker Runner ----------
async function runWpscan(url) {
  const dockerArgs = ["run", "--rm"];
  if (WPSCAN_USE_NETWORK_HOST) dockerArgs.push("--network", "host");
  if (WPSCAN_API_KEY) dockerArgs.push("-e", `WPSCAN_API_TOKEN=${WPSCAN_API_KEY}`);
  dockerArgs.push(
    WPSCAN_DOCKER_IMAGE,
    "--url", url,
    "--enumerate", "p",
    "--format", "json",
    "--no-banner",
    "--plugins-detection", "mixed"
  );

  return new Promise((resolve) => {
    const proc = spawn("docker", dockerArgs, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    const timeout = setTimeout(() => proc.kill("SIGKILL"), WPSCAN_TIMEOUT_MS);
    proc.stdout.on("data", (d) => stdout += d);
    proc.stderr.on("data", (d) => stderr += d);
    proc.on("close", (code) => {
      clearTimeout(timeout);
      resolve({ ok: code === 0, stdout, stderr, code });
    });
    proc.on("error", (err) => {
      clearTimeout(timeout);
      resolve({ ok: false, error: err.message });
    });
  });
}

// ---------- ENDPOINTS ----------

// Plugin enumeration endpoint
app.get("/plugins", async (req, res) => {
  const { url } = req.query;
  if (!url) {
    return res.status(400).json({ error: "Missing ?url=" });
  }
  if (!/^https?:\/\//i.test(url)) {
    return res.status(400).json({ error: "URL must start with http:// or https://" });
  }

  const result = await runWpscan(dockerHost(url));
  if (!result.ok) {
    return res.json({ found: false, error: result.error || result.stderr });
  }

  const data = safeJsonParse(result.stdout);
  const plugins = data?.plugins;
  if (!plugins || Object.keys(plugins).length === 0) {
    return res.json({ found: false });
  }

  // Return all detected plugins with slug and version
  const pluginList = Object.values(plugins).map(pl => ({
    slug: pl.slug,
    version: pl.version?.number || pl.version,
    // Optionally include vulnerability count or CVEs:
    vulnerabilities: pl.vulnerabilities ? pl.vulnerabilities.map(v => v.references?.cve?.[0] || v.title) : []
  }));
  return res.json({ found: true, plugins: pluginList });
});

// Readme hash database lookup endpoint
app.get("/hashdb", async (req, res) => {
  const { url } = req.query;
  if (!url) {
    return res.status(400).json({ error: "Missing ?url=" });
  }
  const slug = extractSlug(url) || "unknown";
  const info = await identifyPluginFromSlug(url, slug);
  if (info.version) {
    // Found a match or determined a version
    return res.json({ found: true, slug: info.slug, version: info.version, source: info.source });
  } else {
    return res.json({ found: false, slug: info.slug, message: "No match or version could not be determined" });
  }
});

// Layer 1: Known CVE mappings (rule-based)
const KNOWN_CVES = { "contact-form-7": { "5.1": "CVE-2024-10101" } };
app.get("/cve/layer1", (req, res) => {
  const { slug, version } = req.query;
  const cve = slug && version ? (KNOWN_CVES[slug]?.[version] || null) : null;
  return res.json({ hit: !!cve, cve, source: "rule-based" });
});

// Layer 2: Public CVE search (CIRCL)
app.get("/cve/layer2", async (req, res) => {
  const { slug } = req.query;
  if (!slug) {
    return res.status(400).json({ error: "Missing slug" });
  }
  try {
    const resp = await fetch(`https://cve.circl.lu/api/search/${encodeURIComponent(slug)}`, { timeout: 10000 });
    const data = await resp.json();
    const cve = Array.isArray(data) && data.length > 0 ? data[0].id : null;
    return res.json({ hit: !!cve, cve, source: "circl-api" });
  } catch (err) {
    return res.json({ hit: false, error: err.message, source: "circl-api" });
  }
});

// Layer 3: Advanced scan via MCP (WebSocket + Polling)
app.get("/cve/layer3", async (req, res) => {
  const { slug, version } = req.query;
  if (!slug || !version) {
    return res.status(400).json({ error: "Missing slug/version" });
  }
  let ws;
  try {
    ws = new WebSocket(MCP_WS);
    // Wait for WS connection open
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("WS timeout")), 5000);
      ws.on("open", () => { clearTimeout(t); resolve(); });
      ws.on("error", reject);
    });

    const requestId = Date.now().toString();
    ws.send(JSON.stringify({ 
      type: "request", 
      request_id: requestId, 
      tool: "cai.redteam.scan", 
      params: { slug, version } 
    }));

    // Wait for immediate response on WS (up to 10s)
    const msg = await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("Reply timeout")), 10000);
      ws.once("message", (m) => { clearTimeout(t); resolve(m); });
    });
    const data = safeJsonParse(msg);
    ws.close();

    if (data?.cves?.length > 0) {
      const c = data.cves[0];
      return res.json({ hit: true, cve: c.id, poc: c.poc, bounty: c.bounty, source: "mcp" });
    }

    // No immediate result, fall back to polling the HTTP endpoint
    for (let i = 0; i < MCP_POLL_MAX; i++) {
      await new Promise(r => setTimeout(r, MCP_POLL_INTERVAL));
      try {
        const pollResp = await fetch(`${MCP_HTTP}/result/${requestId}`, { timeout: 5000 });
        if (pollResp.ok) {
          const result = await pollResp.json();
          if (result?.cves?.length > 0) {
            const c = result.cves[0];
            return res.json({ hit: true, cve: c.id, poc: c.poc, bounty: c.bounty, source: "mcp-poll" });
          }
        }
      } catch {
        // ignore errors during polling
      }
    }

    // If we reach here, no CVE found via MCP
    return res.json({ hit: false, error: "MCP timeout" });
  } catch (err) {
    if (ws) ws.close();
    return res.json({ hit: false, error: err.message });
  }
});

// Full scan endpoint orchestrating all steps
app.get("/scan", async (req, res) => {
  const { url } = req.query;
  if (!url) {
    return res.status(400).json({ error: "Missing ?url=" });
  }

  const report = { time: new Date().toISOString(), url: url };

  // 1. WPScan to detect plugin(s) and version(s)
  const scanResult = await runWpscan(dockerHost(url));
  if (scanResult.ok) {
    const data = safeJsonParse(scanResult.stdout);
    const plugins = data?.plugins;
    if (plugins && Object.keys(plugins).length > 0) {
      const pluginArray = Object.values(plugins);
      // Prefer a plugin that has known vulnerabilities in the WPScan report
      let targetPlugin = pluginArray.find(pl => pl.vulnerabilities && pl.vulnerabilities.length > 0);
      if (!targetPlugin) {
        targetPlugin = pluginArray[0];
      }
      report.plugin = { 
        slug: targetPlugin.slug, 
        version: targetPlugin.version?.number || targetPlugin.version, 
        source: "wpscan" 
      };
      // If WPScan already reported vulnerabilities (requires API token), use them
      if (targetPlugin.vulnerabilities && targetPlugin.vulnerabilities.length > 0) {
        const vuln = targetPlugin.vulnerabilities[0];
        const cveId = vuln.references?.cve?.[0] || null;
        report.cve = { cve: cveId, title: vuln.title, source: "wpscan-db" };
        return res.json(report);  // return early with this data
      }
    }
  }

  // 2. Fallback detection via HTML source and hash DB if no plugin found by WPScan
  if (!report.plugin) {
    try {
      const resp = await fetch(url, { timeout: 10000 });
      const html = await resp.text();
      const slugMatch = html.match(/\/wp-content\/plugins\/([^\/]+)\//i);
      if (slugMatch) {
        const slug = slugMatch[1];
        const info = await identifyPluginFromSlug(url, slug);
        report.plugin = { slug: info.slug, version: info.version, source: info.source };
      }
    } catch {
      // Could not fetch site or no plugin identified in HTML
    }
  }

  // 3. CVE lookup layers if a plugin was identified
  if (report.plugin) {
    const { slug, version } = report.plugin;
    if (version) {
      // Layer 1: check hardcoded known CVEs
      const knownCve = KNOWN_CVES[slug]?.[version];
      if (knownCve) {
        report.cve = { cve: knownCve, source: "rule-based", layer: 1 };
        return res.json(report);
      }
      // Layer 3: advanced scan via MCP
      const mcpRes = await fetch(`http://localhost:${PORT}/cve/layer3?slug=${slug}&version=${version}`).then(r => r.json());
      if (mcpRes.hit) {
        report.cve = { cve: mcpRes.cve, poc: mcpRes.poc, bounty: mcpRes.bounty, source: mcpRes.source, layer: 3 };
      } else {
        // Layer 2: public CVE search as fallback
        const circlRes = await fetch(`http://localhost:${PORT}/cve/layer2?slug=${slug}`).then(r => r.json());
        if (circlRes.hit) {
          report.cve = { cve: circlRes.cve, source: circlRes.source, layer: 2 };
        }
      }
    } else {
      // Unknown version: skip layer1 and layer3, go straight to layer2 search
      const circlRes = await fetch(`http://localhost:${PORT}/cve/layer2?slug=${slug}`).then(r => r.json());
      if (circlRes.hit) {
        report.cve = { cve: circlRes.cve, source: circlRes.source, layer: 2 };
      }
    }
  }

  return res.json(report);
});

// Report formatting endpoint
app.get("/report", (req, res) => {
  const { slug, version, cve, source, layer, poc, bounty } = req.query;
  return res.json({ report: `
WPGuardian Pro Report
────────────────────
Time: ${new Date().toLocaleString()}
Plugin: ${slug || "N/A"}
Version: ${version || "N/A"}
CVE: ${cve || "None"}
Source: ${source || "N/A"}
Layer: ${layer || "N/A"}
PoC: ${poc ? "Yes" : "No"}
Bounty: ${bounty || "Unknown"}
  `.trim() });
});

// Start the server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`WPGuardian → http://0.0.0.0:${PORT}`);
});
