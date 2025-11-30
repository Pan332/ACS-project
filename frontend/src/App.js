// src/App.js
import React, { useState, useEffect } from "react";


function App() {
  const [url, setUrl] = useState("");
  const [wpscanApiKey, setWpscanApiKey] = useState("");
  const [scanStatus, setScanStatus] = useState("idle");
  const [pluginsFound, setPluginsFound] = useState([]);
  const [selectedPlugin, setSelectedPlugin] = useState(null);
  const [analysisMode, setAnalysisMode] = useState("plugins");
  const [apiMode, setApiMode] = useState("free");
  const [fuzzResults, setFuzzResults] = useState([]);
  const [fuzzStatus, setFuzzStatus] = useState("idle");

  // Analysis State
  const [layerStatus, setLayerStatus] = useState("");
  const [cveResult, setCveResult] = useState(null);
  const [aiReport, setAiReport] = useState("");
  // New: All scan vulnerabilities block
  const [scanVulnerabilities, setScanVulnerabilities] = useState([]);

  const API_BASE = "http://localhost:4000";

  const callApi = async (endpoint) => {
    try {
      const res = await fetch(`${API_BASE}${endpoint}`);
      return await res.json();
    } catch (e) {
      console.error(e);
      return { error: "Connection Failed" };
    }
  };

  // Save API key to localStorage
  const saveApiKey = (key) => {
    setWpscanApiKey(key);
    if (key) {
      localStorage.setItem("wpscan_api_key", key);
      setApiMode("premium");
    } else {
      localStorage.removeItem("wpscan_api_key");
      setApiMode("free");
    }
  };

  // Load previous scan results
  const loadPreviousScan = () => {
    const saved = localStorage.getItem("last_scan_results");
    if (saved) {
      try {
        const data = JSON.parse(saved);
        if (data.url) setUrl(data.url);
        setPluginsFound(data.plugins || []);
        setScanVulnerabilities(data.vulnerabilities || []);
        setCveResult(data); // Patch: set cveResult to the whole scan object
        setLayerStatus(
          `📁 Loaded previous scan from ${new Date(
            data.timestamp
          ).toLocaleString()}`
        );
      } catch (e) {
        console.error("Failed to load previous scan:", e);
      }
    } else {
      setLayerStatus("No previous scan found");
    }
  };

  // Load API key from localStorage on component mount
  useEffect(() => {
    const savedKey = localStorage.getItem("wpscan_api_key");
    if (savedKey) {
      setWpscanApiKey(savedKey);
      setApiMode("premium");
    }
    loadPreviousScan();
  }, []);

  // Step 1: Scan Target for Plugins
  const scanTarget = async () => {
    if (!url || url.trim() === "") {
      setLayerStatus("❌ Please enter a target URL first.");
      return;
    }

    setScanStatus("scanning_target");
    setPluginsFound([]);
    setSelectedPlugin(null);
    setCveResult(null);
    setAiReport("");
    setFuzzResults([]);

    // Build API URL with API key if provided
    const apiUrl = wpscanApiKey
      ? `/plugins?url=${encodeURIComponent(url)}&apiKey=${encodeURIComponent(
          wpscanApiKey
        )}`
      : `/plugins?url=${encodeURIComponent(url)}`;

    setLayerStatus(`🔍 Scanning ${url} with ${apiMode} mode...`);

    // 1. Run WPScan
    const data = await callApi(apiUrl);

    if (data.error) {
      setLayerStatus(`❌ WPScan Error: ${data.error}`);
      if (String(data.error).toLowerCase().includes("api key")) {
        saveApiKey("");
      }
      setScanStatus("error");
      return;
    }

    if (data.ok && Array.isArray(data.plugins) && data.plugins.length > 0) {
      setPluginsFound(data.plugins);
      setScanVulnerabilities(data.vulnerabilities || []);
      setScanStatus("plugins_found");
      setLayerStatus(
        `✅ Found ${data.plugins.length} plugins using ${
          data.api_mode || "free"
        } mode`
      );

      // Save to localStorage for persistence
      try {
        localStorage.setItem(
          "last_scan_results",
          JSON.stringify({
            url: url,
            plugins: data.plugins,
            vulnerabilities: data.vulnerabilities || [],
            timestamp: new Date().toISOString(),
            wordpress: data.wordpress,
          })
        );
      } catch (e) {
        console.warn("Failed saving scan results:", e);
      }
    } else if (data.ok) {
      setPluginsFound([]);
      setScanStatus("no_plugins");

      if (data.wordpress) {
        setLayerStatus(
          `ℹ️ No plugins detected, but found WordPress ${data.wordpress.wordpress_version} with ${(
            data.wordpress.wordpress_vulnerabilities || []
          ).length} vulnerabilities`
        );
      } else {
        setLayerStatus(data.warning || "❌ No plugins detected");
      }
    } else {
      setScanStatus("error");
      setLayerStatus(`❌ Scan error: ${data.error || "Unknown error"}`);
    }
  };

  // FFUF Directory Enumeration
  const runFuzzScan = async () => {
    if (!url || url.trim() === "") {
      setLayerStatus("❌ Please enter a target URL first.");
      return;
    }

    setFuzzStatus("scanning");
    setFuzzResults([]);
    setLayerStatus("🔍 FFUF: Scanning for hidden plugins...");

    const result = await callApi(`/fuzz?url=${encodeURIComponent(url)}`);

    if (result.ok && Array.isArray(result.data)) {
      setFuzzResults(result.data);
      setFuzzStatus("completed");
      setLayerStatus(`✅ FFUF: Found ${result.data.length} potential plugins`);
    } else {
      setFuzzStatus("error");
      setLayerStatus(`❌ FFUF Error: ${result.error || "Unknown error"}`);
    }
  };

  // Direct URL Analysis
  const analyzeDirectUrl = async () => {
    if (!url || url.trim() === "") {
      setLayerStatus("❌ Please enter a target URL first.");
      return;
    }

    setScanStatus("analyzing_direct");
    setPluginsFound([]);
    setSelectedPlugin(null);
    setCveResult(null);
    setAiReport("");
    setFuzzResults([]);
    setLayerStatus("🚀 Starting comprehensive WordPress analysis...");

    const result = await callApi(
      `/analyze/url?url=${encodeURIComponent(url)}`
    );

    if (result.success) {
      setCveResult(result);
      setLayerStatus(
        `✅ Comprehensive analysis completed! Found ${(
          result.analysis || []
        ).length} security issues.`
      );
      setAiReport(
        `COMPREHENSIVE SECURITY REPORT:\n\nTarget: ${url}\nIssues Found: ${
          (result.analysis || []).length
        }\nAnalysis Time: ${result.analysis_time || "N/A"}\n\n${(
          result.analysis || []
        )
          .map(
            (issue, i) =>
              `${i + 1}. ${issue.cve || issue.id}: ${issue.title} (${
                issue.severity || "N/A"
              })`
          )
          .join("\n")}`
      );
    } else {
      setLayerStatus(`❌ Analysis failed: ${result.error || "Unknown error"}`);
    }
  };

  // Step 2: Analyze Specific Plugin (The 3 Layers)
  const analyzePlugin = async (plugin) => {
    setSelectedPlugin(plugin);
    setScanStatus("analyzing_plugin");
    setCveResult(null);
    setAiReport("");

    const slug = plugin.slug;
    let version = plugin.version;

    // Layer 0: If version is missing, try Hash DB
    if (!version) {
      setLayerStatus("⚠️ Version missing. Attempting Hash DB...");
      const hashRes = await callApi(
        `/hashdb?url=${encodeURIComponent(url)}&slug=${slug}`
      );
      if (hashRes.found) {
        version = hashRes.version;
        setLayerStatus(`✅ Hash DB found version: ${version}`);
      } else {
        setLayerStatus("❌ Could not determine version. Aborting.");
        setScanStatus("idle");
        return;
      }
    }

    // Layer 1: Rule-Based
    setLayerStatus("Layer 1: Checking Local Rules...");
    const l1 = await callApi(`/cve/layer1?slug=${slug}&version=${version}`);
    if (l1.hit) {
      finishAnalysis(l1, "Layer 1 (Local Rule)");
      return;
    }

    // Layer 2: API (CIRCL/WPScan)
    setLayerStatus("Layer 2: Querying Global APIs...");
    const l2 = await callApi(`/cve/layer2?slug=${slug}&version=${version}`);
    if (l2.hit) {
      finishAnalysis(l2, "Layer 2 (Public API)");
      return;
    }

    // Layer 3: AI Agent
    setLayerStatus("Layer 3: Activating AI Agent (This takes time)...");
    const l3 = await callApi(`/cve/layer3?slug=${slug}&version=${version}`);
    if (l3.hit) {
      finishAnalysis(l3, "Layer 3 (AI Agent)");
    } else {
      setLayerStatus("✅ Analysis Complete: No CVEs found.");
      setScanStatus("idle");
    }
  };

  // Analyze FFUF-discovered plugin
  const analyzeFuzzResult = async (fuzzItem) => {
    setSelectedPlugin(fuzzItem);
    setScanStatus("analyzing_plugin");
    setCveResult(null);
    setAiReport("");

    const slug = fuzzItem.slug;
    const version = fuzzItem.version;

    setLayerStatus(`🔍 Analyzing FFUF discovery: ${slug} v${version}`);

    // Use the complete analysis endpoint
    const analysis = await callApi(`/cve/analyze?slug=${slug}&version=${version}`);

    if (analysis.ok) {
      const result = analysis.analysis;
      if (result.final_result?.hit) {
        finishAnalysis(result.final_result, result.final_result.source);
      } else {
        setLayerStatus("✅ Analysis Complete: No CVEs found.");
        setScanStatus("idle");
      }
    } else {
      setLayerStatus(`❌ Analysis failed: ${analysis.error}`);
      setScanStatus("idle");
    }
  };

  const finishAnalysis = (result, source) => {
    setCveResult(result);
    setLayerStatus(`🚨 VULNERABILITY FOUND via ${source}`);
    setAiReport(
      `GENERATED REPORT:\nCVE: ${result.cve || result.cves?.[0]?.cve}\nSeverity: HIGH\nSource: ${source}\n\nRemediation: Update ${
        selectedPlugin?.slug || "the plugin"
      } immediately.`
    );
    setScanStatus("analysis_complete");
  };

  return (
    <div
      style={{
        fontFamily: "monospace",
        padding: "20px",
        background: "#0d1117",
        color: "#58a6ff",
        minHeight: "100vh",
      }}
    >
      <h1>🛡️ WPGuardian v3</h1>

      {/* WPScan API Key Section */}
      <div
        style={{
          marginBottom: "15px",
          padding: "15px",
          background: "#161b22",
          border: "1px solid #30363d",
          borderRadius: "5px",
        }}
      >
        <h3 style={{ margin: "0 0 10px 0", color: "#58a6ff" }}>
          WPScan API Configuration
        </h3>
        <div
          style={{
            display: "flex",
            gap: "10px",
            alignItems: "center",
            flexWrap: "wrap",
          }}
        >
          <div style={{ flex: 1 }}>
            <input
              type="password"
              value={wpscanApiKey}
              onChange={(e) => saveApiKey(e.target.value)}
              placeholder="Enter WPScan API Key (optional - for premium features)"
              style={{
                width: "100%",
                padding: "8px",
                background: "#0d1117",
                border: `1px solid ${
                  apiMode === "premium" ? "#3fb950" : "#30363d"
                }`,
                color: "white",
                borderRadius: "3px",
              }}
            />
          </div>
          <div style={{ display: "flex", gap: "5px", alignItems: "center" }}>
            <span
              style={{
                padding: "4px 8px",
                background: apiMode === "premium" ? "#238636" : "#6e7681",
                color: "white",
                borderRadius: "3px",
                fontSize: "12px",
              }}
            >
              {apiMode === "premium" ? "🔑 PREMIUM" : "🆓 FREE"}
            </span>
            {wpscanApiKey && (
              <button
                onClick={() => saveApiKey("")}
                style={{
                  padding: "4px 8px",
                  background: "#da3633",
                  color: "white",
                  border: "none",
                  cursor: "pointer",
                  borderRadius: "3px",
                  fontSize: "12px",
                }}
              >
                Clear
              </button>
            )}
          </div>
        </div>
        <div style={{ marginTop: "8px", fontSize: "12px", color: "#8b949e" }}>
          {apiMode === "premium" ? (
            "✅ Using premium WPScan API - Full vulnerability database access"
          ) : (
            "ℹ️ Using free mode - Limited results. Get API key from: https://wpscan.com/api"
          )}
        </div>
      </div>

      {/* ANALYSIS MODE SELECTOR */}
      <div
        style={{
          marginBottom: "15px",
          padding: "10px",
          background: "#161b22",
          border: "1px solid #30363d",
        }}
      >
        <label style={{ marginRight: "15px" }}>
          <input
            type="radio"
            value="plugins"
            checked={analysisMode === "plugins"}
            onChange={(e) => setAnalysisMode(e.target.value)}
            style={{ marginRight: "5px" }}
          />
          Plugin-by-Plugin Analysis
        </label>
        <label>
          <input
            type="radio"
            value="direct"
            checked={analysisMode === "direct"}
            onChange={(e) => setAnalysisMode(e.target.value)}
            style={{ marginRight: "5px" }}
          />
          Direct AI Analysis
        </label>
      </div>

      {/* INPUT AREA */}
      <div
        style={{
          marginBottom: "20px",
          borderBottom: "1px solid #303d3d",
          paddingBottom: "20px",
        }}
      >
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://target-wordpress-site.com"
          style={{
            width: "300px",
            padding: "10px",
            background: "#0d1117",
            border: "1px solid #30363d",
            color: "white",
            marginRight: "10px",
          }}
        />

        {analysisMode === "plugins" ? (
          <>
            <button
              onClick={scanTarget}
              disabled={scanStatus === "scanning_target"}
              style={{
                padding: "10px 20px",
                background: apiMode === "premium" ? "#da3633" : "#238636",
                color: "white",
                border: "none",
                cursor: "pointer",
                marginRight: "10px",
              }}
            >
              {scanStatus === "scanning_target"
                ? "SCANNING..."
                : `SCAN PLUGINS (${apiMode.toUpperCase()})`}
            </button>

            <button
              onClick={runFuzzScan}
              disabled={fuzzStatus === "scanning"}
              style={{
                padding: "10px 20px",
                background: "#8b5cf6",
                color: "white",
                border: "none",
                cursor: "pointer",
                marginRight: "10px",
              }}
            >
              {fuzzStatus === "scanning" ? "FUZZING..." : "🔍 FFUF SCAN"}
            </button>

            <button
              onClick={loadPreviousScan}
              style={{
                padding: "10px 15px",
                background: "#6e7681",
                color: "white",
                border: "none",
                cursor: "pointer",
              }}
            >
              📁 LOAD PREVIOUS
            </button>
          </>
        ) : (
          <button
            onClick={analyzeDirectUrl}
            disabled={scanStatus === "analyzing_direct"}
            style={{
              padding: "10px 20px",
              background: "#da3633",
              color: "white",
              border: "none",
              cursor: "pointer",
            }}
          >
            {scanStatus === "analyzing_direct" ? "AI ANALYZING..." : "AI FULL ANALYSIS"}
          </button>
        )}
      </div>

      {/* RESULTS GRID */}
      <div style={{ display: "flex", gap: "20px", flexWrap: "wrap" }}>
        {/* LEFT: Plugin List */}
        <div style={{ flex: 1, minWidth: "300px" }}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "10px",
            }}
          >
            <h3 style={{ margin: 0 }}>Detected Plugins</h3>
            {pluginsFound.length > 0 && (
              <span
                style={{
                  fontSize: "12px",
                  color: apiMode === "premium" ? "#3fb950" : "#8b949e",
                  background: apiMode === "premium" ? "#1c532c" : "#30363d",
                  padding: "2px 8px",
                  borderRadius: "3px",
                }}
              >
                {apiMode === "premium" ? "🔑 PREMIUM SCAN" : "🆓 FREE SCAN"}
              </span>
            )}
          </div>

          {pluginsFound.length === 0 && fuzzResults.length === 0 && (
            <div style={{ color: "#8b949e", textAlign: "center", padding: "20px" }}>
              {scanStatus === "scanning_target" ? (
                "Scanning target website..."
              ) : (
                <div>
                  <p>No plugins found yet.</p>
                  {apiMode === "free" && (
                    <div
                      style={{
                        background: "#1c532c",
                        padding: "10px",
                        borderRadius: "5px",
                        marginTop: "10px",
                        border: "1px solid #3fb950",
                      }}
                    >
                      <strong>💡 Pro Tip:</strong> Use a WPScan API key for better plugin detection and vulnerability data.
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {pluginsFound.map((p, i) => (
            <div
              key={i}
              style={{
                padding: "10px",
                border: "1px solid #30363d",
                marginBottom: "10px",
                background: "#161b22",
                borderLeft:
                  p.confidence > 90
                    ? "4px solid #3fb950"
                    : p.confidence > 70
                    ? "4px solid #d29922"
                    : "4px solid #f85149",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <strong style={{ color: p.vulnerable ? "#f85149" : "white" }}>
                  {p.vulnerable && "🚨 "}{p.slug}
                </strong>
                {p.confidence && (
                  <span
                    style={{
                      fontSize: "12px",
                      color: p.confidence > 90 ? "#3fb950" : p.confidence > 70 ? "#d29922" : "#f85149",
                      background: "#30363d",
                      padding: "2px 6px",
                      borderRadius: "3px",
                    }}
                  >
                    {p.confidence}% confidence
                  </span>
                )}
              </div>
              <div style={{ marginLeft: "10px", color: p.version ? "#58a6ff" : "#f85149", fontSize: "14px" }}>
                {p.version ? `v${p.version}` : "Unknown Version"}
              </div>
              <div style={{ fontSize: "12px", color: "#8b949e", marginTop: "5px" }}>
                Source: {p.source === "wpscan_premium" ? "🔑 Premium Database" : p.source === "wpscan_free" ? "🆓 Free Detection" : p.source}
              </div>
              {p.vulnerable && (
                <div style={{ fontSize: "12px", color: "#f85149", marginTop: "5px", fontWeight: "bold" }}>
                  ⚠️ VULNERABLE - Click ANALYZE for details
                </div>
              )}
              <button
                onClick={() => analyzePlugin(p)}
                style={{
                  float: "right",
                  cursor: "pointer",
                  background: p.vulnerable ? "#da3633" : "#1f6feb",
                  color: "white",
                  border: "none",
                  padding: "4px 12px",
                  borderRadius: "3px",
                  marginTop: "5px",
                }}
              >
                ANALYZE
              </button>
            </div>
          ))}

          {/* FFUF Results Section */}
          {fuzzResults.length > 0 && (
            <div style={{ marginTop: "30px" }}>
              <h3 style={{ color: "#8b5cf6", borderBottom: "1px solid #8b5cf6", paddingBottom: "5px" }}>
                🔍 FFUF Discovered Plugins
              </h3>
              {fuzzResults.map((item, i) => (
                <div
                  key={i}
                  style={{
                    padding: "10px",
                    border: "1px solid #8b5cf6",
                    marginBottom: "10px",
                    background: "#1a1a2e",
                    borderRadius: "5px",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <strong style={{ color: "white" }}>{item.slug}</strong>
                    <span
                      style={{
                        fontSize: "12px",
                        color: "#8b5cf6",
                        background: "#2d2b55",
                        padding: "2px 6px",
                        borderRadius: "3px",
                      }}
                    >
                      FFUF Discovery
                    </span>
                  </div>
                  <div style={{ marginLeft: "10px", color: item.version ? "#58a6ff" : "#f85149", fontSize: "14px" }}>
                    {item.version ? `v${item.version}` : "Version Unknown"}
                  </div>
                  {item.analysis && (
                    <div style={{ fontSize: "12px", marginTop: "5px" }}>
                      <span style={{ color: item.analysis.hit ? "#f85149" : "#3fb950" }}>
                        {item.analysis.hit ? "🚨 VULNERABLE" : "✅ CLEAN"}
                      </span>
                    </div>
                  )}
                  <button
                    onClick={() => analyzeFuzzResult(item)}
                    style={{
                      float: "right",
                      cursor: "pointer",
                      background: "#8b5cf6",
                      color: "white",
                      border: "none",
                      padding: "4px 12px",
                      borderRadius: "3px",
                      marginTop: "5px",
                    }}
                  >
                    ANALYZE
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* RIGHT: Analysis Console */}
        <div style={{ flex: 1, minWidth: "300px", border: "1px solid #30363d", padding: "15px", background: "#010409" }}>
          <h3>Analysis Console</h3>
          <p>Status: <span style={{ color: "white" }}>{layerStatus}</span></p>

          {/* New: All vulnerabilities block - Plugins + WordPress Core CVEs */}
          {cveResult && cveResult.plugins && (
            <div style={{ marginTop: "20px", padding: "10px", border: "1px solid #f85149", color: "#f85149", background: "#161b22", maxHeight: "600px", overflowY: "auto" }}>
              <strong>🔎 Complete Scan Results</strong>
              
              {/* PLUGIN VULNERABILITIES SECTION */}
              <div style={{ marginTop: "15px", borderTop: "1px solid #444", paddingTop: "10px" }}>
                {(() => {
                  const vulnerablePlugins = cveResult.plugins.filter(p => {
                    const vuln = (cveResult.vulnerabilities || []).find(v => v.plugin === p.slug);
                    return vuln && vuln.findings && vuln.findings.length > 0;
                  });
                  return vulnerablePlugins.length > 0 ? (
                    <>
                      <strong style={{ color: "#ff6b6b" }}>⚠️ Vulnerable Plugins ({vulnerablePlugins.length})</strong>
                      <ul style={{ color: "#f85149", fontSize: "13px", marginTop: "10px", marginLeft: "15px" }}>
                        {vulnerablePlugins.map((plugin, idx) => {
                          const vuln = (cveResult.vulnerabilities || []).find(v => v.plugin === plugin.slug);
                          return (
                            <li key={idx} style={{ marginBottom: "12px", paddingBottom: "8px", borderBottom: "1px solid #333" }}>
                              <div><b>Plugin:</b> {plugin.slug} <b>v{plugin.version}</b></div>
                              {vuln.findings.map((f, j) => (
                                <div key={j} style={{ marginLeft: "15px", marginTop: "5px", background: "#1a1a2e", padding: "5px", borderRadius: "3px" }}>
                                  <b>CVE:</b> {f.cve} | <b>Severity:</b> {f.severity} <br/>
                                  <b>Title:</b> {f.title}
                                </div>
                              ))}
                            </li>
                          );
                        })}
                      </ul>
                    </>
                  ) : (
                    <div style={{ color: "#3fb950", marginTop: "10px" }}>✅ No plugin vulnerabilities detected</div>
                  );
                })()}
              </div>

              {/* WORDPRESS CORE VULNERABILITIES SECTION */}
              {cveResult.wordpress_core && cveResult.wordpress_core.vulnerabilities && cveResult.wordpress_core.vulnerabilities.length > 0 && (
                <div style={{ marginTop: "20px", borderTop: "1px solid #444", paddingTop: "10px", color: "#58a6ff" }}>
                  <strong style={{ color: "#58a6ff", fontSize: "15px" }}>🔒 WordPress Core CVEs ({cveResult.wordpress_core.vulnerabilities.length})</strong>
                  <div style={{ fontSize: "12px", color: "#8b949e", marginTop: "5px" }}>WordPress v{cveResult.wordpress_core.version} - Status: {cveResult.wordpress_core.status}</div>
                  <ul style={{ color: "#58a6ff", fontSize: "12px", marginTop: "10px", marginLeft: "15px" }}>
                    {cveResult.wordpress_core.vulnerabilities.map((coreVuln, i) => (
                      <li key={i} style={{ marginBottom: "15px", paddingBottom: "10px", borderBottom: "1px solid #222", background: "#0a0e27", padding: "8px", borderRadius: "3px" }}>
                        <div><b>Title:</b> {coreVuln.title}</div>
                        {coreVuln.fixed_in && <div style={{ marginTop: "3px" }}><b>Fixed In:</b> {coreVuln.fixed_in}</div>}
                        {coreVuln.references && coreVuln.references.cve && (
                          <div style={{ marginTop: "3px" }}><b>CVE(s):</b> <span style={{ color: "#f85149" }}>{Array.isArray(coreVuln.references.cve) ? coreVuln.references.cve.join(", ") : coreVuln.references.cve}</span></div>
                        )}
                        {coreVuln.references && coreVuln.references.url && (
                          <div style={{ marginTop: "3px" }}><b>URLs:</b> 
                            {Array.isArray(coreVuln.references.url) ? (
                              <ul style={{ marginLeft: "15px", marginTop: "3px", listStyle: "none", padding: 0 }}>
                                {coreVuln.references.url.map((u, j) => (
                                  <li key={j} style={{ marginBottom: "2px" }}><a href={u} target="_blank" rel="noopener noreferrer" style={{ color: "#58a6ff", textDecoration: "underline", fontSize: "11px" }}>{u.substring(0, 60)}...</a></li>
                                ))}
                              </ul>
                            ) : (
                              <a href={coreVuln.references.url} target="_blank" rel="noopener noreferrer" style={{ color: "#58a6ff", textDecoration: "underline" }}>{coreVuln.references.url}</a>
                            )}
                          </div>
                        )}
                        {coreVuln.references && coreVuln.references.wpvulndb && (
                          <div style={{ marginTop: "3px" }}><b>WPVulnDB:</b> {Array.isArray(coreVuln.references.wpvulndb) ? coreVuln.references.wpvulndb.join(", ") : coreVuln.references.wpvulndb}</div>
                        )}
                        {coreVuln.severity && <div style={{ marginTop: "3px" }}><b>Severity:</b> {coreVuln.severity}</div>}
                        {coreVuln.references && Object.keys(coreVuln.references).filter(k => !['cve','url','wpvulndb'].includes(k)).length > 0 && (
                          <div style={{ marginTop: "5px", fontSize: "11px", color: "#8b949e" }}>
                            {Object.keys(coreVuln.references).filter(k => !['cve','url','wpvulndb'].includes(k)).map((k, j) => (
                              <div key={j}><b>{k}:</b> {Array.isArray(coreVuln.references[k]) ? coreVuln.references[k].join(", ") : String(coreVuln.references[k])}</div>
                            ))}
                          </div>
                        )}
                      </li>
                    ))}
                  </ul>
                  <div style={{ fontSize: "11px", color: "#8b949e", marginTop: "10px", padding: "8px", background: "#0a0e27", borderRadius: "3px" }}>
                    📊 Total CVEs shown: {cveResult.wordpress_core.vulnerabilities.length}
                  </div>
                </div>
              )}
            </div>
          )}

          {fuzzStatus === "scanning" && (
            <div style={{ marginTop: "10px", padding: "10px", background: "#1a1a2e", border: "1px solid #8b5cf6" }}>
              <strong style={{ color: "#8b5cf6" }}>🔍 FFUF Scan in Progress...</strong>
              <p style={{ color: "#8b949e", margin: "5px 0 0 0" }}>Enumerating WordPress plugin directories</p>
            </div>
          )}

          {cveResult && analysisMode === "plugins" && (
            <div style={{ marginTop: "20px", padding: "10px", border: "1px solid #f85149", color: "#f85149" }}>
              <strong>⚠️ CVE DETECTED</strong>
              <p>ID: {cveResult.cve || (cveResult.cves && cveResult.cves[0]?.cve)}</p>
              <pre style={{ color: "#8b949e", whiteSpace: "pre-wrap" }}>{aiReport}</pre>
            </div>
          )}

          {cveResult && analysisMode === "direct" && (
            <div style={{ marginTop: "20px", padding: "10px", border: "1px solid #58a6ff", color: "#58a6ff" }}>
              <strong>📊 COMPREHENSIVE ANALYSIS REPORT</strong>
              <p><strong>Target:</strong> {url}</p>
              <p><strong>Issues Found:</strong> {(cveResult.analysis || []).length}</p>
              <p><strong>Analysis Time:</strong> {cveResult.analysis_time || "N/A"}</p>
              <p><strong>Source:</strong> {cveResult.source}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;