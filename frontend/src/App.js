// src/App.js
import React, { useState, useEffect } from 'react';

function App() {
  const [url, setUrl] = useState("");
  const [status, setStatus] = useState("");
  const [plugin, setPlugin] = useState(null);
  const [cve, setCve] = useState(null);
  const [report, setReport] = useState("");
  const [layer, setLayer] = useState("");

  const callApi = async (path) => {
    const res = await fetch(`http://localhost:4000${path}`);
    return await res.json();
  };

  const startScan = async () => {
  setStatus("Scanning...");
  setPlugin(null); setCve(null); setReport(""); setLayer("");

  setStatus("Step 1: Running WPScan (Mixed Mode)");
  const wpscan = await callApi(`/plugins?url=${encodeURIComponent(url)}`);
  
  let pluginData;
  if (wpscan.found) {
    pluginData = wpscan;
    setPlugin(wpscan);
    setStatus("WPScan found plugin → Using version");
  } else {
    setStatus("WPScan missed → Trying Hash DB");
    const hash = await callApi(`/hashdb?url=${encodeURIComponent(url)}`);
    if (hash.found) {
      pluginData = hash;
      setPlugin(hash);
      setStatus("Hash DB confirmed version");
    } else {
      setStatus("Unknown plugin – Flagged for review");
      return;
    }
  }

  // Now use pluginData instead of plugin
  const version = pluginData.version;
  const slug = pluginData.slug;
  setStatus("Starting 3-Layer CVE Hunt...");

  setLayer("Layer 1: Rule-Based DB");
  const l1 = await callApi(`/cve/layer1?slug=${slug}&version=${version}`);
  if (l1.hit) { setCve(l1); setLayer("Hit! CVE found instantly"); return; }

  setLayer("Layer 2: CIRCL API");
  const l2 = await callApi(`/cve/layer2?slug=${slug}&version=${version}`);
  if (l2.hit) { setCve(l2); setLayer("Official CVE confirmed"); return; }

  setLayer("Layer 3: Your Jailbroken AI");
  const l3 = await callApi(`/cve/layer3?slug=${slug}&version=${version}`);
  setCve(l3);
  setLayer("AI found hidden CVE");
};


  // Auto-refresh report
  useEffect(() => {
    if (cve) {
      const fetchReport = async () => {
      const data = await callApi(`/report?slug=${plugin.slug}&version=${plugin.version}&cve=${cve.cve}&source=${cve.source}&layer=${layer}`);
      setReport(data.report);
    };
      fetchReport();
      const interval = setInterval(fetchReport, 3000);
      return () => clearInterval(interval);
    }
  }, [cve]);

  return (
    <div style={{ fontFamily: 'monospace', padding: '20px', background: '#111', color: '#0f0', minHeight: '100vh' }}>
      <h1>WPGuardian Pro</h1>
      <p><strong>A. User Enters URL:</strong></p>
      <input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com" style={{ width: '400px', padding: '8px' }} />
      <button onClick={startScan} disabled={!url} style={{ marginLeft: '10px', padding: '8px 16px' }}>SCAN</button>
      <hr style={{ borderColor: '#0f0' }}/>

      <p><strong>Status:</strong> {status || "Ready"}</p>
      {plugin && <p><strong>Plugin:</strong> {plugin.slug} v{plugin.version} ({plugin.source})</p>}
      {layer && <p><strong>Layer:</strong> {layer}</p>}
      {cve && <p><strong>CVE:</strong> {cve.cve} ({cve.source})</p>}

      {cve && (
        <div>
          <p><strong>P. Live HTML Report:</strong></p>
          <div style={{ border: '1px solid #0f0', padding: '15px', background: '#222', color: '#0f0' }}>
            <pre>{report || "Loading live report..."}</pre>
          </div>
          <p><em>Q. Auto-refresh every 3s</em></p>
        </div>
      )}
    </div>
  );
}

export default App;