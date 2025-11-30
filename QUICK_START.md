# 🚀 Quick Start Guide - WordPress Vulnerability Scanner

## One-Minute Setup

### Terminal 1: Backend
```powershell
cd "c:\Users\WIN11 64BIT\Downloads\ACS project\backend"
node server.js
```
✅ Server running on http://localhost:4000

### Terminal 2: Frontend
```powershell
cd "c:\Users\WIN11 64BIT\Downloads\ACS project\frontend"
npm start
```
✅ Browser opens http://localhost:3000

## Two-Minute First Scan

1. **Enter URL**: `http://192.168.1.20:31337`
2. **Click**: SCAN PLUGINS (FREE)
3. **Wait**: 15-30 seconds for completion
4. **See**: Plugin list with vulnerability indicators
5. **Click**: ANALYZE on any plugin for CVE details

## What You'll See

### Clean Plugin
```
wordpress-seo v19.0
v19.0 (blue)
Source: 🔑 Premium Database
100% confidence
[ANALYZE] (blue button)
```

### Vulnerable Plugin ✨ NEW
```
🚨 social-warfare v3.5.2
v3.5.2 (blue)
Source: 🔑 Premium Database
80% confidence
⚠️ VULNERABLE - Click ANALYZE for details  ← NEW!
[ANALYZE] (RED button)  ← NEW!
```

## Features

| Feature | Status | What It Does |
|---------|--------|-------------|
| Plugin Detection | ✅ | Finds WordPress plugins on target |
| Vulnerability Scanning | ✅ | Identifies known CVEs |
| 3-Layer Analysis | ✅ | Local rules → APIs → AI |
| FFUF Fuzzing | ✅ | Discovers hidden plugins |
| Report Saving | ✅ | JSON files in backend/scans/ |
| Free Mode | ✅ | No API key needed |
| Premium Mode | ✅ | Requires WPScan API key |
| Plugin Visualization | ✅ | RED for vulnerable, normal for clean |
| CVE Details | ✅ | Click ANALYZE to see details |

## Files Modified

### backend/server.js
- Line 120-200: Updated response generation
- Added `ok: true`, `plugins: []`, `found: boolean`
- Kept all detailed vulnerability data

### frontend/src/App.js
- Line 520-620: Enhanced plugin rendering
- Added red highlighting for vulnerable plugins
- Added warning message and icon

## What Changed

### Before
```javascript
// Response missing 'ok' field
response.status = "success"
response.plugins = undefined  // ❌
```

### After
```javascript
// Response has frontend compatibility fields
response.ok = true  // ✅
response.found = true/false  // ✅
response.plugins = [...]  // ✅
response.vulnerabilities = [...]  // ✅
```

### Before
```jsx
// All plugins looked the same
<div>{p.slug} v{p.version}</div>
```

### After
```jsx
// Vulnerable plugins highlighted
🚨 social-warfare v3.5.2  ← Red text
⚠️ VULNERABLE - Click ANALYZE for details
[ANALYZE]  ← Red button
```

## Keyboard Shortcuts

| Action | Keys |
|--------|------|
| Scan | Enter (in URL field) |
| Refresh | F5 or Ctrl+R |
| Console | F12 → Console tab |

## Troubleshooting

**"Cannot connect to the remote server"**
- Backend not running? → Run `node server.js`
- Port 4000 blocked? → Restart Windows Firewall
- Kill stuck processes: `Get-Process node | Stop-Process`

**"No plugins found"**
- WordPress not running on target URL? → Verify URL
- Free mode limitations? → Add WPScan API key
- Docker not running? → Start Docker Desktop

**"Slow scan"**
- First scan is slower (Docker pulls image)
- Free mode is slower than premium
- AI analysis (Layer 3) intentionally slow

## API Endpoints

```
GET /plugins?url=...&apiKey=...
  → Returns: ok, plugins[], vulnerabilities[], wordpress_core

GET /fuzz?url=...
  → Returns: FFUF discovered plugins

GET /cve/layer1?slug=...&version=...
  → Returns: Layer 1 analysis (fast, local rules)

GET /cve/layer2?slug=...&version=...
  → Returns: Layer 2 analysis (APIs)

GET /cve/layer3?slug=...&version=...
  → Returns: Layer 3 analysis (AI WebSocket)

GET /health
  → Returns: {"status": "ok"}
```

## Report Locations

Scan reports saved to: `backend/scans/`

Files:
- `scan_premium_*.json` - Premium mode scans (with WPScan API key)
- `scan_free_*.json` - Free mode scans
- `ffuf_scan_*.json` - FFUF discovery results

Format: `scan_{mode}_{timestamp}.json`

## Example Report Structure

```json
{
  "ok": true,
  "found": true,
  "plugins": [
    {
      "slug": "social-warfare",
      "version": "3.5.2",
      "vulnerable": true
    }
  ],
  "vulnerabilities": [
    {
      "plugin": "social-warfare",
      "version": "3.5.2",
      "findings": [
        {
          "cve": "CVE-2019-9978",
          "severity": "High (RCE)",
          "source": "Layer 1 (Local)"
        }
      ]
    }
  ]
}
```

## Performance

- **Plugin Detection**: 10-20 seconds
- **Vulnerability Analysis**: +5-15 seconds
- **WordPress Scan**: Total 15-30 seconds
- **Per Plugin Analysis**: 1-3 seconds

## Getting WPScan API Key (Optional)

1. Visit: https://wpscan.com/register
2. Create free account
3. Get API key from account page
4. Paste into frontend: WPScan API Configuration
5. Scan results improve significantly

Benefits of premium API:
- More comprehensive plugin database
- Faster scanning
- More accurate results
- Aggressive enumeration

## Test Site

Default test URL: `http://192.168.1.20:31337`

Expected results:
- 6 plugins detected
- 2 vulnerable plugins found
- 57 WordPress core vulnerabilities
- Full scan in ~25 seconds

## Next Steps

1. ✅ Scan your own WordPress sites
2. ✅ Review vulnerability reports
3. ✅ Click ANALYZE on vulnerable plugins
4. ✅ Update or remove vulnerable plugins
5. ✅ Re-scan to verify fixes

## Support

- Check backend logs: Terminal where `node server.js` runs
- Check frontend logs: Browser F12 → Console
- Check reports: `backend/scans/` JSON files
- Read detailed docs: IMPLEMENTATION_SUMMARY.md

---

**Fully Integrated & Ready to Use! 🎉**

Start scanning now:
```powershell
# Terminal 1
node "c:\Users\WIN11 64BIT\Downloads\ACS project\backend\server.js"

# Terminal 2
cd "c:\Users\WIN11 64BIT\Downloads\ACS project\frontend" && npm start
```

Then open http://localhost:3000 and scan your WordPress sites! 🛡️
