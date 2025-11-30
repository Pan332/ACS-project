import fetch from 'node-fetch';

const targetUrl = 'http://192.168.1.20:31337';
const apiKey = 'YOUR_API_KEY_HERE'; // Replace if testing with premium

const testEndpoint = async () => {
  try {
    console.log(`[TEST] Calling /plugins endpoint with URL: ${targetUrl}`);
    
    const endpoint = apiKey 
      ? `http://localhost:4000/plugins?url=${encodeURIComponent(targetUrl)}&apiKey=${encodeURIComponent(apiKey)}`
      : `http://localhost:4000/plugins?url=${encodeURIComponent(targetUrl)}`;
    
    console.log(`[TEST] Endpoint: ${endpoint}`);
    
    const response = await fetch(endpoint);
    const data = await response.json();
    
    console.log('\n=== RESPONSE STRUCTURE ===');
    console.log(`ok: ${data.ok}`);
    console.log(`status: ${data.status}`);
    console.log(`found: ${data.found}`);
    console.log(`plugins length: ${data.plugins?.length || 0}`);
    console.log(`wordpress detected: ${data.wordpress?.detected || false}`);
    
    if (data.plugins && data.plugins.length > 0) {
      console.log('\n=== FIRST PLUGIN ===');
      console.log(JSON.stringify(data.plugins[0], null, 2));
    }
    
    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
      console.log('\n=== VULNERABILITIES ===');
      console.log(`Found ${data.vulnerabilities.length} vulnerable plugins`);
      data.vulnerabilities.forEach(v => {
        console.log(`  - ${v.plugin} v${v.version}: ${v.findings.length} findings`);
        v.findings.forEach(f => {
          console.log(`    * ${f.cve} (${f.severity}): ${f.title}`);
        });
      });
    }
    
    console.log('\n=== FULL RESPONSE SAVED ===');
    console.log(JSON.stringify(data, null, 2).substring(0, 500) + '...');
    
  } catch (error) {
    console.error('[ERROR]', error.message);
  }
};

testEndpoint();
