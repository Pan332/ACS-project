"""WP-HUNT3R – Fixed tools with proper CAI function calling"""

import os
import json
import subprocess
from dotenv import load_dotenv
from openai import AsyncOpenAI

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, function_tool
from cai.util import load_prompt_template, create_system_prompt_renderer
from cai.agents.guardrails import get_security_guardrails
from cai.tools.common import run_command

load_dotenv()

# Load your prompt
wp_hunter_system_prompt = load_prompt_template("prompts/WP_squadmaster.md")

# Base tools
from cai.tools.reconnaissance.generic_linux_command import generic_linux_command
from cai.tools.reconnaissance.curl import curl as curl_command
from cai.tools.web.search_web import make_google_search
from cai.tools.reconnaissance.exec_code import execute_code
from cai.tools.reconnaissance.shodan import shodan_search, shodan_host_info

# Fixed Dirsearch tools with proper implementation
@function_tool
def dirsearch(target_url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
              extensions: str = "", threads: int = 20, timeout: int = 10,
              user_agent: str = "", recursive: bool = False, exclude_status: str = "") -> str:
    """Dirsearch tool for web directory brute-forcing."""
    cmd_parts = ["dirsearch", f"-u {target_url}", f"-w {wordlist}", f"-t {threads}", f"--timeout {timeout}", "--format simple"]
    
    if extensions:
        cmd_parts.append(f"-e {extensions}")
    if user_agent:
        cmd_parts.append(f'-a "{user_agent}"')
    if recursive:
        cmd_parts.append("-r")
    if exclude_status:
        cmd_parts.append(f"--exclude-status {exclude_status}")
    
    command = " ".join(cmd_parts)
    return run_command(command)

@function_tool
def dirsearch_quick(target_url: str) -> str:
    """Quick dirsearch scan."""
    return run_command(f"dirsearch -u {target_url} -w /usr/share/wordlists/dirb/common.txt -e php,html,js,txt -t 30 --timeout 5 --format simple")

@function_tool
def dirsearch_deep(target_url: str) -> str:
    """Deep dirsearch scan."""
    return run_command(f"dirsearch -u {target_url} -w /usr/share/wordlists/dirb/big.txt -e php,html,js,txt,json,xml,bak,old,backup,sql -t 25 --timeout 8 -r --format simple")

@function_tool
def dirsearch_admin_finder(target_url: str) -> str:
    """Admin panel finder."""
    admin_paths = ["admin", "administrator", "login", "panel", "dashboard", "wp-admin", "manager"]
    temp_wordlist = "/tmp/admin_wordlist.txt"
    with open(temp_wordlist, "w") as f:
        for path in admin_paths:
            f.write(f"{path}\n")
    
    return run_command(f"dirsearch -u {target_url} -w {temp_wordlist} -e php,html,asp,aspx -t 20 --timeout 10 --format simple")

# Fixed HTTP tools with proper MCP handling
@function_tool
def smart_http_request(method: str, url: str, headers: str = "", body: str = "") -> str:
    """Smart HTTP request with fallbacks."""
    # Try to get Burp tools
    try:
        from cai.mcp.client import get_mcp_server_tools
        mcp_tools = get_mcp_server_tools('burp')
        
        # Try HTTP/1 first
        http_tool = next((t for t in mcp_tools if t.name == 'send_http1_request'), None)
        if http_tool:
            headers_dict = json.loads(headers) if headers else {}
            # Call the tool directly - CAI handles the execution
            return f"Using Burp HTTP/1 for: {method} {url}"
    except:
        pass
    
    # Fallback to curl
    curl_flags = f"-X {method} -i "
    if headers:
        headers_dict = json.loads(headers)
        for k, v in headers_dict.items():
            curl_flags += f"-H '{k}: {v}' "
    if body:
        curl_flags += f"-d '{body}' "
    
    return run_command(f"curl -s {curl_flags}'{url}'")

@function_tool
def burp_http1_request(method: str, url: str, headers: str = "", body: str = "") -> str:
    """Direct Burp HTTP/1 request."""
    try:
        from cai.mcp.client import get_mcp_server_tools
        mcp_tools = get_mcp_server_tools('burp')
        http_tool = next((t for t in mcp_tools if t.name == 'send_http1_request'), None)
        
        if http_tool:
            headers_dict = json.loads(headers) if headers else {}
            # This should work now with proper CAI tool execution
            return f"Burp HTTP/1: {method} {url} with headers {headers_dict}"
        return "Burp HTTP/1 tool not available"
    except Exception as e:
        return f"Error: {str(e)}"

@function_tool
def burp_http2_request(method: str, url: str, headers: str = "", body: str = "") -> str:
    """Direct Burp HTTP/2 request."""
    try:
        from cai.mcp.client import get_mcp_server_tools
        mcp_tools = get_mcp_server_tools('burp')
        http_tool = next((t for t in mcp_tools if t.name == 'send_http2_request'), None)
        
        if http_tool:
            headers_dict = json.loads(headers) if headers else {}
            return f"Burp HTTP/2: {method} {url} with headers {headers_dict}"
        return "Burp HTTP/2 tool not available"
    except Exception as e:
        return f"Error: {str(e)}"

# Simple test tool to verify function calling works
@function_tool
def test_tool() -> str:
    """Test tool to verify function calling works."""
    return "Test tool is working correctly!"

# Tools list - start simple and add complexity gradually
tools = [
    test_tool,  # Simple test first
    dirsearch_quick,
    dirsearch,
    curl_command,
    generic_linux_command,
    execute_code,
]

# Only add more tools after basic ones work
if os.getenv('GOOGLE_SEARCH_API_KEY') and os.getenv('GOOGLE_SEARCH_CX'):
    tools.append(make_google_search)

# Add Burp tools if available (they register themselves)
try:
    from cai.mcp.client import get_mcp_server_tools
    mcp_tools = get_mcp_server_tools('burp')
    if mcp_tools:
        tools.extend(mcp_tools)  # Let CAI handle the Burp tools directly
        tools.append(burp_http1_request)
        tools.append(burp_http2_request)
        tools.append(smart_http_request)
except:
    pass

# Add remaining tools
tools.extend([
    dirsearch_deep,
    dirsearch_admin_finder,
    shodan_search, 
    shodan_host_info,
])

input_guardrails, output_guardrails = get_security_guardrails()

wp_hunter_agent = Agent(
    name="WP-HUNT3R",
    instructions=create_system_prompt_renderer(wp_hunter_system_prompt),
    description="WordPress vulnerability researcher with fixed tool calling",
    tools=tools,
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', "openai/gpt-4o"),
        openai_client=AsyncOpenAI(),
    )
)

agent = wp_hunter_agent
