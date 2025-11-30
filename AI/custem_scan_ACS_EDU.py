"""CVE-FRONTLINE - Immediate CVE analysis agent for Layer3 flows"""

import os
import json
from dotenv import load_dotenv
from openai import AsyncOpenAI

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, function_tool
from cai.util import load_prompt_template, create_system_prompt_renderer
from cai.agents.guardrails import get_security_guardrails
from cai.tools.common import run_command
from cai.tools.web.search_web import make_google_search

load_dotenv()

# Load frontline prompt
frontline_prompt = load_prompt_template("prompts/WP_search_prompt.md")

@function_tool
def plugin_cve_analysis(slug: str, version: str = "Unknown", analysis_type: str = "plugin_cve_analysis") -> str:
    """Immediately begin CVE analysis for a WordPress plugin."""
    return f"🔍 INITIATING PLUGIN CVE ANALYSIS: {slug} (v{version}) - {analysis_type}"

@function_tool
def theme_cve_analysis(slug: str, version: str = "Unknown", analysis_type: str = "theme_cve_analysis") -> str:
    """Immediately begin CVE analysis for a WordPress theme."""
    return f"🔍 INITIATING THEME CVE ANALYSIS: {slug} (v{version}) - {analysis_type}"

@function_tool
def core_cve_analysis(version: str = "Unknown", analysis_type: str = "core_cve_analysis") -> str:
    """Immediately begin CVE analysis for WordPress core."""
    return f"🔍 INITIATING CORE CVE ANALYSIS: WordPress {version} - {analysis_type}"

@function_tool
def search_cve_database(plugin_slug: str, version: str = "Unknown") -> str:
    """Search CVE databases for known vulnerabilities."""
    return f"📚 SEARCHING CVE DATABASES: {plugin_slug} v{version}"

@function_tool
def check_wpvulndb(slug: str) -> str:
    """Check WordPress Vulnerability Database for known issues."""
    return f"🔎 CHECKING WPVULNDB: {slug}"


#if os.getenv('GOOGLE_SEARCH_API_KEY') and os.getenv('GOOGLE_SEARCH_CX'):
#    frontline_tools.append(make_google_search)
 

# Frontline tools - focused on CVE analysis only
frontline_tools = [
    plugin_cve_analysis,
    theme_cve_analysis, 
    core_cve_analysis,
    search_cve_database,
    check_wpvulndb
]

input_guardrails, output_guardrails = get_security_guardrails()

frontline_agent = Agent(
    name="WP_CVE_Search",
    instructions=create_system_prompt_renderer(frontline_prompt),
    description="Immediate CVE analysis agent for Layer3 plugin/theme security flows",
    tools=frontline_tools,
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', "openai/gpt-4o"),
        openai_client=AsyncOpenAI(),
    )
)
