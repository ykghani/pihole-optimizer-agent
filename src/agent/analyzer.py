"""
PiHole DNS Analysis Agent

This agent uses LangGraph to implement a multi-step workflow:
1. OBSERVE: Collect DNS query data from MCP server
2. ANALYZE: Send to Claude for pattern identification
3. PROPOSE: Generate whitelist/blacklist recommendations
4. APPLY: Optionally apply low-risk changes automatically
5. REPORT: Send email summary

The agent runs on a schedule (cron) and makes decisions autonomously
while keeping humans in the loop for high-risk changes.
"""

import os
import sys
import json
import hmac
import hashlib
import httpx
import asyncio
from datetime import datetime
from typing import TypedDict, Annotated, Literal
from dataclasses import dataclass
from urllib.parse import quote
import logging

from dotenv import load_dotenv
from anthropic import Anthropic
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# CONFIGURATION
# ============================================================================

MCP_SERVER_URL = os.getenv('MCP_SERVER_URL', 'http://localhost:8765')
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
APPROVAL_SECRET = os.getenv('APPROVAL_SECRET', '')
APPROVAL_BASE_URL = os.getenv('APPROVAL_BASE_URL', MCP_SERVER_URL)

# Safety settings
AUTO_APPLY_WHITELIST = True   # Auto-apply whitelist for known-good patterns
AUTO_APPLY_BLACKLIST = False  # Require human approval for blacklisting
MAX_AUTO_CHANGES = 5          # Max automatic changes per run


# ============================================================================
# STATE DEFINITION
# ============================================================================

class AgentState(TypedDict):
    """
    State that flows through the LangGraph workflow.
    
    LangGraph maintains this state across nodes, allowing each step
    to read previous results and add its own.
    """
    # Data collection
    recent_queries: dict
    top_blocked: list
    top_permitted: list
    client_activity: list
    pihole_status: dict
    
    # Analysis results
    analysis: str
    recommendations: list  # List of {action, domain, reason, risk_level}
    
    # Actions taken
    actions_taken: list
    
    # Report
    report: str
    
    # Metadata
    run_timestamp: str
    errors: list


# ============================================================================
# MCP CLIENT
# ============================================================================

async def call_mcp_tool(tool_name: str, arguments: dict = None) -> dict:
    """
    Call a tool on the MCP server via HTTP.
    
    The MCP streamable-http transport accepts JSON-RPC requests.
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            # MCP uses JSON-RPC 2.0 format
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": arguments or {}
                }
            }
            
            response = await client.post(
                f"{MCP_SERVER_URL}/mcp",
                json=payload,
                headers={"Content-Type": "application/json",
		 	 "Accept": "application/json"}
            )
            response.raise_for_status()
            
            result = response.json()
            
            # Extract the actual result from JSON-RPC response
            if "result" in result:
                # Tool results come as content array
                content = result["result"].get("content", [])
                if content and content[0].get("type") == "text":
                    # Parse the text as JSON if possible
                    text = content[0].get("text", "{}")
                    try:
                        return json.loads(text)
                    except json.JSONDecodeError:
                        return {"raw": text}
                return result["result"]
            elif "error" in result:
                logger.error(f"MCP error: {result['error']}")
                return {"error": result["error"]}
            
            return result
            
        except httpx.HTTPError as e:
            logger.error(f"HTTP error calling MCP tool {tool_name}: {e}")
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Error calling MCP tool {tool_name}: {e}")
            return {"error": str(e)}


# ============================================================================
# WORKFLOW NODES
# ============================================================================

async def observe_node(state: AgentState) -> AgentState:
    """
    OBSERVE: Collect current DNS data from PiHole via MCP.
    
    This is the first step - gather all the information we need
    before doing any analysis.
    """
    logger.info("=== OBSERVE: Collecting DNS data ===")
    
    errors = []
    
    # Get recent queries (last 6 hours since we run every 6 hours)
    recent = await call_mcp_tool("pihole_get_recent_queries", {"minutes": 1440})
    if "error" in recent:
        errors.append(f"Failed to get recent queries: {recent['error']}")
        recent = {}
    
    # Get top blocked
    blocked = await call_mcp_tool("pihole_get_top_blocked", {"count": 30})
    if isinstance(blocked, dict) and "error" in blocked:
        errors.append(f"Failed to get top blocked: {blocked['error']}")
        blocked = []
    elif isinstance(blocked, dict) and not isinstance(blocked, list):
        # Pi-hole may return {domain: count} dict — convert to list
        try:
            blocked = [
                {'domain': d, 'count': c}
                for d, c in blocked.items()
                if isinstance(c, (int, float))  # Filter out non-numeric values
            ]
            blocked.sort(key=lambda x: x['count'], reverse=True)
        except (AttributeError, TypeError) as e:
            logger.error(f"Failed to parse top_blocked response: {e}, data: {blocked}")
            blocked = []
    elif not isinstance(blocked, list):
        logger.warning(f"Unexpected top_blocked type: {type(blocked)}, setting to empty list")
        blocked = []

    # Get top permitted
    permitted = await call_mcp_tool("pihole_get_top_permitted", {"count": 30})
    if isinstance(permitted, dict) and "error" in permitted:
        errors.append(f"Failed to get top permitted: {permitted['error']}")
        permitted = []
    elif isinstance(permitted, dict) and not isinstance(permitted, list):
        try:
            permitted = [
                {'domain': d, 'count': c}
                for d, c in permitted.items()
                if isinstance(c, (int, float))
            ]
            permitted.sort(key=lambda x: x['count'], reverse=True)
        except (AttributeError, TypeError) as e:
            logger.error(f"Failed to parse top_permitted response: {e}, data: {permitted}")
            permitted = []
    elif not isinstance(permitted, list):
        logger.warning(f"Unexpected top_permitted type: {type(permitted)}, setting to empty list")
        permitted = []

    # Get client activity
    clients = await call_mcp_tool("pihole_get_clients", {"hours": 24})
    if isinstance(clients, dict) and "error" in clients:
        errors.append(f"Failed to get client activity: {clients['error']}")
        clients = []
    elif isinstance(clients, dict) and not isinstance(clients, list):
        try:
            clients = [
                {'client': k, 'count': v}
                for k, v in clients.items()
                if isinstance(v, (int, float))
            ]
            clients.sort(key=lambda x: x['count'], reverse=True)
        except (AttributeError, TypeError) as e:
            logger.error(f"Failed to parse clients response: {e}, data: {clients}")
            clients = []
    elif not isinstance(clients, list):
        logger.warning(f"Unexpected clients type: {type(clients)}, setting to empty list")
        clients = []
    
    # Get PiHole status
    status = await call_mcp_tool("pihole_status")
    if "error" in status:
        errors.append(f"Failed to get status: {status['error']}")
        status = {}
    
    logger.info(f"Collected: {recent.get('total_queries', 0)} queries, "
                f"{len(blocked)} blocked domains, {len(permitted)} permitted domains")
    
    return {
        **state,
        "recent_queries": recent,
        "top_blocked": blocked,
        "top_permitted": permitted,
        "client_activity": clients,
        "pihole_status": status,
        "errors": errors,
        "run_timestamp": datetime.now().isoformat()
    }


async def analyze_node(state: AgentState) -> AgentState:
    """
    ANALYZE: Send collected data to Claude for pattern identification.

    Claude looks for:
    - Legitimate domains being incorrectly blocked
    - Tracking/telemetry domains not in blocklists
    - Suspicious patterns (DGA, malware C2, etc.)
    - Unusual client behavior
    """
    logger.info("=== ANALYZE: Sending data to Claude ===")

    # Check if there's enough meaningful data to analyze
    # Skip analysis if data is trivial (not worth the API call)
    total_queries = state['recent_queries'].get('total_queries', 0)
    blocked_count = len(state.get('top_blocked', []))
    permitted_count = len(state.get('top_permitted', []))

    # Thresholds: need at least 50 queries OR 5 blocked/permitted domains
    MIN_QUERIES = 50
    MIN_DOMAINS = 5

    if total_queries < MIN_QUERIES and blocked_count < MIN_DOMAINS and permitted_count < MIN_DOMAINS:
        logger.info(f"Insufficient data to analyze - skipping Claude API call "
                   f"({total_queries} queries, {blocked_count} blocked, {permitted_count} permitted)")
        return {
            **state,
            "analysis": f"Insufficient data to analyze ({total_queries} queries, {blocked_count} blocked domains, {permitted_count} permitted domains). Waiting for more activity.",
            "recommendations": []
        }

    client = Anthropic(api_key=ANTHROPIC_API_KEY)

    # Prepare the analysis prompt
    analysis_prompt = f"""You are a network security analyst reviewing DNS query logs from a home PiHole installation.

## Current Data (Last 6 Hours)

### Summary Statistics
- Total queries: {state['recent_queries'].get('total_queries', 'N/A')}
- Blocked queries: {state['recent_queries'].get('total_blocked', 'N/A')}
- Permitted queries: {state['recent_queries'].get('total_permitted', 'N/A')}
- Cached queries: {state['recent_queries'].get('total_cached', 'N/A')}
- PiHole Status: {json.dumps(state['pihole_status'], indent=2)}

### Top Blocked Domains
{json.dumps(state['top_blocked'][:15], indent=2)}

### Top Permitted Domains
{json.dumps(state['top_permitted'][:15], indent=2)}

### Unique Blocked Domains This Period
{json.dumps(state['recent_queries'].get('blocked', [])[:20], indent=2)}

### Client Activity (queries per device)
{json.dumps(state['client_activity'][:10], indent=2)}

## Your Task

Analyze this DNS data and provide:

1. A detailed written analysis covering:
   - **False Positives (Whitelist Candidates)**: Legitimate services being blocked
   - **Tracking/Telemetry to Block**: Domains that should be blacklisted
   - **Security Concerns**: Unusual patterns, potential threats
   - **Observations**: General network health and anomalies

2. After your analysis, provide a JSON block with specific recommendations in this EXACT format:

```json
{{
  "recommendations": [
    {{
      "action": "whitelist",
      "domain": "example.com",
      "reason": "Brief explanation why",
      "risk_level": "low",
      "confidence": 95
    }}
  ]
}}
```

**Risk Level Guidelines:**
- "low": Very confident this is legitimate/malicious, minimal chance of breaking functionality
- "medium": Likely correct but some uncertainty
- "high": Uncertain, needs human review

**Confidence Guidelines:**
- 90-100: Very confident based on clear evidence (known service, obvious tracker pattern)
- 80-89: Confident but some ambiguity
- 70-79: Moderately confident
- Below 70: Low confidence, definitely needs review

Only recommend changes you're confident about. It's better to miss something than to break legitimate functionality.
"""

    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=3000,
            messages=[{"role": "user", "content": analysis_prompt}]
        )

        analysis_text = response.content[0].text

        # Detect truncation and warn
        if response.stop_reason == "max_tokens":
            logger.warning("Analysis was truncated due to max_tokens limit")
            analysis_text += "\n\n*[Analysis truncated — output exceeded max_tokens limit]*"

        logger.info("Analysis complete")
        
        # Parse recommendations from the analysis
        # (In production, you'd use structured output or tool use)
        recommendations = _parse_recommendations(analysis_text)
        
        return {
            **state,
            "analysis": analysis_text,
            "recommendations": recommendations
        }
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return {
            **state,
            "analysis": f"Analysis failed: {e}",
            "recommendations": [],
            "errors": state.get("errors", []) + [str(e)]
        }


def _parse_recommendations(analysis_text: str) -> list:
    """
    Parse recommendations from Claude's analysis.

    Looks for JSON block in the analysis with structured recommendations.
    Falls back to simple pattern matching if JSON not found.
    """
    recommendations = []

    # Try to extract JSON block first
    import re
    json_pattern = r'```json\s*(\{.*?\})\s*```'
    json_match = re.search(json_pattern, analysis_text, re.DOTALL | re.IGNORECASE)

    if json_match:
        try:
            json_data = json.loads(json_match.group(1))
            if 'recommendations' in json_data and isinstance(json_data['recommendations'], list):
                logger.info(f"Parsed {len(json_data['recommendations'])} recommendations from JSON")
                return json_data['recommendations']
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON recommendations: {e}")

    # Fallback: Simple pattern matching for recommendations
    # Look for lines like: "whitelist: cdn.example.com (reason: CDN for legitimate service)"
    patterns = [
        r'(?:recommend\s+)?(?P<action>whitelist|blacklist)(?:ing)?[:\s]+(?P<domain>[\w\.\-]+)',
        r'- action:\s*(?P<action>\w+).*?domain:\s*(?P<domain>[\w\.\-]+)',
    ]

    for pattern in patterns:
        matches = re.finditer(pattern, analysis_text, re.IGNORECASE | re.DOTALL)
        for match in matches:
            action = match.group('action').lower()
            domain = match.group('domain')

            if action in ['whitelist', 'blacklist'] and '.' in domain:
                recommendations.append({
                    'action': action,
                    'domain': domain,
                    'reason': 'Identified by Claude analysis',
                    'risk_level': 'medium',  # Default since we couldn't parse structured data
                    'confidence': 70
                })

    # Deduplicate
    seen = set()
    unique_recs = []
    for rec in recommendations:
        key = (rec['action'], rec['domain'])
        if key not in seen:
            seen.add(key)
            unique_recs.append(rec)

    logger.info(f"Parsed {len(unique_recs)} recommendations using fallback pattern matching")
    return unique_recs


async def propose_node(state: AgentState) -> AgentState:
    """
    PROPOSE: Filter recommendations and decide what to apply.
    
    Safety rules:
    - Only auto-apply low-risk whitelists
    - Never auto-apply blacklists (false positive = broken site)
    - Limit auto-changes per run
    """
    logger.info("=== PROPOSE: Filtering recommendations ===")
    
    recommendations = state.get("recommendations", [])
    
    # Filter for auto-apply candidates
    auto_apply = []
    needs_review = []
    
    for rec in recommendations:
        action = rec.get('action')
        risk = rec.get('risk_level', 'high')
        confidence = rec.get('confidence', 0)
        
        # Auto-apply criteria
        is_safe_whitelist = (
            action == 'whitelist' and
            AUTO_APPLY_WHITELIST and
            risk == 'low' and
            confidence >= 80 and
            len(auto_apply) < MAX_AUTO_CHANGES
        )
        
        is_safe_blacklist = (
            action == 'blacklist' and
            AUTO_APPLY_BLACKLIST and
            risk == 'low' and
            confidence >= 90 and
            len(auto_apply) < MAX_AUTO_CHANGES
        )
        
        if is_safe_whitelist or is_safe_blacklist:
            auto_apply.append(rec)
        else:
            needs_review.append(rec)
    
    logger.info(f"Auto-apply: {len(auto_apply)}, Needs review: {len(needs_review)}")
    
    # Store categorized recommendations back in state
    state["recommendations"] = auto_apply + needs_review
    state["auto_apply_count"] = len(auto_apply)
    
    return state


async def apply_node(state: AgentState) -> AgentState:
    """
    APPLY: Execute approved changes via MCP.
    
    Only applies changes marked for auto-apply in the propose step.
    """
    logger.info("=== APPLY: Executing changes ===")
    
    actions_taken = []
    auto_apply_count = state.get("auto_apply_count", 0)
    recommendations = state.get("recommendations", [])
    
    for i, rec in enumerate(recommendations[:auto_apply_count]):
        action = rec.get('action')
        domain = rec.get('domain')
        reason = rec.get('reason', 'Automated analysis')
        
        logger.info(f"Applying: {action} {domain}")
        
        if action == 'whitelist':
            result = await call_mcp_tool("pihole_whitelist", {
                "domain": domain,
                "reason": f"[AUTO] {reason}"
            })
        elif action == 'blacklist':
            result = await call_mcp_tool("pihole_blacklist", {
                "domain": domain,
                "reason": f"[AUTO] {reason}"
            })
        else:
            result = {"error": f"Unknown action: {action}"}
        
        actions_taken.append({
            "action": action,
            "domain": domain,
            "reason": reason,
            "result": result,
            "timestamp": datetime.now().isoformat()
        })
    
    logger.info(f"Applied {len(actions_taken)} changes")
    
    return {
        **state,
        "actions_taken": actions_taken
    }


def _generate_approval_url(action: str, domain: str, reason: str) -> str:
    """Generate a signed approval URL for a recommendation."""
    token = hmac.new(
        APPROVAL_SECRET.encode(),
        f"{action}:{domain}".encode(),
        hashlib.sha256
    ).hexdigest()
    encoded_reason = quote(reason)
    return f"{APPROVAL_BASE_URL}/approve?action={action}&domain={domain}&token={token}&reason={encoded_reason}"


def _send_email_report(report: str):
    """Send report via msmtp."""
    import subprocess
    import re

    if not EMAIL_ADDRESS:
        logger.warning("EMAIL_ADDRESS not set in .env, skipping email report")
        return

    # Validate email format for security
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', EMAIL_ADDRESS):
        logger.error(f"Invalid email address format: {EMAIL_ADDRESS}")
        return

    email_body = f"""Subject: PiHole Analysis Report - {datetime.now().strftime('%Y-%m-%d %H:%M')}
To: {EMAIL_ADDRESS}
From: pihole-agent@juicypi5u.local
Content-Type: text/plain; charset=utf-8

{report}
"""

    try:
        proc = subprocess.run(
            ['msmtp', '-a', 'default', EMAIL_ADDRESS],
            input=email_body,
            text=True,
            capture_output=True,
            timeout=30
        )
        if proc.returncode == 0:
            logger.info(f"Email report sent successfully to {EMAIL_ADDRESS}")
        else:
            logger.error(f"Failed to send email: {proc.stderr}")
    except Exception as e:
        logger.error(f"Email error: {e}")


async def report_node(state: AgentState) -> AgentState:
    """
    REPORT: Generate and send summary report.
    """
    logger.info("=== REPORT: Generating summary ===")

    # Build report
    report_lines = [
        "# PiHole Analysis Report",
        f"**Run Time:** {state.get('run_timestamp', 'N/A')}",
        "",
        "## Summary",
        f"- Queries analyzed: {state['recent_queries'].get('total_queries', 'N/A')}",
        f"- Blocked: {state['recent_queries'].get('total_blocked', 'N/A')}",
        f"- Permitted: {state['recent_queries'].get('total_permitted', 'N/A')}",
        f"- Cached: {state['recent_queries'].get('total_cached', 'N/A')}",
        "",
        "## Analysis",
        state.get('analysis', 'No analysis available'),
        "",
        "## Actions Taken",
    ]

    actions = state.get('actions_taken', [])
    if actions:
        for action in actions:
            status = "✓" if action.get('result', {}).get('success') else "✗"
            report_lines.append(
                f"- {status} {action['action']} {action['domain']}: {action['reason']}"
            )
    else:
        report_lines.append("- No automatic actions taken")

    report_lines.append("")
    report_lines.append("## Recommendations Needing Review")

    auto_count = state.get('auto_apply_count', 0)
    pending = state.get('recommendations', [])[auto_count:]
    if pending:
        for rec in pending[:10]:
            line = f"- [{rec['risk_level'].upper()}] {rec['action']} {rec['domain']}: {rec['reason']}"
            if APPROVAL_SECRET:
                url = _generate_approval_url(rec['action'], rec['domain'], rec['reason'])
                line += f"\n  Approve: {url}"
            report_lines.append(line)
    else:
        report_lines.append("- None")

    if state.get('errors'):
        report_lines.append("")
        report_lines.append("## Errors")
        for error in state['errors']:
            report_lines.append(f"- {error}")

    report = "\n".join(report_lines)

    # Save report to file
    import os
    log_dir = os.path.expanduser("~/pihole-agent/logs")
    os.makedirs(log_dir, exist_ok=True)
    report_file = os.path.join(log_dir, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
    try:
        with open(report_file, 'w') as f:
            f.write(report)
        logger.info(f"Report saved to {report_file}")
    except Exception as e:
        logger.error(f"Failed to save report: {e}")

    # Send email (using msmtp which you already have configured)
    _send_email_report(report)

    return {
        **state,
        "report": report
    }


# ============================================================================
# GRAPH DEFINITION
# ============================================================================

def create_agent_graph():
    """
    Build the LangGraph workflow.
    
    Graph structure:
    START -> observe -> analyze -> propose -> apply -> report -> END
    """
    workflow = StateGraph(AgentState)
    
    # Add nodes
    workflow.add_node("observe", observe_node)
    workflow.add_node("analyze", analyze_node)
    workflow.add_node("propose", propose_node)
    workflow.add_node("apply", apply_node)
    workflow.add_node("report", report_node)
    
    # Add edges (linear flow for now)
    workflow.add_edge(START, "observe")
    workflow.add_edge("observe", "analyze")
    workflow.add_edge("analyze", "propose")
    workflow.add_edge("propose", "apply")
    workflow.add_edge("apply", "report")
    workflow.add_edge("report", END)
    
    return workflow.compile()


# ============================================================================
# MAIN
# ============================================================================

async def run_analysis():
    """Run the full analysis workflow."""
    logger.info("Starting PiHole analysis agent")
    
    graph = create_agent_graph()
    
    # Initialize empty state
    initial_state = {
        "recent_queries": {},
        "top_blocked": [],
        "top_permitted": [],
        "client_activity": [],
        "pihole_status": {},
        "analysis": "",
        "recommendations": [],
        "actions_taken": [],
        "report": "",
        "run_timestamp": "",
        "errors": []
    }
    
    # Run the graph
    final_state = await graph.ainvoke(initial_state)
    
    logger.info("Analysis complete")
    print("\n" + "="*60)
    print(final_state.get("report", "No report generated"))
    print("="*60)
    
    return final_state


if __name__ == "__main__":
    asyncio.run(run_analysis())
