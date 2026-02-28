"""
PiHole Email Responder

Monitors Gmail for replies to PiHole Analysis Report emails and executes
commands via the MCP server. This closes the feedback loop: the analyzer
sends reports, users reply with instructions, and this script acts on them.

Flow:
1. Connect to Gmail via IMAP (imapclient library)
2. Find unread replies to "PiHole Analysis Report" emails
3. Extract the reply text
4. Send to Claude to interpret intent → determine which MCP tool to call
5. Call the MCP tool via HTTP (localhost:8765)
6. Email back a confirmation of the action taken

Runs every 5 minutes via cron.
"""

import os
import sys
import re
import json
import email
import subprocess
import logging
from datetime import datetime

import httpx
import imapclient
from dotenv import load_dotenv
from anthropic import Anthropic

# Load .env from project root (same pattern as analyzer.py)
load_dotenv()

# ============================================================================
# LOGGING (same pattern as analyzer.py)
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# CONFIGURATION
# ============================================================================

# MCP server URL — must match the port in .env / server.py
MCP_SERVER_URL = os.getenv('MCP_SERVER_URL', 'http://localhost:8765')

# Anthropic API key for Claude intent parsing
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')

# Gmail credentials for IMAP access
GMAIL_EMAIL = os.getenv('GMAIL_EMAIL')
GMAIL_APP_PASSWORD = os.getenv('GMAIL_APP_PASSWORD')

# Email address to send confirmations to (reuses existing EMAIL_ADDRESS from .env)
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')

# Gmail IMAP server — standard for all Gmail accounts
IMAP_HOST = 'imap.gmail.com'
IMAP_PORT = 993  # SSL port, Gmail requires encrypted connections

# Subject line to search for — must match what analyzer.py sends
REPORT_SUBJECT = 'PiHole Analysis Report'


# ============================================================================
# IMAP: CONNECT TO GMAIL AND FETCH REPLY EMAILS
# ============================================================================

def connect_to_gmail():
    """
    Establish an IMAP connection to Gmail using imapclient.

    imapclient wraps Python's imaplib with a friendlier API:
    - No need to manually encode search criteria
    - Returns parsed message data instead of raw bytes
    - Handles IMAP protocol quirks (like Gmail's extensions)

    Returns an authenticated IMAPClient instance, or None on failure.
    """
    if not GMAIL_EMAIL or not GMAIL_APP_PASSWORD:
        logger.error("GMAIL_EMAIL and GMAIL_APP_PASSWORD must be set in .env")
        return None

    try:
        # Create a connection using SSL (port 993)
        # ssl=True means the connection is encrypted from the start,
        # as opposed to STARTTLS which upgrades a plain connection
        client = imapclient.IMAPClient(IMAP_HOST, port=IMAP_PORT, ssl=True)

        # Authenticate with the app password
        # Gmail requires an "App Password" when 2FA is enabled —
        # a regular password won't work with IMAP
        client.login(GMAIL_EMAIL, GMAIL_APP_PASSWORD)

        logger.info(f"Connected to Gmail IMAP as {GMAIL_EMAIL}")
        return client

    except imapclient.exceptions.LoginError as e:
        # LoginError means credentials were rejected
        # Common causes: wrong app password, 2FA not set up, less secure apps disabled
        logger.error(f"Gmail login failed — check GMAIL_APP_PASSWORD: {e}")
        return None
    except Exception as e:
        logger.error(f"IMAP connection failed: {e}")
        return None


def fetch_unread_replies(client):
    """
    Search Gmail for unread emails that are replies to PiHole Analysis Reports.

    How IMAP search works:
    - select_folder('INBOX') tells the server which mailbox to search
    - search() sends an IMAP SEARCH command with criteria
    - Gmail supports standard IMAP search, plus extensions like X-GM-RAW

    We look for emails that:
    1. Are UNSEEN (unread) — so we don't re-process old replies
    2. Have a subject containing "Re: PiHole Analysis Report"
       (Gmail auto-prepends "Re:" to reply subjects)

    Returns a list of dicts: [{uid, sender, subject, body}, ...]
    """
    # Select INBOX — the readonly=False flag allows us to modify flags (mark as read)
    client.select_folder('INBOX', readonly=False)

    # Build search criteria:
    # UNSEEN = unread messages only
    # SUBJECT = matches substring in the subject header
    # We search for "Re:" prefix because these are replies to our outgoing reports
    search_criteria = ['UNSEEN', 'SUBJECT', f'Re: {REPORT_SUBJECT}']

    # Execute the search — returns a list of message UIDs (unique IDs)
    # UIDs are stable identifiers that don't change when other messages are deleted
    message_uids = client.search(search_criteria)

    if not message_uids:
        logger.info("No unread replies found")
        return []

    logger.info(f"Found {len(message_uids)} unread reply(ies)")

    replies = []

    # Fetch the actual message data for each UID
    # RFC822 = the full raw email message (headers + body)
    # We could fetch just specific parts, but for plain text emails this is fine
    raw_messages = client.fetch(message_uids, ['RFC822'])

    for uid, data in raw_messages.items():
        # data[b'RFC822'] is the raw email bytes
        raw_email = data[b'RFC822']

        # Parse the raw bytes into a Python email.message.Message object
        # email.message_from_bytes handles MIME decoding, charset conversion, etc.
        msg = email.message_from_bytes(raw_email)

        # Extract the sender's email address from the From header
        sender = msg.get('From', 'unknown')

        # Extract the subject for logging
        subject = msg.get('Subject', 'no subject')

        # Extract the plain text body from the email
        body = _extract_plain_text_body(msg)

        if body:
            replies.append({
                'uid': uid,
                'sender': sender,
                'subject': subject,
                'body': body.strip()
            })
            logger.info(f"  Reply from {sender}: {body[:80]}...")
        else:
            logger.warning(f"  Reply from {sender} had no extractable text body")

    return replies


def _extract_plain_text_body(msg):
    """
    Extract the plain text body from an email message.

    Emails can be:
    - Simple: single text/plain part (basic emails)
    - Multipart: multiple parts like text/plain + text/html (most email clients)
    - Nested: multipart containing multipart (forwarded emails, etc.)

    For replies, we want just the new text the user typed,
    not the quoted original message. We strip common quote markers.
    """
    body = None

    if msg.is_multipart():
        # Walk through all MIME parts and grab the first text/plain one
        # walk() recursively iterates through nested multipart structures
        for part in msg.walk():
            content_type = part.get_content_type()
            # Skip container parts (multipart/mixed, multipart/alternative)
            if content_type == 'text/plain':
                # get_payload(decode=True) handles base64/quoted-printable decoding
                # Returns bytes, so we decode to string
                charset = part.get_content_charset() or 'utf-8'
                body = part.get_payload(decode=True).decode(charset, errors='replace')
                break  # Use the first text/plain part
    else:
        # Simple single-part email
        if msg.get_content_type() == 'text/plain':
            charset = msg.get_content_charset() or 'utf-8'
            body = msg.get_payload(decode=True).decode(charset, errors='replace')

    if not body:
        return None

    # Strip the quoted original message from the reply
    # Most email clients add a line like "On <date>, <sender> wrote:" before the quote
    # We only want the text ABOVE that line (the user's new reply)
    body = _strip_quoted_text(body)

    return body


def _strip_quoted_text(text):
    """
    Remove quoted text from an email reply, keeping only the new content.

    Email clients use different quoting styles:
    - Gmail: "On Mon, Jan 1, 2025 at 12:00 PM <user@gmail.com> wrote:"
    - Outlook: "From: user@example.com\nSent: ..."
    - Generic: lines starting with ">" are quoted
    """
    lines = text.split('\n')
    cleaned_lines = []

    for line in lines:
        # Stop at Gmail-style quote header
        if re.match(r'^On .+ wrote:$', line.strip()):
            break
        # Stop at Outlook-style quote header
        if line.strip().startswith('From:') and 'Sent:' in text:
            break
        # Stop at generic "----" dividers that precede quoted text
        if re.match(r'^-{3,}', line.strip()):
            break
        # Skip individual quoted lines (lines starting with >)
        if line.strip().startswith('>'):
            continue
        cleaned_lines.append(line)

    return '\n'.join(cleaned_lines).strip()


def mark_as_read(client, uid):
    """
    Mark an email as read (SEEN) so we don't process it again on the next run.

    IMAP uses "flags" to track message state:
    - \\Seen = message has been read
    - \\Flagged = message is starred
    - \\Deleted = message is marked for deletion

    add_flags() sends an IMAP STORE command to set the flag on the server.
    """
    client.add_flags(uid, [imapclient.SEEN])
    logger.info(f"Marked message UID {uid} as read")


# ============================================================================
# CLAUDE: INTERPRET USER INTENT
# ============================================================================

def interpret_command(reply_text):
    """
    Send the user's reply to Claude to determine which MCP tool to call.

    We use Claude as a natural language interpreter:
    - User writes: "block samsungsmarthub.com"
    - Claude returns: {"tool": "pihole_blacklist", "arguments": {"domain": "...", "reason": "..."}}

    This is more flexible than regex parsing because it handles:
    - Variations: "block", "blacklist", "add to blocklist"
    - Typos and informal language
    - Multi-step requests
    """
    client = Anthropic(api_key=ANTHROPIC_API_KEY)

    # System prompt tells Claude exactly what tools are available and what JSON to return
    system_prompt = """You are a PiHole command interpreter. The user has replied to a PiHole Analysis Report email with instructions.

Your job is to determine which MCP tool to call based on their message.

Available tools and when to use them:

1. pihole_blacklist - Block a domain
   Arguments: {"domain": "example.com", "reason": "User requested via email"}
   Trigger words: block, blacklist, deny, ban, add to blocklist

2. pihole_whitelist - Allow a domain
   Arguments: {"domain": "example.com", "reason": "User requested via email"}
   Trigger words: whitelist, allow, permit, unblock, add to allowlist

3. pihole_get_recent_queries - Show recent DNS queries
   Arguments: {"minutes": 60} (default 60, or extract timeframe from message)
   Optional: if user mentions a specific client/IP, note it in the reason field
   Trigger words: show queries, recent queries, what's been queried, DNS activity

4. pihole_status - Get PiHole system status
   Arguments: {} (no arguments needed)
   Trigger words: status, how is pihole, is pihole running, health check

5. pihole_get_top_blocked - Show most blocked domains
   Arguments: {"count": 20} (default 20, or extract count from message)
   Trigger words: top blocked, most blocked, what's being blocked

6. pihole_get_top_permitted - Show most permitted domains
   Arguments: {"count": 20} (default 20, or extract count from message)
   Trigger words: top permitted, most allowed, what's being allowed

7. pihole_get_clients - Show client device activity
   Arguments: {"hours": 24} (default 24, or extract timeframe from message)
   Trigger words: clients, devices, who's using, device activity

Respond with ONLY a JSON object (no markdown, no explanation):
{
  "tool": "tool_name_here",
  "arguments": {"key": "value"},
  "summary": "Brief description of what the user wants"
}

If the message doesn't match any tool, respond with:
{
  "tool": null,
  "arguments": {},
  "summary": "Could not understand the request"
}"""

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6-20250627",
            max_tokens=500,
            system=system_prompt,
            messages=[{"role": "user", "content": reply_text}]
        )

        response_text = response.content[0].text.strip()

        # Parse the JSON response from Claude
        # Claude should return pure JSON, but strip markdown fences just in case
        response_text = re.sub(r'^```json\s*', '', response_text)
        response_text = re.sub(r'\s*```$', '', response_text)

        parsed = json.loads(response_text)
        logger.info(f"Interpreted command: {parsed.get('summary', 'unknown')}")
        return parsed

    except json.JSONDecodeError as e:
        logger.error(f"Claude returned invalid JSON: {e}")
        logger.error(f"Raw response: {response_text}")
        return {"tool": None, "arguments": {}, "summary": "Failed to parse Claude response"}
    except Exception as e:
        logger.error(f"Claude API call failed: {e}")
        return {"tool": None, "arguments": {}, "summary": f"API error: {e}"}


# ============================================================================
# MCP: CALL THE PIHOLE MCP SERVER
# ============================================================================

def call_mcp_tool(tool_name, arguments=None):
    """
    Call a tool on the MCP server via HTTP (synchronous version).

    Uses the same JSON-RPC 2.0 format as analyzer.py's async version,
    but with httpx.Client instead of httpx.AsyncClient since this script
    doesn't need to be async (it processes emails sequentially).

    The MCP server runs on localhost:8765 with streamable-http transport.
    """
    try:
        # JSON-RPC 2.0 payload — the standard format MCP uses
        payload = {
            "jsonrpc": "2.0",
            "id": 1,  # Request ID — could be incremented but we only make one call at a time
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments or {}
            }
        }

        # Use a synchronous HTTP client with a generous timeout
        # The MCP server might need time to talk to PiHole's API
        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                f"{MCP_SERVER_URL}/mcp",
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
            )
            response.raise_for_status()

        result = response.json()

        # Parse the JSON-RPC response
        if "result" in result:
            # MCP tool results come wrapped in a content array
            content = result["result"].get("content", [])
            if content and content[0].get("type") == "text":
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
# EMAIL: SEND CONFIRMATION BACK TO USER
# ============================================================================

def send_confirmation_email(recipient, action_summary, result_data):
    """
    Send a confirmation email back to the user showing what action was taken.

    Uses msmtp (already configured on the Pi for the analyzer) via subprocess.
    Same pattern as _send_email_report() in analyzer.py.
    """
    if not EMAIL_ADDRESS:
        logger.warning("EMAIL_ADDRESS not set, skipping confirmation email")
        return

    # Validate email format (same security check as analyzer.py)
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', EMAIL_ADDRESS):
        logger.error(f"Invalid email address format: {EMAIL_ADDRESS}")
        return

    # Format the result data for readability
    if isinstance(result_data, dict):
        result_formatted = json.dumps(result_data, indent=2, default=str)
    else:
        result_formatted = str(result_data)

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')

    email_body = f"""Subject: Re: PiHole Action Confirmation - {timestamp}
To: {EMAIL_ADDRESS}
From: pihole-agent@juicypi5u.local
Content-Type: text/plain; charset=utf-8

PiHole Email Responder - Action Confirmation
=============================================

Action: {action_summary}
Time: {timestamp}

Result:
{result_formatted}

---
This is an automated response from your PiHole agent.
Reply to a PiHole Analysis Report email to send another command.
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
            logger.info(f"Confirmation email sent to {EMAIL_ADDRESS}")
        else:
            logger.error(f"Failed to send confirmation email: {proc.stderr}")
    except FileNotFoundError:
        logger.error("msmtp not found — is it installed? (sudo apt install msmtp)")
    except Exception as e:
        logger.error(f"Email error: {e}")


def send_error_email(error_message):
    """Send an error notification email when something goes wrong."""
    if not EMAIL_ADDRESS:
        return

    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', EMAIL_ADDRESS):
        return

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')

    email_body = f"""Subject: PiHole Responder Error - {timestamp}
To: {EMAIL_ADDRESS}
From: pihole-agent@juicypi5u.local
Content-Type: text/plain; charset=utf-8

PiHole Email Responder encountered an error:

{error_message}

The email has been marked as read so it won't be retried.
Check the logs at ~/pihole-agent/logs/ for details.
"""

    try:
        proc = subprocess.run(
            ['msmtp', '-a', 'default', EMAIL_ADDRESS],
            input=email_body,
            text=True,
            capture_output=True,
            timeout=30
        )
        if proc.returncode != 0:
            logger.error(f"Failed to send error email: {proc.stderr}")
    except Exception as e:
        logger.error(f"Could not send error email: {e}")


# ============================================================================
# MAIN: ORCHESTRATE THE FULL FLOW
# ============================================================================

def process_replies():
    """
    Main processing loop:
    1. Connect to Gmail
    2. Fetch unread replies to PiHole reports
    3. For each reply: interpret → execute → confirm
    4. Mark processed emails as read
    5. Disconnect
    """
    logger.info("=" * 60)
    logger.info("PiHole Email Responder starting")
    logger.info("=" * 60)

    # Pre-flight checks
    if not ANTHROPIC_API_KEY:
        logger.error("ANTHROPIC_API_KEY not set in .env — cannot interpret commands")
        return

    # Step 1: Connect to Gmail
    client = connect_to_gmail()
    if not client:
        return  # Error already logged in connect_to_gmail()

    try:
        # Step 2: Fetch unread replies
        replies = fetch_unread_replies(client)

        if not replies:
            logger.info("No replies to process — exiting")
            return

        # Step 3: Process each reply
        for reply in replies:
            logger.info(f"Processing reply from {reply['sender']}")
            logger.info(f"  Body: {reply['body'][:100]}")

            # Step 3a: Send reply text to Claude to interpret the command
            command = interpret_command(reply['body'])
            tool_name = command.get('tool')
            arguments = command.get('arguments', {})
            summary = command.get('summary', 'Unknown action')

            if not tool_name:
                # Claude couldn't map the reply to a tool
                logger.warning(f"Could not interpret command: {summary}")
                send_error_email(
                    f"Could not understand your reply:\n\n"
                    f'"{reply["body"]}"\n\n'
                    f"Supported commands:\n"
                    f"- block <domain>\n"
                    f"- whitelist <domain>\n"
                    f"- show queries\n"
                    f"- status\n"
                    f"- show top blocked\n"
                    f"- show top permitted\n"
                    f"- show clients"
                )
                # Still mark as read so we don't keep retrying
                mark_as_read(client, reply['uid'])
                continue

            # Step 3b: Call the MCP tool
            logger.info(f"Calling MCP tool: {tool_name} with args: {arguments}")
            result = call_mcp_tool(tool_name, arguments)

            # Step 3c: Send confirmation email
            send_confirmation_email(reply['sender'], summary, result)

            # Step 3d: Mark email as read so we don't process it again
            mark_as_read(client, reply['uid'])

            logger.info(f"Finished processing reply from {reply['sender']}")

    except Exception as e:
        logger.error(f"Error during processing: {e}", exc_info=True)

    finally:
        # Always disconnect cleanly
        # logout() sends the IMAP LOGOUT command, which:
        # 1. Commits any pending flag changes (like our SEEN flags)
        # 2. Closes the selected mailbox
        # 3. Ends the authenticated session
        try:
            client.logout()
            logger.info("Disconnected from Gmail")
        except Exception:
            pass  # Don't mask the original error if logout fails

    logger.info("Email responder finished")


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    process_replies()
