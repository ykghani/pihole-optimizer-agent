# PiHole Optimizer Agent

> An AI-powered agent that automatically analyzes your PiHole DNS logs and intelligently optimizes your allowlist/blocklist using Claude's API.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## What Does This Do?

This project runs a self-learning AI agent on your Raspberry Pi (or any Linux system) that:

1. **Observes** your DNS traffic by analyzing PiHole query logs
2. **Analyzes** patterns using Claude AI to identify:
   - Legitimate domains incorrectly blocked (false positives)
   - Tracking/telemetry domains that should be blocked
   - Suspicious patterns (potential malware, DGA domains, etc.)
   - Unusual device behavior
3. **Proposes** whitelist and blacklist recommendations with detailed reasoning
4. **Applies** low-risk changes automatically (configurable)
5. **Reports** via email or log files with detailed analysis

**Example output:**
```markdown
## PiHole Analysis Report

**Summary:**
- Queries analyzed: 610
- Blocked: 1
- Permitted: 409

**Recommendations:**
- ✓ Whitelist metrics.icloud.com (Apple's legitimate iCloud metrics - incorrectly blocked)
- Review: Blacklist telemetry.example.com (suspicious tracking pattern detected)
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Raspberry Pi / Linux Server                       │
│                                                                       │
│  ┌─────────────┐    ┌─────────────────┐    ┌──────────────────┐    │
│  │   PiHole    │◄───│  MCP Server     │◄───│  LangGraph Agent │    │
│  │   CLI/API   │    │  (HTTP :8765)   │    │  (Claude API)    │    │
│  └─────────────┘    └─────────────────┘    └──────────────────┘    │
│                             │                       │                │
│                             │                       ▼                │
│                             │              ┌──────────────────┐     │
│                             │              │  Cron (6 hours)  │     │
│                             │              │  + Email Alerts  │     │
│                             │              └──────────────────┘     │
└─────────────────────────────┼──────────────────────────────────────┘
                              │
          ┌───────────────────┴───────────────────┐
          ▼                                       ▼
   ┌─────────────┐                         ┌─────────────┐
   │ MacBook     │                         │ Claude      │
   │ (Terminal)  │                         │ Desktop     │
   └─────────────┘                         └─────────────┘
```

### Components

| Component | Purpose |
|-----------|---------|
| **MCP Server** | Exposes PiHole operations as tools via [Model Context Protocol](https://modelcontextprotocol.io) |
| **LangGraph Agent** | Orchestrates multi-step analysis workflow using Claude AI |
| **Claude API** | Provides intelligent pattern recognition and recommendations |
| **Cron Job** | Runs analysis automatically every 6 hours |
| **Email Reporting** | Sends summaries of findings and actions taken |

## 🔒 Security Considerations

**Please read this section carefully before installing.**

### Network Security

The MCP server is configured to bind to `localhost` (127.0.0.1) by default, which means it's only accessible from your Raspberry Pi itself. This is the recommended configuration.

**⚠️ CRITICAL WARNINGS:**
- **NEVER** change the server host to `0.0.0.0` without implementing authentication
- Exposing the MCP server to your network allows anyone with network access to:
  - Read ALL DNS queries from every device on your network
  - Modify PiHole whitelist/blacklist to disable protection or enable malware domains
  - Drain your Claude API credits by triggering analysis runs
  - Enumerate all devices on your network with IP addresses and activity patterns

**For remote access:** Use Tailscale or WireGuard VPN to securely access your Pi from outside your network. Even with VPN, keep the server bound to localhost.

### Privacy Implications

This tool logs and analyzes ALL DNS queries from your network, including:
- Every website visited by every device
- Timestamps of access
- Which device (by IP address) accessed what domains
- Patterns revealing sleep schedules, work hours, interests, and behavior

**Recommendations:**
- Understand that this data is stored in plaintext in `~/pihole-agent/logs/`
- Review file permissions on your Raspberry Pi
- Never share log files publicly when asking for help (redact domains/IPs)
- Consider implementing log retention policies (auto-delete after 30 days)
- Only share your Raspberry Pi access with trusted individuals

### API Key Security

Your Anthropic API key is stored in the `.env` file and has billing implications:

**Best Practices:**
- ✅ The `.env` file is in `.gitignore` - **never commit it to git**
- ✅ Monitor your Anthropic API usage at https://console.anthropic.com/
- ✅ Set up billing alerts to detect unexpected usage
- ✅ If you fork this repo, verify `.env` is in your fork's `.gitignore`
- ❌ **NEVER** share your `ANTHROPIC_API_KEY` with anyone
- ❌ **NEVER** post your `.env` file contents when asking for help

If you suspect your API key has been compromised:
1. Immediately revoke it at https://console.anthropic.com/settings/keys
2. Generate a new key
3. Update your `.env` file
4. Review your Anthropic billing for unexpected usage

### Getting Help Safely

When asking for help on Reddit, GitHub, or Discord:

**✅ Safe to share:**
- Sanitized log excerpts (with domains and IPs redacted)
- Error messages from the terminal
- Your configuration (without API keys)
- Screenshots of issues (blur any sensitive domains)

**❌ NEVER share:**
- Your `.env` file or its contents
- Your `ANTHROPIC_API_KEY`
- Raw log files (contain your browsing history)
- SSH/remote access to your Raspberry Pi
- Full DNS query logs

**⚠️ Be wary of:**
- People DMing you offering "quick help" (use public forums)
- Requests to "just share your .env so I can compare"
- Helpful strangers offering to SSH in to debug
- Forks of this repo from unknown authors (verify the code)

Report suspicious activity to moderators.

---

## Prerequisites

### System Requirements

- **Hardware:** Raspberry Pi 3/4/5 or any Linux server with 512MB+ RAM
- **OS:** Debian/Ubuntu-based Linux (Raspberry Pi OS, Ubuntu, etc.)
- **PiHole:** Already installed and running ([install guide](https://github.com/pi-hole/pi-hole/#one-step-automated-install))
- **Python:** 3.11 or higher
- **uv package manager:** Fast Python package manager ([install guide](https://github.com/astral-sh/uv))

### API Keys

- **Anthropic API Key**: Required for Claude AI analysis ([get one here](https://console.anthropic.com/))
  - Models supported: Claude Sonnet 4 or newer
  - Cost: ~$0.01-0.05 per analysis run (depending on traffic volume)

### Optional

- **Email server**: For email reports (msmtp, sendmail, or Gmail SMTP)
- **Tailscale**: For remote access to the MCP server

## Installation

### 1. Clone the Repository

```bash
# SSH to your Raspberry Pi or Linux server
ssh pi@raspberrypi.local  # or your server's IP

# Clone the repo
cd ~
git clone https://github.com/yourusername/pihole-optimizer-agent.git
cd pihole-optimizer-agent
```

### 2. Install uv Package Manager

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.cargo/env  # or restart your shell
```

### 3. Install Dependencies

```bash
# Initialize the project and install all dependencies
uv sync
```

This installs:
- `fastmcp` - MCP server framework
- `anthropic` - Claude API client
- `langgraph` - Agent orchestration
- `httpx`, `pydantic`, `python-dotenv` - Utilities

### 4. Configure Environment Variables

```bash
# Copy the example environment file
cp .env.example .env

# Edit with your settings
nano .env
```

Update these values in `.env`:

```bash
# Required: Your Anthropic API key
ANTHROPIC_API_KEY=sk-ant-api03-...

# Optional: Email for reports
EMAIL_ADDRESS=your.email@example.com

# Server configuration (defaults are usually fine)
PIHOLE_HOST=localhost
MCP_SERVER_PORT=8765
LOG_LEVEL=INFO
```

### 5. Test the Installation

```bash
# Test PiHole tools directly
uv run python src/tools/pihole_tools.py

# Should show PiHole status, test queries, etc.
```

### 6. Start the MCP Server

You have two options:

**Option A: Run as systemd service (recommended for 24/7 operation)**

```bash
# Copy the service file
sudo cp systemd/pihole-mcp.service.example /etc/systemd/system/pihole-mcp.service

# Edit paths if your installation differs
sudo nano /etc/systemd/system/pihole-mcp.service
# Update: User, WorkingDirectory, ExecStart paths

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable --now pihole-mcp.service

# Verify it's running
sudo systemctl status pihole-mcp.service
```

**Option B: Run manually (for testing)**

```bash
uv run python src/mcp_server/server.py
```

### 7. Test the Agent

```bash
# Run a single analysis manually
uv run python src/agent/analyzer.py

# This will:
# 1. Collect DNS data from PiHole
# 2. Send to Claude for analysis
# 3. Generate recommendations
# 4. Save report to logs/report_TIMESTAMP.md
```

### 8. Set Up Automated Scheduling (Optional)

To run analysis automatically every 6 hours:

```bash
# Edit your crontab
crontab -e

# Add this line (adjust paths to match your installation):
0 */6 * * * cd /home/pi/pihole-optimizer-agent && /home/pi/.local/bin/uv run python src/agent/analyzer.py >> /home/pi/pihole-optimizer-agent/logs/cron.log 2>&1
```

This runs the agent at 12am, 6am, 12pm, and 6pm every day.

## Usage

### Manual Analysis

Run an analysis anytime:

```bash
cd ~/pihole-optimizer-agent
uv run python src/agent/analyzer.py
```

View the latest report:

```bash
# Reports are saved to logs/
cat logs/report_*.md | tail -100
```

### View Audit Log

All whitelist/blacklist changes are logged:

```bash
# View all actions taken
cat logs/audit.jsonl | jq '.'

# View today's changes
cat logs/audit.jsonl | jq 'select(.timestamp | startswith("2026-02-15"))'
```

### Adjust Auto-Apply Settings

Edit `src/agent/analyzer.py` to configure automated changes:

```python
# Safety settings (around line 1056)
AUTO_APPLY_WHITELIST = True   # Auto-apply whitelist for known-good patterns
AUTO_APPLY_BLACKLIST = False  # Require human approval for blacklisting
MAX_AUTO_CHANGES = 5          # Max automatic changes per run
```

**Safety recommendations:**
- Start with `AUTO_APPLY_WHITELIST = False` and review recommendations manually
- Once comfortable, enable `AUTO_APPLY_WHITELIST = True` for low-risk changes only
- Keep `AUTO_APPLY_BLACKLIST = False` to prevent accidentally blocking legitimate sites

### Monitor the MCP Server

```bash
# Check service status
sudo systemctl status pihole-mcp.service

# View real-time logs
sudo journalctl -u pihole-mcp.service -f

# Test the HTTP endpoint
curl http://localhost:8765/mcp
```

## Configuration

### Environment Variables

All configuration is in `.env`:

| Variable | Description | Default |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | Your Claude API key (required) | None |
| `PIHOLE_HOST` | PiHole hostname/IP | `localhost` |
| `MCP_SERVER_PORT` | HTTP server port | `8765` |
| `EMAIL_ADDRESS` | Where to send reports | None |
| `LOG_LEVEL` | Logging verbosity | `INFO` |

### Customizing Analysis

The agent's behavior can be tuned in `src/agent/analyzer.py`:

```python
# How much data to analyze (line 1167)
recent = await call_mcp_tool("pihole_get_recent_queries", {"minutes": 360})

# Number of top domains to review (lines 1174, 1180)
blocked = await call_mcp_tool("pihole_get_top_blocked", {"count": 30})
permitted = await call_mcp_tool("pihole_get_top_permitted", {"count": 30})

# Claude model selection (line 1283)
model="claude-sonnet-4-20250514"
```

## Advanced Features

### Remote Access via Tailscale

If you have [Tailscale](https://tailscale.com/) set up, you can securely access the MCP server from anywhere while keeping it bound to localhost:

```bash
# On your Raspberry Pi, the server binds to 127.0.0.1 (localhost)
# But Tailscale creates a secure tunnel

# From your laptop/phone (via Tailscale)
# SSH into your Pi first, then access locally:
ssh pi@100.x.x.x  # Your Pi's Tailscale IP
curl http://127.0.0.1:8765/mcp

# Or use SSH port forwarding:
ssh -L 8765:127.0.0.1:8765 pi@100.x.x.x
# Then access on your laptop:
curl http://localhost:8765/mcp
```

**Security Note:** Even with Tailscale, keep the MCP server bound to `127.0.0.1`. Tailscale provides the secure remote access layer.

### Claude Desktop Integration

Connect Claude Desktop to your PiHole:

1. Create a local wrapper script (see `pihole_mcp_implementation_guide.md` section 6.2)
2. Add to Claude Desktop's MCP config
3. Ask Claude to check PiHole status, test domains, etc.

### Email Reports

To enable email reports, uncomment the `_send_email_report()` call in `analyzer.py` and configure msmtp:

```bash
# Install msmtp
sudo apt install msmtp msmtp-mta

# Configure with your email settings
nano ~/.msmtprc
```

## Troubleshooting

### MCP Server Won't Start

```bash
# Check logs for errors
sudo journalctl -u pihole-mcp.service -n 50

# Common issues:
# 1. Port 8765 already in use
sudo ss -tlnp | grep 8765

# 2. Missing dependencies
cd ~/pihole-optimizer-agent
uv sync

# 3. Permission errors
sudo chown -R $USER:$USER ~/pihole-optimizer-agent
```

### Agent Can't Read PiHole Logs

```bash
# Add your user to pihole group
sudo usermod -aG pihole $USER

# Or fix log permissions
sudo chmod 644 /var/log/pihole/pihole.log

# Then logout and back in
```

### No Recommendations Generated

This is normal if:
- Your PiHole blocklists are already well-tuned
- Traffic volume is low in the analysis period
- No obvious patterns detected

Try:
- Increase analysis time window (change `minutes: 360` to `minutes: 1440` for 24 hours)
- Run during high-traffic periods
- Check that PiHole is logging queries

### Claude API Errors

```bash
# Verify API key
echo $ANTHROPIC_API_KEY

# Test API manually
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4-20250514","max_tokens":100,"messages":[{"role":"user","content":"test"}]}'
```

### Cron Job Not Running

```bash
# Check cron logs
grep CRON /var/log/syslog | tail -20

# Test manually with full paths
cd /home/pi/pihole-optimizer-agent && /home/pi/.local/bin/uv run python src/agent/analyzer.py

# Verify crontab
crontab -l
```

## Project Structure

```
pihole-optimizer-agent/
├── src/
│   ├── mcp_server/
│   │   └── server.py           # MCP HTTP server (exposes PiHole tools)
│   ├── tools/
│   │   └── pihole_tools.py     # PiHole CLI wrappers
│   └── agent/
│       └── analyzer.py         # LangGraph agent (main analysis logic)
├── systemd/
│   ├── pihole-mcp.service.example  # Service file for auto-start
│   └── README.md               # Systemd setup guide
├── logs/
│   ├── report_*.md             # Analysis reports
│   ├── audit.jsonl             # Audit log of all changes
│   └── cron.log                # Cron execution log
├── .env.example                # Environment template
├── pyproject.toml              # Python dependencies
└── README.md                   # This file
```

## How It Works

### Workflow

1. **OBSERVE** (Collect Data)
   - Parses PiHole logs for recent DNS queries
   - Gathers top blocked/permitted domains
   - Tracks client activity patterns

2. **ANALYZE** (Claude AI)
   - Sends collected data to Claude API
   - Identifies patterns, anomalies, false positives
   - Generates recommendations with reasoning

3. **PROPOSE** (Safety Filter)
   - Categorizes recommendations by risk level
   - Filters for auto-apply vs. human review
   - Applies safety limits (max changes per run)

4. **APPLY** (Execute Changes)
   - Whitelists/blacklists approved domains via PiHole CLI
   - Logs all actions to audit trail
   - Only applies low-risk changes automatically

5. **REPORT** (Generate Summary)
   - Creates markdown report with findings
   - Optionally emails summary
   - Saves to `logs/` directory

### Safety Features

- **Human-in-the-loop**: High-risk changes require manual review
- **Audit logging**: All changes recorded with timestamps and reasoning
- **Rate limiting**: Max 5 auto-changes per run (configurable)
- **Risk scoring**: Claude assigns risk levels to each recommendation
- **Rollback**: All changes logged in audit.jsonl for easy reversal

## Cost Estimate

**Claude API costs** (as of Feb 2026):
- Model: Claude Sonnet 4.5
- Per analysis: ~2,000-5,000 tokens
- Cost: ~$0.01-0.05 per run
- Running every 6 hours: **~$3-6/month**

Costs scale with:
- DNS query volume
- Number of unique domains
- Analysis time window

## Contributing

Contributions welcome! Areas for improvement:

- [ ] Support for additional DNS blockers (AdGuard Home, DNSmasq)
- [ ] Web dashboard for reviewing recommendations
- [ ] Integration with Suricata/ntopng for network context
- [ ] DGA (Domain Generation Algorithm) detection
- [ ] Botnet C2 pattern recognition
- [ ] Machine learning for network baseline

## License

MIT License - see LICENSE file

## Acknowledgments

- Built with [FastMCP](https://github.com/jlowin/fastmcp) by Marvin AI
- Powered by [Anthropic's Claude API](https://www.anthropic.com/)
- Uses [LangGraph](https://github.com/langchain-ai/langgraph) for agent orchestration
- Designed for [Pi-hole](https://pi-hole.net/)

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/pihole-optimizer-agent/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/pihole-optimizer-agent/discussions)
- **Guide**: See [pihole_mcp_implementation_guide.md](pihole_mcp_implementation_guide.md) for detailed setup

## Roadmap

- [x] Core MCP server with PiHole tools
- [x] LangGraph agent with Claude integration
- [x] Automated scheduling with cron
- [x] Audit logging
- [ ] Email notifications (partially implemented)
- [ ] Web dashboard
- [ ] Multi-device DNS analysis
- [ ] Advanced threat detection
- [ ] Custom blocklist learning

---

**Made with ❤️ for the PiHole community**

If this project helps you, consider:
- ⭐ Starring the repo
- 🐛 Reporting bugs
- 💡 Suggesting features
- 📖 Improving documentation
