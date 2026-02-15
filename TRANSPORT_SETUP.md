# PiHole MCP Server - Dual Transport Setup

## Overview

This project runs the MCP server with **two transports simultaneously** to support different clients:

```
┌─────────────────────────────────────────────────────────────┐
│                        Pi5 Server                           │
│                                                             │
│  ┌─────────────────────┐      ┌─────────────────────┐     │
│  │  UNIX Socket        │      │  HTTP Server        │     │
│  │  /tmp/pihole-       │      │  http://localhost:  │     │
│  │  mcp.sock           │      │  8765/mcp           │     │
│  └──────────┬──────────┘      └──────────┬──────────┘     │
│             │                            │                 │
│             │    ┌──────────────────┐    │                 │
│             └────┤  MCP Tools       ├────┘                 │
│                  │  (pihole_tools)  │                      │
│                  └──────────────────┘                      │
└─────────────────────────────────────────────────────────────┘
         ▲                                    ▲
         │                                    │
    ┌────┴─────┐                         ┌───┴────┐
    │ Claude   │                         │analyzer│
    │ Desktop  │                         │  .py   │
    │ (Mac)    │                         │ (Pi5)  │
    └──────────┘                         └────────┘
```

## Why Two Transports?

### UNIX Socket (stdio transport)
- **Client:** Claude Desktop on your Mac
- **Location:** `/tmp/pihole-mcp.sock`
- **Started by:** `socat` (already running since Feb 13)
- **Access:** Via SSH/Tailscale only (local file-based)
- **Use case:** Interactive MCP sessions with Claude

### HTTP Server
- **Client:** `analyzer.py` automation agent
- **Location:** `http://localhost:8765/mcp`
- **Started by:** systemd service (this guide)
- **Access:** Network-accessible (local, LAN, Tailscale)
- **Use case:** Automated analysis, cron jobs, API access

## Installation

### Step 1: Install HTTP Server Service

On your Pi5:
```bash
cd ~/pihole-agent

# Copy the example service file
sudo cp systemd/pihole-mcp.service.example /etc/systemd/system/pihole-mcp.service

# Edit if your paths differ
sudo nano /etc/systemd/system/pihole-mcp.service

# Install and start
sudo systemctl daemon-reload
sudo systemctl enable --now pihole-mcp.service
```

See [systemd/README.md](systemd/README.md) for detailed installation instructions.

This will:
- ✅ Install systemd service
- ✅ Enable auto-start on boot
- ✅ Start the HTTP server immediately

### Step 3: Verify Both Transports

```bash
# Check UNIX socket (for Claude Desktop)
ls -lh /tmp/pihole-mcp.sock

# Check HTTP server (for analyzer.py)
curl -X POST http://localhost:8765/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq .

# Check systemd service
sudo systemctl status pihole-mcp-http
```

## Service Management

```bash
# View live logs
sudo journalctl -u pihole-mcp-http -f

# Restart after code changes
sudo systemctl restart pihole-mcp-http

# Stop the service
sudo systemctl stop pihole-mcp-http

# Disable auto-start
sudo systemctl disable pihole-mcp-http
```

## Testing the Analyzer

After installation, test the analyzer:

```bash
cd ~/pihole-agent
uv run python src/agent/analyzer.py
```

You should see successful HTTP requests to `http://localhost:8765/mcp`.

## Environment Variables

Both transports read from the same `.env` file:

```bash
# HTTP server port (default: 8765)
MCP_SERVER_PORT=8765

# PiHole connection
PIHOLE_HOST=localhost

# For analyzer.py
ANTHROPIC_API_KEY=your_key_here
EMAIL_ADDRESS=your@email.com
```

## Troubleshooting

### "Connection refused" errors
```bash
# Check if HTTP server is running
sudo systemctl status pihole-mcp-http

# Check if port is listening
sudo ss -tlnp | grep 8765
```

### Service won't start
```bash
# View error logs
sudo journalctl -u pihole-mcp-http -n 50 --no-pager

# Check Python environment
cd ~/pihole-agent
uv run python src/mcp_server/server.py
```

### Port already in use
```bash
# Find what's using port 8765
sudo lsof -i :8765

# Change port in .env file
echo "MCP_SERVER_PORT=8766" >> .env
sudo systemctl restart pihole-mcp-http
```

## Architecture Notes

- **UNIX socket** is created by the existing `socat` process (PID 135490)
- **HTTP server** is managed by the new systemd service
- Both can run simultaneously without conflict
- They share the same MCP tool implementations
- The HTTP server listens on `0.0.0.0` (all interfaces) for Tailscale access if needed

## Future: Cron Job for Analyzer

Once the HTTP service is stable, you can schedule the analyzer:

```bash
# Edit crontab
crontab -e

# Run every 6 hours
0 */6 * * * cd /home/pi5/pihole-agent && /home/pi5/.local/bin/uv run python src/agent/analyzer.py >> /home/pi5/pihole-agent/logs/cron.log 2>&1
```
