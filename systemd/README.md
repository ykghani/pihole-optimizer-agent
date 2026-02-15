# Systemd Service Installation

This directory contains systemd service files for running the PiHole MCP server as a background service.

## Quick Start

```bash
# 1. Copy the example service file
sudo cp systemd/pihole-mcp.service.example /etc/systemd/system/pihole-mcp.service

# 2. Edit paths if your installation differs from /home/pi5/pihole-agent
sudo nano /etc/systemd/system/pihole-mcp.service

# 3. Reload systemd and start the service
sudo systemctl daemon-reload
sudo systemctl enable --now pihole-mcp.service

# 4. Verify it's running
sudo systemctl status pihole-mcp.service
```

## What This Service Does

The `pihole-mcp.service` runs the MCP server with **HTTP transport** on port 8765. This allows:

- The `analyzer.py` agent to make automated API calls
- Network access to MCP tools (useful for remote management)
- Cron jobs and scheduled analysis tasks

## Dual Transport Setup

Many users run **two MCP transports simultaneously**:

1. **HTTP Server** (this service) - For programmatic access
   - Used by: analyzer.py, cron jobs, API clients
   - Endpoint: `http://localhost:8765/mcp`

2. **UNIX Socket** (separate socat process) - For Claude Desktop
   - Used by: Claude Desktop MCP integration
   - Socket: `/tmp/pihole-mcp.sock`

See [TRANSPORT_SETUP.md](../TRANSPORT_SETUP.md) for details on running both.

## Service Management

```bash
# View logs in real-time
sudo journalctl -u pihole-mcp.service -f

# Restart after code changes
sudo systemctl restart pihole-mcp.service

# Stop the service
sudo systemctl stop pihole-mcp.service

# Disable auto-start on boot
sudo systemctl disable pihole-mcp.service
```

## Troubleshooting

### Service won't start

```bash
# Check for errors
sudo journalctl -u pihole-mcp.service -n 50 --no-pager

# Common issues:
# 1. Port 8765 already in use - check: sudo ss -tlnp | grep 8765
# 2. Wrong paths in service file - verify WorkingDirectory
# 3. UV not installed - install: curl -LsSf https://astral.sh/uv/install.sh | sh
```

### "Read-only file system" error

The service uses security hardening (`ProtectHome=read-only`). If you see errors about being unable to write to files, add the path to `ReadWritePaths=` in the service file.

### Port already in use

If port 8765 is taken:

1. Find what's using it: `sudo lsof -i :8765`
2. Change the port in your `.env` file: `MCP_SERVER_PORT=8766`
3. Restart the service

## Environment Variables

The service reads configuration from `/home/pi5/pihole-agent/.env`:

```bash
# Server configuration
MCP_SERVER_PORT=8765        # HTTP server port
PIHOLE_HOST=localhost       # PiHole API host

# For analyzer.py
ANTHROPIC_API_KEY=sk-...    # Your Claude API key
EMAIL_ADDRESS=you@email.com # Where to send reports

# Logging
LOG_LEVEL=INFO
```

## Security Notes

The service includes several security hardening features:

- `NoNewPrivileges=true` - Prevents privilege escalation
- `ProtectSystem=strict` - Makes most of the filesystem read-only
- `ProtectHome=read-only` - Makes home directories read-only
- `ReadWritePaths=...` - Explicitly allow writes only where needed
- `MemoryMax=256M` - Limits memory usage
- `CPUQuota=50%` - Limits CPU usage

These settings prevent the service from accessing or modifying files outside its designated areas, reducing the impact of potential security vulnerabilities.

## Customization

To customize the service for your environment:

1. **User/Group**: Change `User=` and `Group=` to your username
2. **Installation Path**: Update `WorkingDirectory=` and all paths in `Environment=` and `ReadWritePaths=`
3. **Resource Limits**: Adjust `MemoryMax=` and `CPUQuota=` based on your system
4. **Port**: Set `MCP_SERVER_PORT` in `.env` file (default: 8765)
