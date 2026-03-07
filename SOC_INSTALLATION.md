# SOC Agent — Installation, Baseline & Testing Guide

This guide covers installing the SOC agent on your Raspberry Pi, establishing a performance baseline in shadow mode, and progressively testing its functionality.

**Prerequisites:** PiHole agent already installed and working. Suricata and ntopng already running on the Pi.

---

## Part 1 — Installation

### Step 1 — Deploy the Code

```bash
# On your Mac — commit and push
cd /path/to/pihole-optimizer-agent
git add -A && git commit -m "Add SOC agent"
git push

# SSH into the Pi
ssh pi5@192.168.1.221
cd ~/pihole-agent
git pull
```

### Step 2 — Configure Environment

```bash
cp .env.example .env
nano .env
```

Fill in these values (others can stay at defaults initially):

```ini
# Existing PiHole settings — leave as-is
ANTHROPIC_API_KEY=sk-ant-...
EMAIL_ADDRESS=your@gmail.com
GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
APPROVAL_SECRET=<run: python3 -c "import secrets; print(secrets.token_hex(32))">

# SOC — start in shadow mode (observe only, no actions)
SOC_MODE=shadow

# Suricata (confirm path with: ls /var/log/suricata/)
SURICATA_EVE_PATH=/var/log/suricata/eve.json

# ntopng (confirm port with: systemctl status ntopng)
NTOPNG_URL=http://192.168.1.221:3000
NTOPNG_USER=admin
NTOPNG_PASSWORD=<your ntopng admin password>

# Neo4j (set BEFORE starting Docker)
NEO4J_PASSWORD=<choose a strong password>
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
```

Protect the file:

```bash
chmod 600 .env
```

### Step 3 — Update Protected Entities

Open `src/config/protected_entities.py` and verify the hardcoded IPs match your network:

```bash
nano src/config/protected_entities.py
```

Key values to confirm/update:
- `"192.168.1.1"` — your router's IP
- `"192.168.1.221"` — your Pi's IP (the device running the agent)
- `IPv4Network("192.168.1.0/24")` — your LAN subnet

These are **not** driven by `.env` — they are intentionally hardcoded so the LLM cannot influence them.

### Step 4 — Update Known-Safe MAC Addresses

Open `src/config/known_safe.py` and populate your device MAC-to-hostname mapping. This enables ARP spoofing detection and reduces false positives on your own devices.

Get current device MACs from your PiHole admin UI (Network tab) or:

```bash
arp -n
```

### Step 5 — Start Neo4j

```bash
cd ~/pihole-agent/neo4j
docker compose up -d

# Wait ~30s for Neo4j to fully start
sleep 30
docker compose logs neo4j | tail -20
docker ps | grep neo4j
```

Seed the graph schema (creates uniqueness constraints and indexes):

```bash
source ~/.env 2>/dev/null || true
docker exec -i neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD" < seed_schema.cypher
```

Verify via browser: `http://192.168.1.221:7474` — run `:schema` to confirm constraints were created.

### Step 6 — Install Python Dependencies

```bash
cd ~/pihole-agent
uv sync
```

---

## Part 2 — Smoke Tests

Run these in order. Stop if any fails — each one tests a dependency of the next.

### Test 1 — Suricata

```bash
uv run python -c "
import sys; sys.path.insert(0, 'src')
from tools.suricata_tools import get_new_alerts
r = get_new_alerts()
print(f'Suricata: {r[\"total_new_lines\"]} new lines, {len(r[\"alerts\"])} alerts')
print(f'Truncated: {r[\"truncated\"]}')
"
```

**Expected:** Line count and alert count printed. If truncated=True on first run, that's normal — the offset was 0 so it read from the start of a large log. It will only read new events on subsequent runs.

### Test 2 — ntopng

```bash
uv run python -c "
import sys, asyncio; sys.path.insert(0, 'src')
from tools.ntopng_tools import get_active_hosts, parse_hosts_response
r = asyncio.run(get_active_hosts())
if 'error' in r:
    print('ntopng ERROR:', r['error'])
else:
    hosts = parse_hosts_response(r)
    print(f'ntopng OK — {len(hosts)} active hosts')
    for h in hosts[:3]:
        print(f'  {h[\"ip\"]} ({h[\"name\"]})')
"
```

**Expected:** List of active hosts on your network. If you see an HTTP 401 error, verify `NTOPNG_USER`/`NTOPNG_PASSWORD` match the ntopng admin credentials.

### Test 3 — Neo4j

```bash
    uv run python -c "
    import sys; sys.path.insert(0, 'src')
    from dotenv import load_dotenv; load_dotenv()
    from tools.neo4j_tools import get_neo4j_stats
    print(get_neo4j_stats())
    "
```

**Expected:** JSON with node counts. Warnings about labels not existing (e.g. `Finding`) are normal on a fresh database — they disappear once the agent has run. The `status: ok` field confirms connectivity.

### Test 4 — Safety System

```bash
uv run python -c "
import sys; sys.path.insert(0, 'src')
from dotenv import load_dotenv; load_dotenv()
from agent.soc_safety import SafetySystem
s = SafetySystem()
print('Safety system OK, mode:', s.soc_mode)
print('Budget check:', s.check_budget())
"
```

**Expected:** `Safety system OK, mode: shadow` and a budget check showing limits remaining.

### Test 5 — Full Dry Run

```bash
uv run python src/agent/soc_agent.py
```

**Expected:** The agent runs one full cycle: collects events, deduplicates, enriches, correlates, classifies (heuristics for clear cases, queues ambiguous for later enrichment), then takes NO action (shadow mode) and writes heartbeat/metrics. Check for tracebacks — warnings are OK, errors need investigation.

---

## Part 3 — Install Systemd Services

The SOC agent uses **two timers** with different responsibilities:

| Service | Timer | Frequency | Uses Claude? |
|---------|-------|-----------|-------------|
| `soc-agent` | `soc-agent.timer` | Every 2 min | No — heuristics only |
| `soc-enrich` | `soc-enrich.timer` | Every hour | Yes — classifies queued ambiguous events |

Events that heuristics cannot classify are written to `~/.soc-agent/ambiguous_queue.jsonl` during each 2-minute cycle. The enrichment service drains this queue once per hour and sends all queued events to Claude in a single batched call.

### SOC Agent Service and Timer (2-min heuristic cycle)

```bash
sudo cp systemd/soc-agent.service.example /etc/systemd/system/soc-agent.service
sudo cp systemd/soc-agent.timer.example /etc/systemd/system/soc-agent.timer
```

Edit the service file to match your username and paths:

```bash
sudo nano /etc/systemd/system/soc-agent.service
```

Lines to update (replace `your-username` with your actual username):
```ini
User=your-username
Group=your-username
WorkingDirectory=/home/your-username/pihole-optimizer-agent
EnvironmentFile=/home/your-username/pihole-optimizer-agent/.env
ExecStart=/home/your-username/.local/bin/uv run python src/agent/soc_agent.py
ReadWritePaths=/home/your-username/.soc-agent /home/your-username/pihole-agent/logs /home/your-username/.cache/uv /home/your-username/pihole-optimizer-agent/.venv
```

### SOC Enrichment Service and Timer (hourly Claude cycle)

```bash
sudo cp systemd/soc-enrich.service.example /etc/systemd/system/soc-enrich.service
sudo cp systemd/soc-enrich.timer.example /etc/systemd/system/soc-enrich.timer
```

Edit the enrichment service file with the same path substitutions:

```bash
sudo nano /etc/systemd/system/soc-enrich.service
```

### Enable Both Timers

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now soc-agent.timer soc-enrich.timer

# Confirm both are scheduled
systemctl list-timers soc-agent.timer soc-enrich.timer

# Watch the 2-minute heuristic cycle
sudo journalctl -u soc-agent.service -f

# Watch the hourly enrichment cycle (runs ~5 min after boot)
sudo journalctl -u soc-enrich.service -f
```

### Verify the Queue is Being Used

After the agent fires once, check that ambiguous events are being queued:

```bash
# Should show > 0 lines after first 2-min cycle
wc -l ~/.soc-agent/ambiguous_queue.jsonl

# Force an enrichment run immediately (don't wait an hour)
sudo systemctl start soc-enrich.service
sudo journalctl -u soc-enrich.service -f

# Queue should be empty after enrichment
wc -l ~/.soc-agent/ambiguous_queue.jsonl
```

---

## Part 4 — Establish a Performance Baseline (Shadow Mode)

Run in `shadow` mode for **at least 2 weeks** before promoting. This period:
- Builds the Neo4j knowledge graph with device and alert history
- Reveals false positive rate on your normal traffic
- Lets you tune `known_safe.py` without risk

### Daily Health Check (Week 1)

```bash
# Did the agent run? (check heartbeat age)
cat ~/.soc-agent/heartbeat.json | python3 -m json.tool

# Is it seeing events?
tail -5 ~/.soc-agent/metrics.jsonl | python3 -m json.tool

# Any errors in the last hour?
sudo journalctl -u soc-agent.service --since "1 hour ago" | grep -i "error\|traceback"

# How many alerts has Neo4j seen so far?
uv run python -c "
import sys; sys.path.insert(0, 'src')
from dotenv import load_dotenv; load_dotenv()
from tools.neo4j_tools import get_neo4j_stats
s = get_neo4j_stats()
print(f'Devices: {s[\"device_count\"]}, Alerts: {s[\"alert_count\"]}, Domains: {s[\"domain_count\"]}')
"
```

### Classification Distribution Check (End of Week 1)

```bash
# What severity mix is the agent seeing?
grep '"source": "soc-agent"' ~/pihole-agent/logs/audit.jsonl 2>/dev/null \
  | python3 -c "
import sys, json, collections
counts = collections.Counter()
for line in sys.stdin:
    try:
        e = json.loads(line)
        for f in e.get('findings', []):
            counts[f.get('classification','?')] += 1
    except: pass
print(dict(counts))
"

# How many events were queued for enrichment vs classified by heuristics?
tail -50 ~/.soc-agent/metrics.jsonl | python3 -c "
import sys, json
total_queued = 0
total_classified = 0
for line in sys.stdin:
    try:
        m = json.loads(line)
        total_queued += m.get('pending_enrichment', 0)
        total_classified += m.get('classifications', 0)
    except: pass
total = total_queued + total_classified
print(f'Queued for Claude: {total_queued} ({100*total_queued//max(total,1)}%), Heuristics: {total_classified - total_queued} ({100*(total_classified-total_queued)//max(total,1)}%)')
"

# Check enrichment cycle is running successfully
sudo journalctl -u soc-enrich.service --since "24 hours ago" | grep -E "complete|error|Drained"
```

**Healthy baseline targets:**
- `soc-agent` runs successfully every 2 minutes (no gaps >5 min in heartbeat)
- `soc-enrich` runs every hour without errors (`journalctl -u soc-enrich.service`)
- FP rate on your own device traffic < 10%
- No `critical` classifications on known-good devices
- Enrichment queue is drained each hour (not accumulating unboundedly)
- Neo4j accumulating data without errors

### Week 2 — Tune False Positives

If specific IPs or domains are generating noisy false positives from your own devices, add them to `src/config/known_safe.py`:

```bash
nano src/config/known_safe.py
# Add IPs to KNOWN_SAFE_IPS or domains to KNOWN_SAFE_DOMAINS
```

Then restart:
```bash
sudo systemctl restart soc-agent.timer
```

### Save Your Baseline Snapshot

At the end of week 2, record the baseline stats before moving to `recommend` mode:

```bash
uv run python -c "
import sys; sys.path.insert(0, 'src')
from dotenv import load_dotenv; load_dotenv()
from tools.neo4j_tools import get_neo4j_stats
import json
stats = get_neo4j_stats()
print('=== Baseline snapshot ===')
print(json.dumps(stats, indent=2))
" | tee ~/.soc-agent/baseline_snapshot.json
```

---

## Part 5 — Escalating Agent Autonomy

### Promote to `recommend` Mode

Once the baseline looks healthy (2+ weeks, FP rate < 10%):

```bash
nano .env
# Change: SOC_MODE=recommend
sudo systemctl restart soc-agent.timer
```

In recommend mode, the agent emails you for MEDIUM/HIGH events. No automated actions are taken. Run in this mode for another 1–2 weeks and track:
- Are the emailed alerts accurate?
- Are you overriding many of them as false positives?

**Target before promoting to `auto_suppress`:** > 95% of emailed alerts are correct (not FPs you needed to manually dismiss).

### Promote to `auto_suppress` Mode

```bash
nano .env
# Change: SOC_MODE=auto_suppress
sudo systemctl restart soc-agent.timer
```

The agent now automatically suppresses signatures it has classified as false positive more than 5 times in 7 days. All other events still generate emails.

### Phase 2: `active` Mode (Future)

`active` mode adds external IP blocking via nftables. This is **not yet implemented** (Phase 2). Do not set `SOC_MODE=active` until the nftables integration is built and tested.

---

## Troubleshooting

### Suricata — Permission Denied

```bash
# Add pi5 user to the suricata group
sudo usermod -aG suricata pi5
# Log out and back in, then re-run the smoke test
```

### ntopng — HTTP 401 Unauthorized

Verify credentials by testing in the browser at `http://192.168.1.221:3000`. Then confirm the same credentials are in `.env`.

### Neo4j — Cannot Connect

```bash
# Is Docker running?
docker ps | grep neo4j

# If container stopped, restart it
cd ~/pihole-agent/neo4j
docker compose up -d

# Check Neo4j logs for errors
docker compose logs neo4j | tail -30
```

### SOC Agent Crashes on Start

```bash
sudo journalctl -u soc-agent.service -n 50 --no-pager
```

Common causes:
- Missing `.env` values (check `NEO4J_PASSWORD`, `ANTHROPIC_API_KEY`)
- Neo4j not running (check `docker ps`)
- Suricata eve.json not readable (check permissions)

### Agent Locked Out (Too Many Errors)

```bash
# View the safety state
cat ~/.soc-agent/safety_state.json | python3 -m json.tool

# To clear a lockout manually (reset consecutive_errors and lockout_until)
python3 -c "
import json
with open('/home/pi5/.soc-agent/safety_state.json') as f:
    s = json.load(f)
s['consecutive_errors'] = 0
s['lockout_until'] = None
with open('/home/pi5/.soc-agent/safety_state.json', 'w') as f:
    json.dump(s, f, indent=2)
print('Lockout cleared')
"
```

### Emergency Stop — Roll Back All Actions

```bash
uv run python -c "
import sys; sys.path.insert(0, 'src')
from dotenv import load_dotenv; load_dotenv()
from tools.firewall_tools import rollback_all
result = rollback_all(hours=24)
print(result)
"
```

---

## Network Coverage

By default the SOC agent sees:
- **All DNS traffic** — every device using PiHole as DNS resolver
- **Suricata alerts** — traffic through the interface Suricata is monitoring
- **ntopng flows** — traffic through ntopng's monitored interface

To get full LAN visibility (all inter-device traffic), you need one of:

| Approach | Description |
|----------|-------------|
| **Port mirroring** | Configure your managed switch to copy all LAN traffic to the Pi's NIC. Best option if your switch supports it (UniFi, Netgear Insight, Cisco). |
| **Gateway mode** | Route all traffic through the Pi. Maximum visibility but the Pi becomes a SPOF. |
| **DNS-only** | Current setup. Full DNS coverage already captures most threats. Gaps: direct-IP C2, LAN lateral movement. |

For port mirroring steps specific to your switch model, refer to your switch's documentation or open an issue.

---

## Performance Metrics Reference

These are the metrics tracked in `~/.soc-agent/metrics.jsonl` and used to inform autonomy escalation:

| Metric | Description | Target for `auto_suppress` | Target for `active` |
|--------|-------------|---------------------------|---------------------|
| FP accuracy | % of flagged events that were true positives | > 90% | > 95% |
| Classification agreement | % of Claude classifications matching heuristics | > 80% | > 85% |
| Recommendation acceptance | % of emailed alerts not overridden by you | > 90% | > 95% |
| Consecutive error-free days | Days without agent crashes or lockouts | > 14 | > 30 |
| API cost per day | Average Claude API spend | < $1.00 | < $2.00 |
