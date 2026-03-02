"""
Firewall tools — Phase 1 dry-run stub.

In Phase 1, this module logs what it WOULD do without touching the firewall.
In Phase 2, it will be replaced with real nftables commands.

Every function checks protected_entities before acting. This check is in
the TOOL layer (not the agent layer) so it cannot be bypassed by prompt
injection or agent logic.
"""

import json
import os
import logging
from datetime import datetime, timedelta
from typing import Optional

from config.protected_entities import is_protected_ip, is_blocked_command

logger = logging.getLogger(__name__)

# Rollback log — tracks all actions and their inverses
ROLLBACK_LOG_FILE = os.path.expanduser("~/.soc-agent/rollback_log.json")

# Shadow action log — records what the agent WOULD have done
SHADOW_LOG_FILE = os.path.expanduser("~/.soc-agent/shadow_actions.jsonl")

# Default block TTL (seconds). Auto-rollback after this window unless
# the human explicitly confirms.
DEFAULT_BLOCK_TTL = int(os.getenv("BLOCK_TTL_SECONDS", "3600"))  # 1 hour


def _load_rollback_log() -> list[dict]:
    """Load the rollback log from disk."""
    try:
        with open(ROLLBACK_LOG_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_rollback_log(log: list[dict]) -> None:
    """Save the rollback log to disk."""
    os.makedirs(os.path.dirname(ROLLBACK_LOG_FILE), exist_ok=True)
    with open(ROLLBACK_LOG_FILE, "w") as f:
        json.dump(log, f, indent=2)


def _write_shadow_log(entry: dict) -> None:
    """Append to the shadow actions log (what the agent would have done)."""
    os.makedirs(os.path.dirname(SHADOW_LOG_FILE), exist_ok=True)
    with open(SHADOW_LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


def block_external_ip(
    ip: str,
    reason: str,
    action_id: str,
    ttl_seconds: int = DEFAULT_BLOCK_TTL,
) -> dict:
    """
    Block an external IP address in the FORWARD chain.

    Phase 1: DRY-RUN ONLY. Logs the action but does not execute it.
    Phase 2: Will use nftables to add a DROP rule with auto-rollback TTL.

    Args:
        ip: The external IP to block
        reason: Why this IP is being blocked
        action_id: Unique action identifier for rollback tracking
        ttl_seconds: Auto-rollback after this many seconds

    Returns:
        Dict with success, message, and rollback info
    """
    # SAFETY: Protected entity check (cannot be bypassed)
    if is_protected_ip(ip):
        logger.warning(f"BLOCKED: Attempted to block protected IP {ip}")
        return {
            "success": False,
            "message": f"Cannot block {ip} — it is a protected entity",
            "dry_run": True,
        }

    auto_rollback_at = (
        datetime.now() + timedelta(seconds=ttl_seconds)
    ).isoformat()

    # Phase 2 commands (not executed yet):
    # block_cmd = f"nft add rule ip filter forward ip saddr {ip} drop"
    # rollback_cmd = f"nft delete rule ip filter forward handle $HANDLE"

    action_record = {
        "action_id": action_id,
        "action": "block_external_ip",
        "target": ip,
        "reason": reason,
        "command": f"[DRY-RUN] nft add rule ip filter forward ip saddr {ip} drop",
        "rollback_command": f"[DRY-RUN] nft delete rule ip filter forward (handle for {ip})",
        "auto_rollback_at": auto_rollback_at,
        "ttl_seconds": ttl_seconds,
        "executed_at": datetime.now().isoformat(),
        "dry_run": True,
        "confirmed_by_human": False,
        "rolled_back": False,
    }

    # Log to shadow actions
    _write_shadow_log(action_record)

    # Add to rollback log
    rollback_log = _load_rollback_log()
    rollback_log.append(action_record)
    _save_rollback_log(rollback_log)

    logger.info(f"[DRY-RUN] Would block external IP {ip}: {reason} (TTL: {ttl_seconds}s)")

    return {
        "success": True,
        "message": f"[DRY-RUN] Would block {ip} (TTL: {ttl_seconds}s)",
        "action_id": action_id,
        "auto_rollback_at": auto_rollback_at,
        "dry_run": True,
    }


def unblock_external_ip(ip: str, action_id: str) -> dict:
    """
    Remove a block on an external IP.

    Phase 1: DRY-RUN ONLY.
    Phase 2: Will use nftables to remove the DROP rule.
    """
    if is_protected_ip(ip):
        return {
            "success": True,
            "message": f"{ip} is a protected entity — was never blocked",
            "dry_run": True,
        }

    # Mark as rolled back in the log
    rollback_log = _load_rollback_log()
    for entry in rollback_log:
        if entry.get("target") == ip and not entry.get("rolled_back"):
            entry["rolled_back"] = True
            entry["rolled_back_at"] = datetime.now().isoformat()

    _save_rollback_log(rollback_log)

    logger.info(f"[DRY-RUN] Would unblock external IP {ip}")

    return {
        "success": True,
        "message": f"[DRY-RUN] Would unblock {ip}",
        "dry_run": True,
    }


def process_auto_rollbacks() -> list[dict]:
    """
    Check for actions that have exceeded their TTL and roll them back.

    This should be called at the start of each agent cycle.
    In Phase 1 (dry-run), it just marks entries as rolled back in the log.
    In Phase 2, it will execute the actual rollback commands.

    Returns:
        List of actions that were rolled back
    """
    rollback_log = _load_rollback_log()
    rolled_back = []
    now = datetime.now()

    for entry in rollback_log:
        if entry.get("rolled_back") or entry.get("confirmed_by_human"):
            continue

        try:
            rollback_at = datetime.fromisoformat(entry["auto_rollback_at"])
        except (KeyError, ValueError):
            continue

        if now >= rollback_at:
            entry["rolled_back"] = True
            entry["rolled_back_at"] = now.isoformat()
            entry["rollback_reason"] = "TTL expired (auto-rollback)"
            rolled_back.append(entry)
            logger.info(
                f"[DRY-RUN] Auto-rollback triggered for {entry['target']} "
                f"(action: {entry['action_id']})"
            )

    if rolled_back:
        _save_rollback_log(rollback_log)

    return rolled_back


def confirm_block(action_id: str) -> dict:
    """
    Human confirms a block, preventing auto-rollback.

    Called when the human clicks the confirmation link in an alert email.
    """
    rollback_log = _load_rollback_log()
    for entry in rollback_log:
        if entry.get("action_id") == action_id:
            entry["confirmed_by_human"] = True
            entry["confirmed_at"] = datetime.now().isoformat()
            _save_rollback_log(rollback_log)
            logger.info(f"Block confirmed by human: {action_id}")
            return {"success": True, "message": f"Block {action_id} confirmed"}

    return {"success": False, "message": f"Action {action_id} not found"}


def rollback_all(hours: int = 24) -> dict:
    """
    Emergency stop: rollback ALL SOC actions from the last N hours.

    This is the "oh no" button. It undoes every automated action
    regardless of confirmation status.
    """
    rollback_log = _load_rollback_log()
    cutoff = datetime.now() - timedelta(hours=hours)
    rolled_back = []

    for entry in rollback_log:
        try:
            executed_at = datetime.fromisoformat(entry["executed_at"])
        except (KeyError, ValueError):
            continue

        if executed_at >= cutoff and not entry.get("rolled_back"):
            entry["rolled_back"] = True
            entry["rolled_back_at"] = datetime.now().isoformat()
            entry["rollback_reason"] = f"Emergency rollback (last {hours}h)"
            rolled_back.append(entry)

    _save_rollback_log(rollback_log)
    logger.warning(f"Emergency rollback: {len(rolled_back)} actions rolled back")

    return {
        "success": True,
        "rolled_back_count": len(rolled_back),
        "actions": rolled_back,
    }


def get_active_blocks() -> list[dict]:
    """Get all currently active (non-rolled-back, non-expired) blocks."""
    rollback_log = _load_rollback_log()
    now = datetime.now()

    active = []
    for entry in rollback_log:
        if entry.get("rolled_back"):
            continue
        try:
            rollback_at = datetime.fromisoformat(entry["auto_rollback_at"])
            if now < rollback_at or entry.get("confirmed_by_human"):
                active.append(entry)
        except (KeyError, ValueError):
            continue

    return active
