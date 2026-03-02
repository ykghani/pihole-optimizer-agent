"""
SOC agent safety system: circuit breakers, rate limiters, and rollback engine.

This module enforces hard limits on what the agent can do, regardless of
what Claude classifies or what the LangGraph workflow proposes. Safety
checks run in the TOOL LAYER — they cannot be bypassed by agent logic.

Design principle: fail safe, fail small, fail visibly.
"""

import json
import os
import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from config.protected_entities import is_protected_ip, is_protected_domain

logger = logging.getLogger(__name__)

# Persistent state files
SAFETY_STATE_FILE = os.path.expanduser("~/.soc-agent/safety_state.json")
HEARTBEAT_FILE = os.path.expanduser("~/.soc-agent/heartbeat.json")
METRICS_FILE = os.path.expanduser("~/.soc-agent/metrics.jsonl")


# ---------------------------------------------------------------------------
# Circuit breaker limits
# ---------------------------------------------------------------------------

SAFETY_LIMITS = {
    "max_actions_per_run": 3,
    "max_actions_per_hour": 10,
    "max_actions_per_day": 30,
    "max_blocks_per_hour": 2,
    "max_blocks_per_day": 5,
    "max_api_calls_per_hour": 30,
    "max_enrichment_per_run": 20,
    "cooldown_after_error_seconds": 300,   # 5-minute cooldown
    "lockout_after_consecutive_errors": 3,
    "lockout_duration_minutes": 30,
}

# Daily Claude API cost cap (estimated from token counts)
DAILY_API_COST_CAP_USD = float(os.getenv("SOC_DAILY_API_CAP", "2.0"))


# ---------------------------------------------------------------------------
# Safety state persistence
# ---------------------------------------------------------------------------

def _load_safety_state() -> dict:
    """Load persistent safety state from disk."""
    try:
        with open(SAFETY_STATE_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "action_log": [],          # List of {timestamp, action_type, target}
            "consecutive_errors": 0,
            "lockout_until": None,
            "daily_api_tokens": 0,
            "daily_api_date": None,
        }


def _save_safety_state(state: dict) -> None:
    """Save safety state to disk."""
    os.makedirs(os.path.dirname(SAFETY_STATE_FILE), exist_ok=True)
    with open(SAFETY_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ---------------------------------------------------------------------------
# Circuit breaker checks
# ---------------------------------------------------------------------------

def check_budget(action_type: str = "action") -> dict:
    """
    Check if the agent has budget remaining for an action.

    Must be called BEFORE every write operation. Returns:
    {
        "allowed": bool,
        "reason": str (if not allowed),
        "remaining": dict of remaining budgets
    }
    """
    state = _load_safety_state()
    now = datetime.now()

    # Check lockout
    if state.get("lockout_until"):
        lockout_end = datetime.fromisoformat(state["lockout_until"])
        if now < lockout_end:
            return {
                "allowed": False,
                "reason": f"Agent locked out until {lockout_end.isoformat()} "
                          f"(consecutive errors exceeded threshold)",
                "remaining": {},
            }
        else:
            # Lockout expired, reset
            state["lockout_until"] = None
            state["consecutive_errors"] = 0
            _save_safety_state(state)

    # Check cooldown after error
    if state.get("consecutive_errors", 0) > 0:
        last_action = state["action_log"][-1] if state["action_log"] else None
        if last_action:
            last_time = datetime.fromisoformat(last_action["timestamp"])
            cooldown = timedelta(seconds=SAFETY_LIMITS["cooldown_after_error_seconds"])
            if now - last_time < cooldown:
                return {
                    "allowed": False,
                    "reason": f"Cooling down after error (wait {SAFETY_LIMITS['cooldown_after_error_seconds']}s)",
                    "remaining": {},
                }

    # Count recent actions
    action_log = state.get("action_log", [])
    hour_ago = (now - timedelta(hours=1)).isoformat()
    day_ago = (now - timedelta(hours=24)).isoformat()

    actions_this_hour = sum(1 for a in action_log if a["timestamp"] > hour_ago)
    actions_today = sum(1 for a in action_log if a["timestamp"] > day_ago)
    blocks_this_hour = sum(
        1 for a in action_log
        if a["timestamp"] > hour_ago and a.get("action_type") in ("block_ip", "block_domain")
    )
    blocks_today = sum(
        1 for a in action_log
        if a["timestamp"] > day_ago and a.get("action_type") in ("block_ip", "block_domain")
    )

    # Check limits
    if actions_this_hour >= SAFETY_LIMITS["max_actions_per_hour"]:
        return {
            "allowed": False,
            "reason": f"Hourly action limit reached ({actions_this_hour}/{SAFETY_LIMITS['max_actions_per_hour']})",
            "remaining": {"actions_this_hour": 0},
        }

    if actions_today >= SAFETY_LIMITS["max_actions_per_day"]:
        return {
            "allowed": False,
            "reason": f"Daily action limit reached ({actions_today}/{SAFETY_LIMITS['max_actions_per_day']})",
            "remaining": {"actions_today": 0},
        }

    if action_type in ("block_ip", "block_domain"):
        if blocks_this_hour >= SAFETY_LIMITS["max_blocks_per_hour"]:
            return {
                "allowed": False,
                "reason": f"Hourly block limit reached ({blocks_this_hour}/{SAFETY_LIMITS['max_blocks_per_hour']})",
                "remaining": {"blocks_this_hour": 0},
            }
        if blocks_today >= SAFETY_LIMITS["max_blocks_per_day"]:
            return {
                "allowed": False,
                "reason": f"Daily block limit reached ({blocks_today}/{SAFETY_LIMITS['max_blocks_per_day']})",
                "remaining": {"blocks_today": 0},
            }

    return {
        "allowed": True,
        "reason": "",
        "remaining": {
            "actions_this_hour": SAFETY_LIMITS["max_actions_per_hour"] - actions_this_hour,
            "actions_today": SAFETY_LIMITS["max_actions_per_day"] - actions_today,
            "blocks_this_hour": SAFETY_LIMITS["max_blocks_per_hour"] - blocks_this_hour,
            "blocks_today": SAFETY_LIMITS["max_blocks_per_day"] - blocks_today,
        },
    }


def record_action(action_type: str, target: str, success: bool) -> None:
    """Record an action in the safety state for rate limiting."""
    state = _load_safety_state()

    state["action_log"].append({
        "timestamp": datetime.now().isoformat(),
        "action_type": action_type,
        "target": target,
        "success": success,
    })

    # Prune old entries (keep last 7 days)
    cutoff = (datetime.now() - timedelta(days=7)).isoformat()
    state["action_log"] = [a for a in state["action_log"] if a["timestamp"] > cutoff]

    # Track consecutive errors
    if not success:
        state["consecutive_errors"] = state.get("consecutive_errors", 0) + 1
        if state["consecutive_errors"] >= SAFETY_LIMITS["lockout_after_consecutive_errors"]:
            lockout_end = datetime.now() + timedelta(
                minutes=SAFETY_LIMITS["lockout_duration_minutes"]
            )
            state["lockout_until"] = lockout_end.isoformat()
            logger.warning(
                f"LOCKOUT: {state['consecutive_errors']} consecutive errors. "
                f"Agent locked out until {lockout_end.isoformat()}"
            )
    else:
        state["consecutive_errors"] = 0

    _save_safety_state(state)


# ---------------------------------------------------------------------------
# API cost tracking
# ---------------------------------------------------------------------------

def check_api_budget(estimated_tokens: int = 0) -> dict:
    """
    Check if the daily Claude API budget allows another call.

    Estimates cost from token count using Sonnet pricing.
    """
    state = _load_safety_state()
    today = datetime.now().strftime("%Y-%m-%d")

    # Reset daily counter at midnight
    if state.get("daily_api_date") != today:
        state["daily_api_tokens"] = 0
        state["daily_api_date"] = today

    # Rough cost estimate (Sonnet pricing: ~$3/M input, ~$15/M output)
    # Approximate blended rate: ~$5/M tokens
    total_tokens = state["daily_api_tokens"] + estimated_tokens
    estimated_cost = total_tokens * 5 / 1_000_000

    if estimated_cost > DAILY_API_COST_CAP_USD:
        return {
            "allowed": False,
            "reason": f"Daily API budget exceeded (est. ${estimated_cost:.2f} > ${DAILY_API_COST_CAP_USD})",
            "tokens_used_today": state["daily_api_tokens"],
        }

    return {
        "allowed": True,
        "reason": "",
        "tokens_used_today": state["daily_api_tokens"],
        "estimated_cost": estimated_cost,
    }


def record_api_usage(tokens: int) -> None:
    """Record Claude API token usage for cost tracking."""
    state = _load_safety_state()
    today = datetime.now().strftime("%Y-%m-%d")

    if state.get("daily_api_date") != today:
        state["daily_api_tokens"] = 0
        state["daily_api_date"] = today

    state["daily_api_tokens"] += tokens
    _save_safety_state(state)


# ---------------------------------------------------------------------------
# Protected entity validation
# ---------------------------------------------------------------------------

def validate_action_target(action_type: str, target: str) -> dict:
    """
    Validate that an action target is not a protected entity.

    This is the final safety gate before any action is executed.
    Called by the MCP tool layer, not the agent layer.
    """
    if action_type in ("block_ip", "isolate_device"):
        if is_protected_ip(target):
            return {
                "allowed": False,
                "reason": f"Cannot {action_type} {target} — protected entity",
            }

    if action_type == "block_domain":
        if is_protected_domain(target):
            return {
                "allowed": False,
                "reason": f"Cannot block domain {target} — protected entity",
            }

    return {"allowed": True, "reason": ""}


# ---------------------------------------------------------------------------
# Mode enforcement
# ---------------------------------------------------------------------------

def is_action_allowed_in_mode(soc_mode: str, action_type: str, classification: str) -> dict:
    """
    Check if an action is allowed in the current SOC_MODE.

    Modes:
    - shadow: No actions, no emails
    - recommend: No actions, emails only
    - auto_suppress: Only FP suppression actions
    - active: FP suppression + external IP blocking (with TTL)
    """
    if soc_mode == "shadow":
        return {
            "allowed": False,
            "reason": f"SOC_MODE=shadow — observe only, no actions",
        }

    if soc_mode == "recommend":
        return {
            "allowed": False,
            "reason": f"SOC_MODE=recommend — recommendations only, no automated actions",
        }

    if soc_mode == "auto_suppress":
        if action_type == "suppress" and classification == "false_positive":
            return {"allowed": True, "reason": ""}
        return {
            "allowed": False,
            "reason": f"SOC_MODE=auto_suppress — only FP suppression is automated",
        }

    if soc_mode == "active":
        # In active mode, FP suppression and external IP blocking are automated
        if action_type in ("suppress", "block_ip"):
            return {"allowed": True, "reason": ""}
        return {
            "allowed": False,
            "reason": f"Action '{action_type}' requires human approval even in active mode",
        }

    return {
        "allowed": False,
        "reason": f"Unknown SOC_MODE: {soc_mode}",
    }


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------

def write_heartbeat(
    run_id: str,
    events_processed: int,
    actions_taken: int,
    errors: list,
    sources_available: list,
    run_duration_seconds: float,
) -> None:
    """Write heartbeat file for the watchdog to check."""
    os.makedirs(os.path.dirname(HEARTBEAT_FILE), exist_ok=True)
    heartbeat = {
        "last_run": datetime.now().isoformat(),
        "run_id": run_id,
        "run_duration_seconds": run_duration_seconds,
        "events_processed": events_processed,
        "actions_taken": actions_taken,
        "errors": errors,
        "sources_available": sources_available,
    }
    with open(HEARTBEAT_FILE, "w") as f:
        json.dump(heartbeat, f, indent=2)


# ---------------------------------------------------------------------------
# Metrics logging
# ---------------------------------------------------------------------------

def log_metrics(metrics: dict) -> None:
    """Append run metrics to the metrics log (JSONL format)."""
    os.makedirs(os.path.dirname(METRICS_FILE), exist_ok=True)
    metrics["timestamp"] = datetime.now().isoformat()
    with open(METRICS_FILE, "a") as f:
        f.write(json.dumps(metrics) + "\n")


# ---------------------------------------------------------------------------
# Integrity checks
# ---------------------------------------------------------------------------

def compute_source_hashes(source_files: list[str]) -> dict[str, str]:
    """
    Compute SHA-256 hashes of the agent's source files.

    Used at startup to detect tampering. If hashes change without
    a corresponding git commit, the agent should halt.
    """
    hashes = {}
    for filepath in source_files:
        try:
            with open(filepath, "rb") as f:
                hashes[filepath] = hashlib.sha256(f.read()).hexdigest()
        except FileNotFoundError:
            hashes[filepath] = "MISSING"
    return hashes
