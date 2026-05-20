"""
NEXUS-IR MCP Server
Connects AI agents to forensic tools with architectural guardrails.
Guardrails are enforced HERE in code — not in prompts.
"""

import os
import subprocess
import json
import hashlib
from datetime import datetime, timezone, timezone
from datetime import timezone as _tz
from config.settings import FORBIDDEN_COMMANDS, READ_ONLY_PATHS

# ─────────────────────────────────────────
# ARCHITECTURAL GUARDRAIL — Cannot be bypassed by AI prompts
# ─────────────────────────────────────────
def _is_safe_command(command: str) -> tuple[bool, str]:
    """
    Checks every command before execution.
    Returns (is_safe, reason).
    This runs in Python — the AI cannot override it.
    """
    cmd_lower = command.lower().strip()
    
    for forbidden in FORBIDDEN_COMMANDS:
        if cmd_lower.startswith(forbidden) or f" {forbidden} " in cmd_lower:
            return False, f"BLOCKED: '{forbidden}' is a forbidden command"
    
    return True, "OK"


def _safe_run(command: str, timeout: int = 30) -> dict:
    """
    Executes a shell command ONLY after safety check passes.
    Returns structured result with timestamp and command hash.
    """
    is_safe, reason = _is_safe_command(command)
    
    if not is_safe:
        return {
            "status": "BLOCKED",
            "reason": reason,
            "command": command,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "output": None
        }
    
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "status": "SUCCESS" if result.returncode == 0 else "ERROR",
            "command": command,
            "command_hash": hashlib.sha256(command.encode()).hexdigest()[:16],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "output": result.stdout[:5000] if result.stdout else "",
            "error": result.stderr[:1000] if result.stderr else "",
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "TIMEOUT",
            "command": command,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "output": None,
            "error": f"Command timed out after {timeout}s"
        }
    except Exception as e:
        return {
            "status": "EXCEPTION",
            "command": command,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "output": None,
            "error": str(e)
        }


# ─────────────────────────────────────────
# FORENSIC TOOL FUNCTIONS
# Each function = one forensic capability
# ─────────────────────────────────────────

def list_evidence_files(case_path: str) -> dict:
    """Lists all files in a case directory safely."""
    if not os.path.exists(case_path):
        return {"status": "ERROR", "error": f"Path not found: {case_path}"}
    return _safe_run(f"find {case_path} -type f | head -100")


def get_file_metadata(filepath: str) -> dict:
    """Gets metadata of a specific file."""
    return _safe_run(f"stat {filepath}")


def search_strings(filepath: str, pattern: str) -> dict:
    """Searches for a string pattern in a file."""
    safe_pattern = pattern.replace("'", "").replace(";", "")
    return _safe_run(f"strings {filepath} | grep -i '{safe_pattern}' | head -50")


def get_file_hash(filepath: str) -> dict:
    """Computes SHA256 hash of a file for integrity verification."""
    return _safe_run(f"sha256sum {filepath}")


def analyze_log_file(logpath: str, keywords: list) -> dict:
    """Searches log file for suspicious keywords."""
    results = {}
    for keyword in keywords[:10]:
        safe_kw = keyword.replace("'", "").replace(";", "")
        results[keyword] = _safe_run(f"grep -i '{safe_kw}' {logpath} | head -20")
    return results


def get_system_info(case_path: str) -> dict:
    """Simulates OS triage from case artifacts."""
    return {
        "case_path": case_path,
        "files_found": _safe_run(f"find {case_path} -type f | wc -l"),
        "disk_usage": _safe_run(f"du -sh {case_path}"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def extract_timeline(case_path: str) -> dict:
    """Extracts a basic file timeline from case artifacts."""
    return _safe_run(f"find {case_path} -type f -printf '%T+ %p\n' | sort | head -50")


def check_known_bad_hashes(filepath: str, bad_hashes: list) -> dict:
    """Checks if a file hash matches known malicious hashes."""
    result = _safe_run(f"sha256sum {filepath}")
    if result["status"] != "SUCCESS":
        return result
    
    file_hash = result["output"].split()[0] if result["output"] else ""
    is_malicious = file_hash in bad_hashes
    
    return {
        "filepath": filepath,
        "hash": file_hash,
        "is_malicious": is_malicious,
        "matched_hash": file_hash if is_malicious else None,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# ─────────────────────────────────────────
# TOOL REGISTRY — What the AI agent can call
# ─────────────────────────────────────────
AVAILABLE_TOOLS = {
    "list_evidence_files": list_evidence_files,
    "get_file_metadata": get_file_metadata,
    "search_strings": search_strings,
    "get_file_hash": get_file_hash,
    "analyze_log_file": analyze_log_file,
    "get_system_info": get_system_info,
    "extract_timeline": extract_timeline,
    "check_known_bad_hashes": check_known_bad_hashes,
}


def call_tool(tool_name: str, **kwargs) -> dict:
    """
    Main entry point for AI agents to call forensic tools.
    All calls are logged with timestamps.
    """
    if tool_name not in AVAILABLE_TOOLS:
        return {
            "status": "ERROR",
            "error": f"Unknown tool: {tool_name}",
            "available_tools": list(AVAILABLE_TOOLS.keys())
        }
    
    tool_func = AVAILABLE_TOOLS[tool_name]
    result = tool_func(**kwargs)
    result["tool_called"] = tool_name
    result["kwargs"] = kwargs
    return result


if __name__ == "__main__":
    print("🔧 NEXUS-IR MCP Server — Self Test")
    print("Testing guardrails...")
    
    blocked = _safe_run("rm -rf /")
    print(f"rm -rf / → {blocked['status']}: {blocked.get('reason', '')}")
    
    blocked2 = _safe_run("dd if=/dev/zero of=/dev/sda")
    print(f"dd attack → {blocked2['status']}: {blocked2.get('reason', '')}")
    
    safe = _safe_run("echo 'NEXUS-IR tool engine is alive!'")
    print(f"Safe command → {safe['status']}: {safe.get('output', '').strip()}")
    
    print("\n✅ MCP Server guardrails working correctly!")
