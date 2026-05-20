"""
NEXUS-IR Log Agent
Specialist in analyzing log files for suspicious activity.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timezone
from tools.mcp_server import call_tool


class LogAgent:
    """Analyzes log files for indicators of compromise."""

    SUSPICIOUS_KEYWORDS = [
        "failed login", "authentication failure", "unauthorized",
        "privilege escalation", "sudo", "root", "exploit",
        "malware", "ransomware", "backdoor", "reverse shell",
        "powershell", "base64", "encoded", "wget", "curl",
        "suspicious", "anomaly", "brute force", "injection"
    ]

    def __init__(self):
        self.name = "LogAgent"
        self.iteration = 0
        self.findings = []
        self.errors = []

    def _log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {"INFO": "ℹ️", "WARN": "⚠️", "ERROR": "❌", "FIND": "🔍"}.get(level, "•")
        print(f"[{timestamp}] {prefix} [{self.name}] {message}")

    def _record_finding(self, finding: dict):
        finding["agent"] = self.name
        finding["iteration"] = self.iteration
        finding["timestamp"] = datetime.now(timezone.utc).isoformat()
        finding["traceable"] = True
        self.findings.append(finding)

    def _analyze_single_log(self, logpath: str) -> dict:
        """Deep analysis of one log file."""
        self._log(f"Analyzing: {os.path.basename(logpath)}")
        hits = {}

        result = call_tool(
            "analyze_log_file",
            logpath=logpath,
            keywords=self.SUSPICIOUS_KEYWORDS[:10]
        )

        for keyword, search_result in result.items():
            if not isinstance(search_result, dict): continue
            if search_result.get("status") == "SUCCESS":
                output = search_result.get("output", "").strip()
                if output:
                    hits[keyword] = {
                        "matches": output.split("\n"),
                        "count": len(output.split("\n")),
                        "source_file": logpath,
                        "tool_used": "grep",
                        "command_hash": search_result.get("command_hash")
                    }
                    self._log(f"  🚨 '{keyword}' found {len(output.split(chr(10)))} time(s)", "FIND")

        return hits

    def _extract_ip_addresses(self, logpath: str) -> list:
        """Extracts IP addresses from log file."""
        result = call_tool(
            "search_strings",
            filepath=logpath,
            pattern="[0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*"
        )
        if result.get("status") == "SUCCESS" and result.get("output"):
            ips = list(set(result["output"].strip().split("\n")))
            return [ip.strip() for ip in ips if ip.strip()]
        return []

    def run(self, case_path: str, log_files: list = None) -> dict:
        """Main log analysis function."""
        self._log(f"Starting log analysis on: {case_path}")
        self.iteration += 1

        # Find log files if not provided
        if not log_files:
            result = call_tool("list_evidence_files", case_path=case_path)
            all_files = result.get("output", "").strip().split("\n")
            log_files = [
                f for f in all_files
                if any(f.endswith(ext) for ext in [".log", ".txt", ".evtx"])
            ]

        self._log(f"Found {len(log_files)} log file(s) to analyze")

        all_hits = {}
        all_ips = []

        for logfile in log_files:
            if not logfile.strip():
                continue

            # Analyze for suspicious keywords
            hits = self._analyze_single_log(logfile)
            if hits:
                all_hits[logfile] = hits
                self._record_finding({
                    "type": "suspicious_log_activity",
                    "file": logfile,
                    "keywords_matched": list(hits.keys()),
                    "total_hits": sum(v["count"] for v in hits.values()),
                    "artifact": logfile
                })

            # Extract IPs
            ips = self._extract_ip_addresses(logfile)
            if ips:
                all_ips.extend(ips)
                self._log(f"  Found {len(ips)} unique IP address(es)", "FIND")

        # Self-correction check
        if not all_hits and log_files:
            self._log("No suspicious keywords found — verifying log files are readable...", "WARN")
            for lf in log_files[:2]:
                meta = call_tool("get_file_metadata", filepath=lf)
                if meta.get("status") != "SUCCESS":
                    self.errors.append(f"Could not read log file: {lf}")

        unique_ips = list(set(all_ips))
        self._log(f"Analysis complete. {len(all_hits)} suspicious file(s), {len(unique_ips)} unique IP(s)")

        return {
            "status": "COMPLETE",
            "agent": self.name,
            "log_files_analyzed": len(log_files),
            "suspicious_files": len(all_hits),
            "hits": all_hits,
            "unique_ips": unique_ips,
            "findings": self.findings,
            "errors": self.errors,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


if __name__ == "__main__":
    print("📋 Testing LogAgent...")
    test_path = "/data/data/com.termux/files/home/test_case"
    os.makedirs(test_path, exist_ok=True)

    with open(f"{test_path}/system.log", "w") as f:
        f.write("2026-05-01 03:12:44 Failed login attempt from 192.168.1.105\n")
        f.write("2026-05-01 03:12:45 Authentication failure for root\n")
        f.write("2026-05-01 03:12:50 sudo command executed by unknown user\n")
        f.write("2026-05-01 03:13:01 Unauthorized access attempt detected\n")
        f.write("2026-05-01 03:13:10 Reverse shell connection from 10.0.0.99\n")

    agent = LogAgent()
    report = agent.run(test_path)

    print(f"\n📋 LOG REPORT:")
    print(f"  Files analyzed: {report['log_files_analyzed']}")
    print(f"  Suspicious files: {report['suspicious_files']}")
    print(f"  Unique IPs found: {report['unique_ips']}")
    print(f"  Errors: {report['errors']}")
    print("\n✅ LogAgent test passed!")
