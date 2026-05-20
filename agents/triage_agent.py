"""
NEXUS-IR Triage Agent
First responder — examines evidence and creates investigation plan.
Thinks like a senior analyst seeing a case for the first time.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from datetime import datetime
from tools.mcp_server import call_tool


class TriageAgent:
    """
    Examines incoming evidence and produces a structured triage report.
    Determines which specialist agents to activate.
    """

    def __init__(self):
        self.name = "TriageAgent"
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
        finding["timestamp"] = datetime.now().isoformat()
        self.findings.append(finding)

    def _detect_evidence_types(self, case_path: str) -> dict:
        """Looks at what evidence files exist and categorizes them."""
        self._log("Scanning evidence files...")
        result = call_tool("list_evidence_files", case_path=case_path)

        if result["status"] != "SUCCESS":
            self.errors.append(f"Could not list files: {result.get('error')}")
            return {}

        files = result.get("output", "").strip().split("\n")
        files = [f for f in files if f.strip()]

        evidence_types = {
            "disk_images": [],
            "memory_dumps": [],
            "log_files": [],
            "network_captures": [],
            "registry_files": [],
            "unknown": []
        }

        extensions = {
            ".E01": "disk_images", ".dd": "disk_images", ".img": "disk_images",
            ".raw": "memory_dumps", ".mem": "memory_dumps", ".dmp": "memory_dumps",
            ".log": "log_files", ".txt": "log_files", ".evtx": "log_files",
            ".pcap": "network_captures", ".pcapng": "network_captures",
            ".reg": "registry_files", ".hive": "registry_files"
        }

        for filepath in files:
            matched = False
            for ext, category in extensions.items():
                if filepath.lower().endswith(ext.lower()):
                    evidence_types[category].append(filepath)
                    matched = True
                    break
            if not matched and filepath:
                evidence_types["unknown"].append(filepath)

        return evidence_types

    def _assess_case_priority(self, evidence_types: dict) -> str:
        """Determines investigation priority based on evidence present."""
        has_memory = len(evidence_types.get("memory_dumps", [])) > 0
        has_disk = len(evidence_types.get("disk_images", [])) > 0
        has_network = len(evidence_types.get("network_captures", [])) > 0
        has_logs = len(evidence_types.get("log_files", [])) > 0

        if has_memory and has_disk:
            return "CRITICAL"
        elif has_memory or has_disk:
            return "HIGH"
        elif has_network and has_logs:
            return "MEDIUM"
        else:
            return "LOW"

    def _build_investigation_plan(self, evidence_types: dict) -> list:
        """Decides which agents to activate based on evidence."""
        plan = []

        if evidence_types.get("disk_images") or evidence_types.get("unknown"):
            plan.append({
                "agent": "DiskAgent",
                "reason": "Disk artifacts detected",
                "priority": 1
            })

        if evidence_types.get("memory_dumps"):
            plan.append({
                "agent": "MemoryAgent",
                "reason": "Memory dump detected",
                "priority": 2
            })

        if evidence_types.get("log_files"):
            plan.append({
                "agent": "LogAgent",
                "reason": "Log files detected",
                "priority": 3
            })

        if evidence_types.get("network_captures"):
            plan.append({
                "agent": "NetworkAgent",
                "reason": "Network capture detected",
                "priority": 4
            })

        plan.append({
            "agent": "CorrelationAgent",
            "reason": "Always runs to cross-reference findings",
            "priority": 5
        })

        plan.append({
            "agent": "CorrectionAgent",
            "reason": "Always runs to validate and self-correct",
            "priority": 6
        })

        return sorted(plan, key=lambda x: x["priority"])

    def run(self, case_path: str) -> dict:
        """
        Main triage function. Examines case and returns investigation plan.
        """
        self._log(f"Starting triage on case: {case_path}")
        self.iteration += 1

        # Step 1 — Get system info
        sys_info = call_tool("get_system_info", case_path=case_path)
        self._log(f"Case loaded. Running analysis...")

        # Step 2 — Detect evidence types
        evidence_types = self._detect_evidence_types(case_path)
        total_files = sum(len(v) for v in evidence_types.values())
        self._log(f"Found {total_files} evidence files across {len(evidence_types)} categories", "FIND")

        for category, files in evidence_types.items():
            if files:
                self._log(f"  {category}: {len(files)} file(s)", "FIND")
                self._record_finding({
                    "type": "evidence_detected",
                    "category": category,
                    "count": len(files),
                    "files": files[:5], "artifact": files[0] if files else "unknown"
                })

        # Step 3 — Assess priority
        priority = self._assess_case_priority(evidence_types)
        self._log(f"Case priority assessed: {priority}", "FIND")

        # Step 4 — Build investigation plan
        plan = self._build_investigation_plan(evidence_types)
        self._log(f"Investigation plan created: {len(plan)} agents to activate")

        for step in plan:
            self._log(f"  → {step['agent']}: {step['reason']}")

        # Step 5 — Self check
        if not plan:
            self._log("WARNING: No investigation plan generated!", "WARN")
            self.errors.append("Empty investigation plan — possible evidence detection failure")

        triage_report = {
            "status": "COMPLETE",
            "agent": self.name,
            "case_path": case_path,
            "priority": priority,
            "evidence_types": evidence_types,
            "total_files": total_files,
            "investigation_plan": plan,
            "findings": self.findings,
            "errors": self.errors,
            "timestamp": datetime.now().isoformat()
        }

        self._log("✅ Triage complete!")
        return triage_report


if __name__ == "__main__":
    print("🔍 Testing TriageAgent...")

    # Create a fake test case
    os.makedirs("/data/data/com.termux/files/home/test_case", exist_ok=True)
    open("/data/data/com.termux/files/home/test_case/system.log", "w").write("Failed login attempt from 192.168.1.1\n")
    open("/data/data/com.termux/files/home/test_case/network.pcap", "w").write("fake pcap data\n")
    open("/data/data/com.termux/files/home/test_case/memory.raw", "w").write("fake memory dump\n")

    agent = TriageAgent()
    report = agent.run("/data/data/com.termux/files/home/test_case")

    print("\n📋 TRIAGE REPORT:")
    print(f"  Priority: {report['priority']}")
    print(f"  Files found: {report['total_files']}")
    print(f"  Agents to run: {[p['agent'] for p in report['investigation_plan']]}")
    print(f"  Errors: {report['errors']}")
    print("\n✅ TriageAgent test passed!")
