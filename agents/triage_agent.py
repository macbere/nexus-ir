import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timezone
from tools.mcp_server import call_tool


class TriageAgent:

    # Keywords that immediately force CRITICAL priority
    CRITICAL_KEYWORDS = [
        "ransomware", "backdoor", "base64", "powershell",
        "reverse shell", "exploit", "malware", "encoded",
        "lateral movement", "exfiltration", "c2", "command and control"
    ]

    # Keywords that force HIGH priority
    HIGH_KEYWORDS = [
        "failed login", "authentication failure", "unauthorized",
        "privilege escalation", "sudo", "root", "brute force",
        "injection", "anomaly"
    ]

    def __init__(self):
        self.name = "TriageAgent"
        self.iteration = 0
        self.findings = []
        self.errors = []
        self.keyword_hits = []

    def _log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {"INFO": "i", "WARN": "!", "ERROR": "X", "FIND": "?", "CRIT": "!!"}.get(level, ".")
        print(f"[{timestamp}] {prefix} [{self.name}] {message}")

    def _record_finding(self, finding: dict):
        finding["agent"] = self.name
        finding["iteration"] = self.iteration
        finding["timestamp"] = datetime.now(timezone.utc).isoformat()
        finding["traceable"] = True
        self.findings.append(finding)

    def _scan_file_for_keywords(self, filepath: str) -> dict:
        found_critical = []
        found_high = []
        try:
            with open(filepath, "r", errors="ignore") as f:
                content = f.read().lower()
                for kw in self.CRITICAL_KEYWORDS:
                    if kw in content:
                        found_critical.append(kw)
                for kw in self.HIGH_KEYWORDS:
                    if kw in content:
                        found_high.append(kw)
        except Exception:
            pass
        return {"critical": found_critical, "high": found_high}

    def _detect_evidence_types(self, case_path: str) -> dict:
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

    def _assess_case_priority(self, evidence_types: dict, case_path: str) -> str:
        self._log("Scanning content for priority keywords...")

        all_critical = []
        all_high = []

        result = call_tool("list_evidence_files", case_path=case_path)
        files = result.get("output", "").strip().split("\n") if result.get("status") == "SUCCESS" else []

        for filepath in files:
            if not filepath.strip():
                continue
            kw_result = self._scan_file_for_keywords(filepath)
            all_critical.extend(kw_result["critical"])
            all_high.extend(kw_result["high"])

        self.keyword_hits = {
            "critical_keywords_found": list(set(all_critical)),
            "high_keywords_found": list(set(all_high))
        }

        # DYNAMIC PRIORITY — keywords override file-type assessment
        if all_critical:
            self._log(f"CRITICAL keywords detected: {list(set(all_critical))}", "CRIT")
            self._record_finding({
                "type": "dynamic_priority_escalation",
                "reason": "Critical keywords found in evidence",
                "keywords": list(set(all_critical)),
                "artifact": case_path,
                "priority_set": "CRITICAL"
            })
            return "CRITICAL"

        if all_high:
            self._log(f"HIGH keywords detected: {list(set(all_high))}", "FIND")
            return "HIGH"

        # Fall back to file-type assessment
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

    def _build_investigation_plan(self, evidence_types: dict, priority: str) -> list:
        plan = []

        if evidence_types.get("disk_images") or evidence_types.get("unknown"):
            plan.append({"agent": "DiskAgent", "reason": "Disk artifacts detected", "priority": 1})

        if evidence_types.get("memory_dumps"):
            plan.append({"agent": "MemoryAgent", "reason": "Memory dump detected", "priority": 2})

        if evidence_types.get("log_files"):
            plan.append({"agent": "LogAgent", "reason": "Log files detected", "priority": 3})

        if evidence_types.get("network_captures"):
            plan.append({"agent": "NetworkAgent", "reason": "Network capture detected", "priority": 4})

        plan.append({"agent": "CorrelationAgent", "reason": "Always runs", "priority": 5})
        plan.append({"agent": "CorrectionAgent", "reason": "Always runs", "priority": 6})

        return sorted(plan, key=lambda x: x["priority"])

    def run(self, case_path: str) -> dict:
        self._log(f"Starting triage on case: {case_path}")
        self.iteration += 1

        sys_info = call_tool("get_system_info", case_path=case_path)
        self._log("Case loaded. Running analysis...")

        evidence_types = self._detect_evidence_types(case_path)
        total_files = sum(len(v) for v in evidence_types.values())
        self._log(f"Found {total_files} evidence files", "FIND")

        for category, files in evidence_types.items():
            if files:
                self._log(f"  {category}: {len(files)} file(s)", "FIND")
                self._record_finding({
                    "type": "evidence_detected",
                    "category": category,
                    "count": len(files),
                    "files": files[:5],
                    "artifact": files[0] if files else "unknown"
                })

        # Dynamic priority assessment
        priority = self._assess_case_priority(evidence_types, case_path)
        self._log(f"Case priority assessed: {priority}", "FIND")

        plan = self._build_investigation_plan(evidence_types, priority)
        self._log(f"Investigation plan: {len(plan)} agents to activate")
        for step in plan:
            self._log(f"  -> {step['agent']}: {step['reason']}")

        if not plan:
            self.errors.append("Empty investigation plan")

        self._log("Triage complete!")

        return {
            "status": "COMPLETE",
            "agent": self.name,
            "case_path": case_path,
            "priority": priority,
            "keyword_hits": self.keyword_hits,
            "evidence_types": evidence_types,
            "total_files": total_files,
            "investigation_plan": plan,
            "findings": self.findings,
            "errors": self.errors,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


if __name__ == "__main__":
    print("Testing TriageAgent dynamic priority...")
    import os

    # Test 1 — Ransomware case (should be CRITICAL)
    test_path = "/data/data/com.termux/files/home/cases/ransomware"
    agent = TriageAgent()
    report = agent.run(test_path)
    print(f"\nRansomware case priority: {report['priority']}")
    print(f"Keywords found: {report['keyword_hits']}")
    assert report['priority'] == 'CRITICAL', f"Expected CRITICAL got {report['priority']}"

    # Test 2 — Brute force case (should be HIGH or CRITICAL)
    test_path2 = "/data/data/com.termux/files/home/cases/brute_force"
    agent2 = TriageAgent()
    report2 = agent2.run(test_path2)
    print(f"\nBrute force case priority: {report2['priority']}")
    assert report2['priority'] in ['HIGH', 'CRITICAL'], f"Expected HIGH/CRITICAL got {report2['priority']}"

    print("\nAll triage tests passed!")
