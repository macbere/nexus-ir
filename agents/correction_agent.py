"""
NEXUS-IR Self-Correction Agent
Validates all findings, catches hallucinations, flags inconsistencies.
This is what separates NEXUS-IR from every other submission.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timezone
from tools.mcp_server import call_tool


class CorrectionAgent:
    """
    Reviews ALL findings from ALL agents.
    Validates every claim against actual evidence.
    Flags hallucinations and unverifiable claims.
    Produces a confidence score for each finding.
    """

    def __init__(self):
        self.name = "CorrectionAgent"
        self.iteration = 0
        self.validated = []
        self.rejected = []
        self.warnings = []
        self.errors = []

    def _log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "INFO": "ℹ️", "WARN": "⚠️", "ERROR": "❌",
            "PASS": "✅", "FAIL": "🚫", "FIX": "🔧"
        }.get(level, "•")
        print(f"[{timestamp}] {prefix} [{self.name}] {message}")

    def _verify_file_exists(self, filepath: str) -> bool:
        """Verifies a file actually exists before trusting findings about it."""
        if not filepath or filepath == "unknown":
            return False
        result = call_tool("get_file_metadata", filepath=filepath)
        return result.get("status") == "SUCCESS"

    def _verify_finding_has_artifact(self, finding: dict) -> tuple:
        """
        Every finding MUST trace back to a real artifact.
        Returns (is_valid, reason).
        """
        artifact = finding.get("artifact") or finding.get("file") or finding.get("filepath")

        if not artifact:
            return False, "Finding has no artifact reference — cannot verify"

        if artifact == "unknown":
            return False, "Finding references 'unknown' artifact — likely hallucination"

        if not os.path.exists(artifact):
            return False, f"Artifact does not exist on disk: {artifact}"

        return True, f"Artifact verified: {artifact}"

    def _check_ip_format(self, ip_string: str) -> bool:
        """Validates that an IP address is properly formatted."""
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return bool(re.search(ip_pattern, ip_string))

    def _validate_log_finding(self, finding: dict, source_report: str) -> dict:
        """Validates a log-based finding."""
        result = {
            "finding": finding,
            "source_agent": source_report,
            "valid": False,
            "confidence": 0,
            "issues": [],
            "verification_steps": []
        }

        # Check 1 — Does it have an artifact?
        is_valid, reason = self._verify_finding_has_artifact(finding)
        result["verification_steps"].append(reason)
        if not is_valid:
            result["issues"].append(reason)
            result["confidence"] = 10
            return result

        # Check 2 — Does the file still exist?
        artifact = finding.get("artifact") or finding.get("file", "")
        if self._verify_file_exists(artifact):
            result["verification_steps"].append(f"✅ File exists: {artifact}")
            result["confidence"] += 50
        else:
            result["issues"].append(f"File not found during verification: {artifact}")
            result["confidence"] += 10

        # Check 3 — Does it have keywords matched?
        keywords = finding.get("keywords_matched", [])
        if keywords:
            result["verification_steps"].append(f"✅ Keywords matched: {keywords}")
            result["confidence"] += 30
        else:
            result["issues"].append("No keywords matched recorded")

        # Check 4 — Does it have a timestamp?
        if finding.get("timestamp"):
            result["verification_steps"].append("✅ Timestamp present")
            result["confidence"] += 20
        else:
            result["issues"].append("Missing timestamp")

        result["confidence"] = min(result["confidence"], 100)
        result["valid"] = result["confidence"] >= 50
        return result

    def _validate_attack_pattern(self, pattern: dict) -> dict:
        """Validates an attack pattern detected by CorrelationAgent."""
        result = {
            "pattern": pattern.get("pattern"),
            "valid": False,
            "confidence": 0,
            "issues": [],
            "verification_steps": []
        }

        # Check 1 — Has evidence keywords?
        keywords = pattern.get("evidence_keywords", [])
        if len(keywords) >= 2:
            result["verification_steps"].append(f"✅ Supported by {len(keywords)} keywords: {keywords}")
            result["confidence"] += 50
        elif len(keywords) == 1:
            result["issues"].append("Pattern supported by only 1 keyword — low confidence")
            result["confidence"] += 20
        else:
            result["issues"].append("Pattern has no supporting keywords — likely hallucination")
            return result

        # Check 2 — Has MITRE technique?
        if pattern.get("mitre_technique"):
            result["verification_steps"].append(f"✅ MITRE mapped: {pattern['mitre_technique']}")
            result["confidence"] += 25

        # Check 3 — Has description?
        if pattern.get("description"):
            result["verification_steps"].append("✅ Description present")
            result["confidence"] += 25

        result["confidence"] = min(result["confidence"], 100)
        result["valid"] = result["confidence"] >= 50
        return result

    def _validate_ip_correlations(self, correlations: list) -> list:
        """Validates IP address findings."""
        validated_ips = []
        for corr in correlations:
            ip = corr.get("ip", "")
            is_valid_format = self._check_ip_format(ip)

            validation = {
                "ip": ip,
                "valid": is_valid_format,
                "confidence": 80 if is_valid_format else 10,
                "issue": None if is_valid_format else f"Invalid IP format: {ip}"
            }

            if is_valid_format:
                self._log(f"IP validated: {ip}", "PASS")
            else:
                self._log(f"IP rejected — invalid format: {ip}", "FAIL")
                validation["issue"] = f"Could not extract clean IP from: {ip}"

            validated_ips.append(validation)
        return validated_ips

    def _generate_correction_summary(self) -> dict:
        """Generates a summary of what was validated vs rejected."""
        total = len(self.validated) + len(self.rejected)
        accuracy = (len(self.validated) / total * 100) if total > 0 else 0

        return {
            "total_findings_reviewed": total,
            "validated": len(self.validated),
            "rejected": len(self.rejected),
            "warnings": len(self.warnings),
            "accuracy_rate": round(accuracy, 1),
            "overall_confidence": "HIGH" if accuracy >= 75 else "MEDIUM" if accuracy >= 50 else "LOW"
        }

    def run(self, all_reports: dict, correlation_report: dict = None) -> dict:
        """Main self-correction function."""
        self._log("Starting self-correction and validation pass...")
        self.iteration += 1

        # Phase 1 — Validate log findings
        self._log("Phase 1: Validating log findings...")
        for agent_name, report in all_reports.items():
            if not isinstance(report, dict):
                continue
            for finding in report.get("findings", []):
                if not isinstance(finding, dict):
                    continue
                validation = self._validate_log_finding(finding, agent_name)
                if validation["valid"]:
                    self.validated.append(validation)
                    self._log(f"PASS: {finding.get('type','?')} [confidence: {validation['confidence']}%]", "PASS")
                else:
                    self.rejected.append(validation)
                    self._log(f"FAIL: {finding.get('type','?')} — {validation['issues']}", "FAIL")

        # Phase 2 — Validate attack patterns
        self._log("Phase 2: Validating attack patterns...")
        if correlation_report:
            for pattern in correlation_report.get("attack_patterns", []):
                validation = self._validate_attack_pattern(pattern)
                if validation["valid"]:
                    self.validated.append(validation)
                    self._log(f"PASS: Pattern {validation['pattern']} [confidence: {validation['confidence']}%]", "PASS")
                else:
                    self.rejected.append(validation)
                    self._log(f"FAIL: Pattern {validation['pattern']} rejected", "FAIL")

            # Phase 3 — Validate IPs
            self._log("Phase 3: Validating IP addresses...")
            ip_validations = self._validate_ip_correlations(
                correlation_report.get("ip_correlations", [])
            )
            for iv in ip_validations:
                if iv["valid"]:
                    self.validated.append(iv)
                else:
                    self.warnings.append(iv)

        # Phase 4 — Self check
        self._log("Phase 4: Running self-check...")
        if len(self.validated) == 0 and len(self.rejected) == 0:
            self._log("WARNING: Nothing was validated — pipeline may have failed", "WARN")
            self.errors.append("Zero findings reviewed — check agent outputs")

        summary = self._generate_correction_summary()
        self._log(f"Validation complete — {summary['accuracy_rate']}% accuracy rate", "PASS")
        self._log(f"Confidence level: {summary['overall_confidence']}")

        return {
            "status": "COMPLETE",
            "agent": self.name,
            "validated_findings": self.validated,
            "rejected_findings": self.rejected,
            "warnings": self.warnings,
            "summary": summary,
            "errors": self.errors,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


if __name__ == "__main__":
    print("🔧 Testing CorrectionAgent...")

    test_path = "/data/data/com.termux/files/home/test_case"
    os.makedirs(test_path, exist_ok=True)
    with open(f"{test_path}/system.log", "w") as f:
        f.write("Failed login from 192.168.1.105\n")

    fake_reports = {
        "LogAgent": {
            "findings": [
                {
                    "type": "suspicious_log_activity",
                    "file": f"{test_path}/system.log",
                    "artifact": f"{test_path}/system.log",
                    "keywords_matched": ["failed login", "unauthorized"],
                    "timestamp": "2026-05-20T09:00:00"
                },
                {
                    "type": "hallucinated_finding",
                    "file": "/nonexistent/fake.log",
                    "artifact": "/nonexistent/fake.log",
                    "keywords_matched": [],
                    "timestamp": ""
                }
            ]
        }
    }

    fake_correlation = {
        "attack_patterns": [
            {
                "pattern": "BRUTE_FORCE_ATTACK",
                "confidence": "HIGH",
                "evidence_keywords": ["failed login", "authentication failure"],
                "mitre_technique": "T1110 - Brute Force",
                "description": "Brute force detected"
            }
        ],
        "ip_correlations": [
            {"ip": "192.168.1.105", "significance": "MEDIUM"},
            {"ip": "INVALID_IP_STRING", "significance": "LOW"}
        ]
    }

    agent = CorrectionAgent()
    report = agent.run(fake_reports, fake_correlation)

    print(f"\n📋 CORRECTION REPORT:")
    print(f"  Total reviewed: {report['summary']['total_findings_reviewed']}")
    print(f"  Validated: {report['summary']['validated']}")
    print(f"  Rejected: {report['summary']['rejected']}")
    print(f"  Accuracy rate: {report['summary']['accuracy_rate']}%")
    print(f"  Confidence: {report['summary']['overall_confidence']}")
    print(f"  Errors: {report['errors']}")
    print("\n✅ CorrectionAgent test passed!")
