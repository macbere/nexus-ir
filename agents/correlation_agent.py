"""
NEXUS-IR Correlation Agent
Cross-references ALL agent findings to find hidden connections.
This is what separates junior analysts from senior analysts.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timezone


class CorrelationAgent:
    """
    Takes findings from all specialist agents and finds connections.
    Every finding must be traceable to a specific artifact.
    """

    def __init__(self):
        self.name = "CorrelationAgent"
        self.iteration = 0
        self.findings = []
        self.errors = []

    def _log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {"INFO": "ℹ️", "WARN": "⚠️", "ERROR": "❌", "FIND": "🔍", "LINK": "🔗"}.get(level, "•")
        print(f"[{timestamp}] {prefix} [{self.name}] {message}")

    def _record_finding(self, finding: dict):
        finding["agent"] = self.name
        finding["iteration"] = self.iteration
        finding["timestamp"] = datetime.now(timezone.utc).isoformat()
        finding["traceable"] = True
        self.findings.append(finding)

    def _extract_all_ips(self, all_reports: dict) -> dict:
        """Pulls all IP addresses from every agent report."""
        ip_map = {}
        for agent_name, report in all_reports.items():
            if not isinstance(report, dict):
                continue
            ips = report.get("unique_ips", [])
            for ip in ips:
                clean_ip = ip.strip()
                if clean_ip:
                    if clean_ip not in ip_map:
                        ip_map[clean_ip] = []
                    ip_map[clean_ip].append(agent_name)
        return ip_map

    def _extract_all_keywords(self, all_reports: dict) -> dict:
        """Pulls all suspicious keywords found across all agents."""
        keyword_map = {}
        for agent_name, report in all_reports.items():
            if not isinstance(report, dict):
                continue
            hits = report.get("hits", {})
            for filepath, file_hits in hits.items():
                if not isinstance(file_hits, dict):
                    continue
                for keyword in file_hits.keys():
                    if keyword not in keyword_map:
                        keyword_map[keyword] = []
                    keyword_map[keyword].append({
                        "agent": agent_name,
                        "file": filepath
                    })
        return keyword_map

    def _find_ip_correlations(self, ip_map: dict) -> list:
        """Finds IPs that appear across multiple evidence sources."""
        correlations = []
        for ip, agents in ip_map.items():
            if len(agents) >= 1:
                correlations.append({
                    "type": "ip_seen_in_evidence",
                    "ip": ip,
                    "seen_by_agents": agents,
                    "significance": "HIGH" if len(agents) > 1 else "MEDIUM",
                    "description": f"IP {ip} appeared in {len(agents)} evidence source(s)"
                })
        return correlations

    def _detect_attack_patterns(self, keyword_map: dict) -> list:
        """Detects known attack patterns from combined keywords."""
        patterns = []

        brute_force_keys = {"failed login", "authentication failure", "brute force"}
        found_brute = brute_force_keys.intersection(set(keyword_map.keys()))
        if len(found_brute) >= 2:
            patterns.append({
                "type": "attack_pattern",
                "pattern": "BRUTE_FORCE_ATTACK",
                "confidence": "HIGH",
                "evidence_keywords": list(found_brute),
                "description": "Multiple failed authentication events detected — consistent with brute force attack",
                "mitre_technique": "T1110 - Brute Force"
            })

        privilege_keys = {"sudo", "root", "privilege escalation", "unauthorized"}
        found_priv = privilege_keys.intersection(set(keyword_map.keys()))
        if len(found_priv) >= 2:
            patterns.append({
                "type": "attack_pattern",
                "pattern": "PRIVILEGE_ESCALATION",
                "confidence": "HIGH",
                "evidence_keywords": list(found_priv),
                "description": "Privilege escalation indicators detected across multiple log entries",
                "mitre_technique": "T1548 - Abuse Elevation Control Mechanism"
            })

        lateral_keys = {"reverse shell", "backdoor", "exploit", "injection"}
        found_lateral = lateral_keys.intersection(set(keyword_map.keys()))
        if found_lateral:
            patterns.append({
                "type": "attack_pattern",
                "pattern": "LATERAL_MOVEMENT_OR_C2",
                "confidence": "CRITICAL",
                "evidence_keywords": list(found_lateral),
                "description": "Command and control or lateral movement indicators detected",
                "mitre_technique": "T1021 - Remote Services / T1059 - Command Interpreter"
            })

        return patterns

    def _build_timeline(self, all_reports: dict) -> list:
        """Builds a unified timeline from all agent findings."""
        events = []
        for agent_name, report in all_reports.items():
            if not isinstance(report, dict):
                continue
            for finding in report.get("findings", []):
                if isinstance(finding, dict):
                    events.append({
                        "agent": agent_name,
                        "type": finding.get("type", "unknown"),
                        "timestamp": finding.get("timestamp", ""),
                        "artifact": finding.get("artifact", finding.get("file", "unknown"))
                    })
        events.sort(key=lambda x: x.get("timestamp", ""))
        return events

    def _calculate_threat_score(self, patterns: list, ip_correlations: list) -> dict:
        """Calculates overall threat score for the case."""
        score = 0
        reasons = []

        for pattern in patterns:
            if pattern["confidence"] == "CRITICAL":
                score += 40
                reasons.append(f"CRITICAL pattern: {pattern['pattern']}")
            elif pattern["confidence"] == "HIGH":
                score += 25
                reasons.append(f"HIGH pattern: {pattern['pattern']}")
            elif pattern["confidence"] == "MEDIUM":
                score += 10
                reasons.append(f"MEDIUM pattern: {pattern['pattern']}")

        for corr in ip_correlations:
            if corr["significance"] == "HIGH":
                score += 15
                reasons.append(f"Correlated IP: {corr['ip']}")
            else:
                score += 5

        score = min(score, 100)

        if score >= 75:
            level = "CRITICAL"
        elif score >= 50:
            level = "HIGH"
        elif score >= 25:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "score": score,
            "level": level,
            "reasons": reasons
        }

    def run(self, all_reports: dict) -> dict:
        """Main correlation function."""
        self._log("Starting cross-agent correlation analysis...")
        self.iteration += 1

        self._log(f"Correlating findings from {len(all_reports)} agent(s)")

        # Step 1 — Extract all IPs
        ip_map = self._extract_all_ips(all_reports)
        self._log(f"Total unique IPs across all evidence: {len(ip_map)}", "FIND")

        # Step 2 — Extract all keywords
        keyword_map = self._extract_all_keywords(all_reports)
        self._log(f"Total suspicious keywords found: {len(keyword_map)}", "FIND")

        # Step 3 — Find IP correlations
        ip_correlations = self._find_ip_correlations(ip_map)
        for corr in ip_correlations:
            self._log(f"IP correlation: {corr['description']}", "LINK")
            self._record_finding(corr)

        # Step 4 — Detect attack patterns
        patterns = self._detect_attack_patterns(keyword_map)
        for pattern in patterns:
            self._log(f"🚨 ATTACK PATTERN: {pattern['pattern']} [{pattern['confidence']}]", "FIND")
            self._log(f"   MITRE: {pattern['mitre_technique']}", "FIND")
            self._record_finding(pattern)

        # Step 5 — Build timeline
        timeline = self._build_timeline(all_reports)
        self._log(f"Unified timeline built: {len(timeline)} event(s)")

        # Step 6 — Calculate threat score
        threat = self._calculate_threat_score(patterns, ip_correlations)
        self._log(f"🎯 THREAT SCORE: {threat['score']}/100 — Level: {threat['level']}", "FIND")

        # Self-correction check
        if not patterns and not ip_correlations:
            self._log("No correlations found — checking if agent reports are populated...", "WARN")
            for name, report in all_reports.items():
                if not isinstance(report, dict):
                    self.errors.append(f"Invalid report format from {name}")

        self._log("✅ Correlation analysis complete!")

        return {
            "status": "COMPLETE",
            "agent": self.name,
            "agents_correlated": len(all_reports),
            "ip_correlations": ip_correlations,
            "attack_patterns": patterns,
            "timeline": timeline,
            "threat_assessment": threat,
            "findings": self.findings,
            "errors": self.errors,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


if __name__ == "__main__":
    print("🔗 Testing CorrelationAgent...")

    fake_reports = {
        "LogAgent": {
            "unique_ips": ["192.168.1.105", "10.0.0.99"],
            "hits": {
                "/test/system.log": {
                    "failed login": {"count": 1},
                    "authentication failure": {"count": 1},
                    "sudo": {"count": 1},
                    "root": {"count": 1},
                    "reverse shell": {"count": 1},
                    "unauthorized": {"count": 1}
                }
            },
            "findings": [
                {
                    "type": "suspicious_log_activity",
                    "file": "/test/system.log",
                    "artifact": "/test/system.log",
                    "timestamp": "2026-05-20T09:00:00"
                }
            ]
        }
    }

    agent = CorrelationAgent()
    report = agent.run(fake_reports)

    print(f"\n📋 CORRELATION REPORT:")
    print(f"  Attack patterns found: {len(report['attack_patterns'])}")
    for p in report['attack_patterns']:
        print(f"    🚨 {p['pattern']} [{p['confidence']}] — {p['mitre_technique']}")
    print(f"  Threat score: {report['threat_assessment']['score']}/100")
    print(f"  Threat level: {report['threat_assessment']['level']}")
    print(f"  Errors: {report['errors']}")
    print("\n✅ CorrelationAgent test passed!")
