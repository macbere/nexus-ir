"""
NEXUS-IR Report Generator
Produces clean, professional incident response reports.
Every finding is traceable to a specific artifact.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from datetime import datetime, timezone


class ReportGenerator:

    def __init__(self):
        self.name = "ReportGenerator"

    def _log(self, message: str):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 📋 [{self.name}] {message}")

    def generate_text_report(self, final_report: dict, output_path: str = None) -> str:
        """Generates a clean text-based investigation report."""

        es = final_report.get("executive_summary", {})
        patterns = final_report.get("attack_patterns", [])
        validated = final_report.get("validated_findings", [])
        rejected = final_report.get("rejected_findings", [])
        timeline = final_report.get("timeline", [])
        ip_corr = final_report.get("ip_correlations", [])
        session_id = final_report.get("session_id", "UNKNOWN")
        duration = final_report.get("duration_seconds", 0)

        lines = []
        lines.append("=" * 60)
        lines.append("       NEXUS-IR INCIDENT RESPONSE REPORT")
        lines.append("       Find Evil! Hackathon — SANS Institute 2026")
        lines.append("=" * 60)
        lines.append(f"  Session ID   : {session_id}")
        lines.append(f"  Generated    : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"  Duration     : {duration}s")
        lines.append(f"  Agent        : NEXUS-IR v{final_report.get('nexus_ir_version','1.0.0')}")
        lines.append("")

        # Executive Summary
        lines.append("─" * 60)
        lines.append("  EXECUTIVE SUMMARY")
        lines.append("─" * 60)
        lines.append(f"  Threat Level     : {es.get('threat_level','?')} ({es.get('threat_score',0)}/100)")
        lines.append(f"  Case Priority    : {es.get('case_priority','?')}")
        lines.append(f"  Files Scanned    : {es.get('total_files_analyzed',0)}")
        lines.append(f"  Attack Patterns  : {es.get('attack_patterns_detected',0)}")
        lines.append(f"  IPs Identified   : {es.get('unique_ips_found',0)}")
        lines.append(f"  Findings Valid   : {es.get('findings_validated',0)}")
        lines.append(f"  Findings Rejected: {es.get('findings_rejected',0)}")
        lines.append(f"  Confidence       : {es.get('overall_confidence','?')}")
        lines.append("")

        # Attack Patterns
        lines.append("─" * 60)
        lines.append("  ATTACK PATTERNS DETECTED")
        lines.append("─" * 60)
        if patterns:
            for i, p in enumerate(patterns, 1):
                lines.append(f"  [{i}] {p.get('pattern','?')}")
                lines.append(f"      Confidence : {p.get('confidence','?')}")
                lines.append(f"      MITRE      : {p.get('mitre_technique','?')}")
                lines.append(f"      Description: {p.get('description','?')}")
                lines.append(f"      Evidence   : {', '.join(p.get('evidence_keywords',[]))}")
                lines.append("")
        else:
            lines.append("  No attack patterns detected.")
            lines.append("")

        # IP Correlations
        lines.append("─" * 60)
        lines.append("  IP ADDRESS CORRELATIONS")
        lines.append("─" * 60)
        if ip_corr:
            for ip in ip_corr:
                lines.append(f"  → {ip.get('ip','?')}")
                lines.append(f"    Significance : {ip.get('significance','?')}")
                lines.append(f"    Seen by      : {', '.join(ip.get('seen_by_agents',[]))}")
                lines.append("")
        else:
            lines.append("  No IP correlations found.")
            lines.append("")

        # Timeline
        lines.append("─" * 60)
        lines.append("  INVESTIGATION TIMELINE")
        lines.append("─" * 60)
        if timeline:
            for event in timeline:
                lines.append(f"  {event.get('timestamp','?')[:19]}")
                lines.append(f"    Agent   : {event.get('agent','?')}")
                lines.append(f"    Event   : {event.get('type','?')}")
                lines.append(f"    Artifact: {event.get('artifact','?')}")
                lines.append("")
        else:
            lines.append("  No timeline events recorded.")
            lines.append("")

        # Validated Findings
        lines.append("─" * 60)
        lines.append("  VALIDATED FINDINGS")
        lines.append("─" * 60)
        vf = [f for f in validated if isinstance(f, dict) and f.get("finding")]
        if vf:
            for i, v in enumerate(vf, 1):
                f = v.get("finding", {})
                lines.append(f"  [{i}] Type       : {f.get('type','?')}")
                lines.append(f"      Agent      : {v.get('source_agent','?')}")
                lines.append(f"      Confidence : {v.get('confidence',0)}%")
                lines.append(f"      Artifact   : {f.get('artifact', f.get('file','?'))}")
                lines.append(f"      Keywords   : {', '.join(f.get('keywords_matched',[]))}")
                lines.append("")
        else:
            lines.append("  No detailed findings to display.")
            lines.append("")

        # Rejected Findings
        lines.append("─" * 60)
        lines.append("  REJECTED / UNVERIFIABLE FINDINGS")
        lines.append("─" * 60)
        if rejected:
            for i, r in enumerate(rejected, 1):
                f = r.get("finding", {})
                lines.append(f"  [{i}] Type  : {f.get('type','?')}")
                lines.append(f"      Reason: {'; '.join(r.get('issues',[]))}")
                lines.append("")
        else:
            lines.append("  No rejected findings.")
            lines.append("")

        # Footer
        lines.append("=" * 60)
        lines.append("  NEXUS-IR — Autonomous Incident Response")
        lines.append("  All findings traceable to specific artifacts.")
        lines.append("  Self-corrected. Zero human intervention.")
        lines.append("=" * 60)

        report_text = "\n".join(lines)

        # Save to file
        if not output_path:
            output_path = os.path.join(
                os.path.dirname(__file__),
                f"output/text_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.txt"
            )

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            f.write(report_text)

        self._log(f"Text report saved: {output_path}")
        return report_text


if __name__ == "__main__":
    print("📋 Testing ReportGenerator...")

    report_dir = "/data/data/com.termux/files/home/nexus-ir/reports/output"
    json_files = [f for f in os.listdir(report_dir) if f.endswith(".json")] if os.path.exists(report_dir) else []

    if json_files:
        latest = sorted(json_files)[-1]
        with open(f"{report_dir}/{latest}") as f:
            final_report = json.load(f)
        self_obj = ReportGenerator()
        text = self_obj.generate_text_report(final_report)
        print("\n" + text)
        print("\n✅ ReportGenerator test passed!")
    else:
        print("⚠️  No JSON report found. Run orchestrator.py first.")
        print("Running orchestrator now...")
        os.system("cd /data/data/com.termux/files/home/nexus-ir && python orchestrator.py")
