"""
NEXUS-IR Orchestrator
The master brain that coordinates all agents.
Type one command — get a complete forensic investigation.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
from datetime import datetime, timezone
from agents.triage_agent import TriageAgent
from agents.log_agent import LogAgent
from agents.correlation_agent import CorrelationAgent
from agents.correction_agent import CorrectionAgent


class NexusOrchestrator:
    """
    Master coordinator for NEXUS-IR.
    Runs the full autonomous investigation pipeline.
    No human intervention required after launch.
    """

    def __init__(self):
        self.name = "NEXUS-IR Orchestrator"
        self.version = "1.0.0"
        self.session_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.all_reports = {}
        self.iteration_log = []

    def _log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        icons = {
            "INFO": "ℹ️", "WARN": "⚠️", "ERROR": "❌",
            "START": "🚀", "DONE": "✅", "AGENT": "🤖",
            "FIND": "🔍", "REPORT": "📋"
        }
        icon = icons.get(level, "•")
        print(f"[{timestamp}] {icon} [{self.name}] {message}")
        self.iteration_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "message": message
        })

    def _print_banner(self):
        print("\n" + "="*55)
        print("   NEXUS-IR — Autonomous Incident Response Agent")
        print("   Find Evil! Hackathon — SANS Institute 2026")
        print("   'Find Evil.' — Two words. Full investigation.")
        print("="*55 + "\n")

    def _record_iteration(self, agent_name: str, status: str, findings_count: int):
        """Records each agent's iteration for the execution trace."""
        self.iteration_log.append({
            "iteration": len(self.iteration_log),
            "agent": agent_name,
            "status": status,
            "findings": findings_count,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    def _run_triage(self, case_path: str) -> dict:
        """Phase 1 — Triage."""
        self._log("Phase 1: TRIAGE — Examining evidence...", "AGENT")
        agent = TriageAgent()
        report = agent.run(case_path)
        self.all_reports["TriageAgent"] = report
        self._record_iteration("TriageAgent", report["status"], len(report["findings"]))
        self._log(f"Triage complete — Priority: {report['priority']}, Files: {report['total_files']}", "DONE")
        return report

    def _run_log_analysis(self, case_path: str) -> dict:
        """Phase 2 — Log Analysis."""
        self._log("Phase 2: LOG ANALYSIS — Hunting suspicious activity...", "AGENT")
        agent = LogAgent()
        report = agent.run(case_path)
        self.all_reports["LogAgent"] = report
        self._record_iteration("LogAgent", report["status"], len(report["findings"]))
        self._log(f"Log analysis complete — Suspicious files: {report['suspicious_files']}", "DONE")
        return report

    def _run_correlation(self) -> dict:
        """Phase 3 — Correlation."""
        self._log("Phase 3: CORRELATION — Cross-referencing all findings...", "AGENT")
        agent = CorrelationAgent()
        report = agent.run(self.all_reports)
        self._record_iteration("CorrelationAgent", report["status"], len(report["findings"]))
        threat = report["threat_assessment"]
        self._log(f"Correlation complete — Threat: {threat['level']} ({threat['score']}/100)", "DONE")
        return report

    def _run_correction(self, correlation_report: dict) -> dict:
        """Phase 4 — Self-Correction."""
        self._log("Phase 4: SELF-CORRECTION — Validating all findings...", "AGENT")
        agent = CorrectionAgent()
        report = agent.run(self.all_reports, correlation_report)
        self._record_iteration("CorrectionAgent", report["status"], report["summary"]["validated"])
        summary = report["summary"]
        self._log(f"Correction complete — {summary['accuracy_rate']}% accuracy, {summary['validated']} validated", "DONE")
        return report

    def _generate_final_report(self, triage: dict, log: dict,
                                correlation: dict, correction: dict) -> dict:
        """Assembles the complete investigation report."""
        threat = correlation.get("threat_assessment", {})
        summary = correction.get("summary", {})

        return {
            "nexus_ir_version": self.version,
            "session_id": self.session_id,
            "investigation_complete": True,
            "executive_summary": {
                "threat_level": threat.get("level", "UNKNOWN"),
                "threat_score": threat.get("score", 0),
                "case_priority": triage.get("priority", "UNKNOWN"),
                "total_files_analyzed": triage.get("total_files", 0),
                "attack_patterns_detected": len(correlation.get("attack_patterns", [])),
                "unique_ips_found": len(correlation.get("ip_correlations", [])),
                "findings_validated": summary.get("validated", 0),
                "findings_rejected": summary.get("rejected", 0),
                "overall_confidence": summary.get("overall_confidence", "UNKNOWN")
            },
            "attack_patterns": correlation.get("attack_patterns", []),
            "ip_correlations": correlation.get("ip_correlations", []),
            "timeline": correlation.get("timeline", []),
            "validated_findings": correction.get("validated_findings", []),
            "rejected_findings": correction.get("rejected_findings", []),
            "execution_trace": self.iteration_log,
            "agent_reports": {
                "triage": triage,
                "log_analysis": log,
                "correlation": correlation,
                "correction": correction
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def _print_summary(self, final_report: dict):
        """Prints a clean summary to the terminal."""
        es = final_report["executive_summary"]
        patterns = final_report["attack_patterns"]

        print("\n" + "="*55)
        print("   NEXUS-IR INVESTIGATION COMPLETE")
        print("="*55)
        print(f"   Session ID   : {final_report['session_id']}")
        print(f"   Threat Level : {es['threat_level']} ({es['threat_score']}/100)")
        print(f"   Priority     : {es['case_priority']}")
        print(f"   Files Scanned: {es['total_files_analyzed']}")
        print(f"   Confidence   : {es['overall_confidence']}")
        print(f"   Validated    : {es['findings_validated']} findings")
        print(f"   Rejected     : {es['findings_rejected']} findings")
        print("─"*55)
        if patterns:
            print("   ATTACK PATTERNS DETECTED:")
            for p in patterns:
                print(f"   🚨 {p['pattern']} [{p['confidence']}]")
                print(f"      MITRE: {p['mitre_technique']}")
        else:
            print("   No attack patterns detected.")
        print("="*55 + "\n")

    def investigate(self, case_path: str) -> dict:
        """
        Main entry point.
        Give it a case path — it does everything else.
        """
        self._print_banner()
        self._log(f"Starting investigation: {case_path}", "START")
        self._log(f"Session ID: {self.session_id}")
        start_time = datetime.now(timezone.utc)

        if not os.path.exists(case_path):
            self._log(f"Case path not found: {case_path}", "ERROR")
            return {"status": "ERROR", "error": f"Path not found: {case_path}"}

        # Run all phases
        triage = self._run_triage(case_path)
        log = self._run_log_analysis(case_path)
        correlation = self._run_correlation()
        correction = self._run_correction(correlation)

        # Build final report
        final_report = self._generate_final_report(triage, log, correlation, correction)

        # Calculate duration
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        final_report["duration_seconds"] = round(duration, 2)
        self._log(f"Total investigation time: {duration:.1f} seconds", "DONE")

        # Save report to file
        report_path = os.path.join(
            os.path.dirname(__file__),
            f"reports/output/report_{self.session_id}.json"
        )
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w") as f:
            json.dump(final_report, f, indent=2)
        self._log(f"Report saved: {report_path}", "REPORT")

        self._print_summary(final_report)
        return final_report


if __name__ == "__main__":
    test_path = "/data/data/com.termux/files/home/test_case"
    os.makedirs(test_path, exist_ok=True)

    with open(f"{test_path}/system.log", "w") as f:
        f.write("2026-05-01 03:12:44 Failed login attempt from 192.168.1.105\n")
        f.write("2026-05-01 03:12:45 Authentication failure for root\n")
        f.write("2026-05-01 03:12:50 sudo command executed by unknown user\n")
        f.write("2026-05-01 03:13:01 Unauthorized access attempt detected\n")
        f.write("2026-05-01 03:13:10 Reverse shell connection from 10.0.0.99\n")

    orchestrator = NexusOrchestrator()
    report = orchestrator.investigate(test_path)

    print(f"✅ Full pipeline test complete!")
    print(f"   Duration: {report.get('duration_seconds', 0)}s")
    print(f"   Threat: {report['executive_summary']['threat_level']}")
