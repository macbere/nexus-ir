import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from orchestrator import NexusOrchestrator
try:
    from langgraph_orchestrator import LangGraphOrchestrator
    USE_LANGGRAPH = True
except ImportError:
    USE_LANGGRAPH = False
from reports.generator import ReportGenerator

def main():
    print("NEXUS-IR Find Evil Hackathon Submission")
    if len(sys.argv) < 2:
        case_path = "/data/data/com.termux/files/home/test_case"
        os.makedirs(case_path, exist_ok=True)
        with open(case_path + "/system.log", "w") as f:
            f.write("Failed login attempt from 192.168.1.105\n")
            f.write("Authentication failure for root\n")
            f.write("sudo command executed by unknown user\n")
            f.write("Unauthorized access attempt detected\n")
            f.write("Reverse shell connection from 10.0.0.99\n")
    else:
        case_path = sys.argv[1]
    if USE_LANGGRAPH:
        orchestrator = LangGraphOrchestrator()
    else:
        orchestrator = NexusOrchestrator()
    final_report = orchestrator.investigate(case_path)
    generator = ReportGenerator()
    generator.generate_text_report(final_report)
    es = final_report.get("executive_summary", {})
    print("Investigation complete!")
    print("Threat: " + es.get("threat_level", "?"))
    print("Duration: " + str(final_report.get("duration_seconds", 0)) + "s")

if __name__ == "__main__":
    main()
