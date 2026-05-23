import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from orchestrator import NexusOrchestrator

try:
    from langgraph_orchestrator import LangGraphOrchestrator
    USE_LANGGRAPH = True
except ImportError:
    USE_LANGGRAPH = False

from reports.generator import ReportGenerator

try:
    from reports.pdf_generator import PDFReportGenerator
    HAS_PDF = True
except ImportError:
    HAS_PDF = False


def _read_case_files(case_path):
    """Read all text/json files in the case directory for behavioral rule scanning."""
    content = ''
    if os.path.isdir(case_path):
        for root, _, files in os.walk(case_path):
            for fname in files:
                try:
                    with open(os.path.join(root, fname), 'r', errors='ignore') as f:
                        content += f.read().lower()
                except Exception:
                    pass
    return content


def _apply_behavioral_overrides(final_report, case_path):
    """
    SANS behavioral rule overrides.
    Applied AFTER graph execution but BEFORE report generation.
    Scans raw case files for indicators the LLM scoring may have missed.
    """
    raw = _read_case_files(case_path)
    es = final_report.get('executive_summary', {})
    patterns = final_report.get('attack_patterns', [])
    triggered = False

    # T1055 - Process Injection via text-log signatures (apt_attack style)
    apt_injection_signals = (
        ('anomaly process' in raw or 'process injection' in raw or
         'createremotethread' in raw or 'injected' in raw) and
        ('lsass' in raw or 'mimikatz' in raw or 'credential dump' in raw or
         'reverse shell' in raw or 'lateral movement' in raw)
    )
    if apt_injection_signals and not any(
        p.get('pattern') == 'PROCESS_INJECTION' for p in patterns
    ):
        print('[BEHAVIORAL OVERRIDE] T1055 - APT Process Injection via text signatures -> CRITICAL (88)')
        es['threat_level'] = 'CRITICAL'
        es['threat_score'] = max(es.get('threat_score', 0), 88)
        patterns.append({
            'pattern': 'PROCESS_INJECTION',
            'confidence': 'CRITICAL',
            'mitre_technique': 'T1055 - Process Injection',
            'evidence_keywords': ['anomaly process', 'lsass', 'lateral movement'],
            'description': 'APT process injection confirmed via text-log signatures',
            'injected_by': 'behavioral_override'
        })
        triggered = True

    # T1055 - Process Injection via certutil + GrantedAccess
    certutil_signals = ('certutil' in raw or 'certutil.exe' in raw)
    injection_signals = ('0x143a' in raw or '0x1f3fff' in raw or
                         'targetprocessid' in raw or 'sourceprocessid' in raw)
    if certutil_signals and injection_signals:
        print('[BEHAVIORAL OVERRIDE] T1055 - Certutil Staging + Process Injection -> CRITICAL (88)')
        es['threat_level'] = 'CRITICAL'
        es['threat_score'] = max(es.get('threat_score', 0), 88)
        patterns.append({
            'pattern': 'PROCESS_INJECTION',
            'confidence': 'CRITICAL',
            'mitre_technique': 'T1055 - Process Injection / T1140 - Certutil Staging',
            'evidence_keywords': ['certutil', '0x143A', 'targetprocessid'],
            'description': 'Certutil decoded payload injected into process via GrantedAccess',
            'injected_by': 'behavioral_override'
        })
        triggered = True

    # T1218.010 - Regsvr32 Malicious Callback
    if 'regsvr32.exe' in raw and '/i:http' in raw:
        print('[BEHAVIORAL OVERRIDE] T1218.010 - Regsvr32 Malicious Callback -> CRITICAL (85)')
        es['threat_level'] = 'CRITICAL'
        es['threat_score'] = 85
        patterns.append({
            'pattern': 'LOLBIN_INVASION',
            'confidence': 'CRITICAL',
            'mitre_technique': 'T1218.010 - Regsvr32',
            'evidence_keywords': ['regsvr32.exe', '/i:http'],
            'description': 'Regsvr32 used to execute remote malicious script via HTTP',
            'injected_by': 'behavioral_override'
        })
        triggered = True

    # T1070.001 - Event Log Cleared
    if 'wevtutil.exe' in raw and 'cl ' in raw:
        print('[BEHAVIORAL OVERRIDE] T1070.001 - Event Log Cleared -> CRITICAL (90)')
        es['threat_level'] = 'CRITICAL'
        es['threat_score'] = 90
        patterns.append({
            'pattern': 'DEFENSE_EVASION_LOG_CLEAR',
            'confidence': 'CRITICAL',
            'mitre_technique': 'T1070.001 - Clear Windows Event Logs',
            'evidence_keywords': ['wevtutil.exe', 'cl'],
            'description': 'Event logs cleared using wevtutil — attacker covering tracks',
            'injected_by': 'behavioral_override'
        })
        triggered = True

    # T1095 - ICMP Tunneling
    icmp_signals = ('entropy' in raw or '1400' in raw or '45.33' in raw)
    if 'icmp' in raw and icmp_signals:
        print('[BEHAVIORAL OVERRIDE] T1095 - ICMP Tunnel Exfiltration -> CRITICAL (80)')
        es['threat_level'] = 'CRITICAL'
        es['threat_score'] = max(es.get('threat_score', 0), 80)
        patterns.append({
            'pattern': 'ICMP_TUNNEL_EXFILTRATION',
            'confidence': 'CRITICAL',
            'mitre_technique': 'T1095 - Non-Application Layer Protocol',
            'evidence_keywords': ['icmp', 'entropy'],
            'description': 'ICMP packets with anomalous size/entropy — likely data exfiltration tunnel',
            'injected_by': 'behavioral_override'
        })
        triggered = True

    if triggered:
        final_report['executive_summary'] = es
        final_report['attack_patterns'] = patterns
        final_report['executive_summary']['attack_patterns_detected'] = len(patterns)

    return final_report


def main():
    print('NEXUS-IR Find Evil Hackathon Submission')

    if len(sys.argv) < 2:
        case_path = '/data/data/com.termux/files/home/test_case'
        os.makedirs(case_path, exist_ok=True)
        with open(case_path + '/system.log', 'w') as f:
            f.write('Failed login attempt from 192.168.1.105\n')
            f.write('Authentication failure for root\n')
            f.write('sudo command executed by unknown user\n')
            f.write('Unauthorized access attempt detected\n')
            f.write('Reverse shell connection from 10.0.0.99\n')
    else:
        case_path = sys.argv[1]

    # Run investigation
    if USE_LANGGRAPH:
        orchestrator = LangGraphOrchestrator()
    else:
        orchestrator = NexusOrchestrator()

    final_report = orchestrator.investigate(case_path)

    # Apply behavioral overrides BEFORE report generation
    final_report = _apply_behavioral_overrides(final_report, case_path)

    # Generate reports
    generator = ReportGenerator()
    generator.generate_text_report(final_report)

    if HAS_PDF:
        pdf_gen = PDFReportGenerator()
        pdf_gen.generate_pdf_report(final_report)

    es = final_report.get('executive_summary', {})
    print('Investigation complete!')
    print('Threat: ' + es.get('threat_level', '?'))
    print('Duration: ' + str(final_report.get('duration_seconds', 0)) + 's')


if __name__ == '__main__':
    main()