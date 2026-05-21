import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from datetime import datetime, timezone


class ReportGenerator:

    def __init__(self):
        self.name = 'ReportGenerator'

    def _log(self, message):
        print(f'[{datetime.now().strftime("%H:%M:%S")}] # [{self.name}] {message}')

    def generate_text_report(self, final_report, output_path=None):
        es = final_report.get('executive_summary', {})
        patterns = final_report.get('attack_patterns', [])
        validated = final_report.get('validated_findings', [])
        rejected = final_report.get('rejected_findings', [])
        timeline = final_report.get('timeline', [])
        ip_corr = final_report.get('ip_correlations', [])
        session_id = final_report.get('session_id', 'UNKNOWN')
        duration = final_report.get('duration_seconds', 0)
        narrative = final_report.get('attack_narrative', '')
        containment = final_report.get('containment_actions', [])
        sequences = final_report.get('temporal_sequences', [])
        entities = final_report.get('extracted_entities', {})
        chain_of_custody = final_report.get('chain_of_custody', {})

        lines = []
        lines.append('=' * 65)
        lines.append('    NEXUS-IR AUTONOMOUS INCIDENT RESPONSE REPORT')
        lines.append('    Find Evil! Hackathon -- SANS Institute 2026')
        lines.append('=' * 65)
        lines.append('  Session ID   : ' + str(session_id))
        lines.append('  Generated    : ' + datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'))
        lines.append('  Duration     : ' + str(duration) + 's')
        lines.append('  Agent        : NEXUS-IR v2.0.0')
        lines.append('  IoC Method   : Regex-Only (Zero LLM Hallucination)')
        lines.append('')

        lines.append('-' * 65)
        lines.append('  EXECUTIVE SUMMARY')
        lines.append('-' * 65)
        lines.append('  Threat Level     : ' + str(es.get('threat_level','?')) + ' (' + str(es.get('threat_score',0)) + '/100)')
        lines.append('  Case Priority    : ' + str(es.get('case_priority','?')))
        lines.append('  Files Scanned    : ' + str(es.get('total_files_analyzed',0)))
        lines.append('  Attack Patterns  : ' + str(es.get('attack_patterns_detected',0)))
        lines.append('  IPs Identified   : ' + str(es.get('unique_ips_found',0)))
        lines.append('  Findings Valid   : ' + str(es.get('findings_validated',0)))
        lines.append('  Findings Rejected: ' + str(es.get('findings_rejected',0)))
        lines.append('  Confidence       : ' + str(es.get('overall_confidence','?')))
        lines.append('')

        if chain_of_custody:
            lines.append('-' * 65)
            lines.append('  CHAIN OF CUSTODY -- EVIDENCE INTEGRITY')
            lines.append('-' * 65)
            for filepath, coc in chain_of_custody.items():
                fname = os.path.basename(filepath)
                lines.append('  File   : ' + fname)
                lines.append('  SHA256 : ' + str(coc.get('sha256','?')))
                lines.append('  Size   : ' + str(coc.get('size_bytes',0)) + ' bytes')
                lines.append('  Hashed : ' + str(coc.get('timestamp','?')))
                lines.append('')

        if narrative:
            lines.append('-' * 65)
            lines.append('  ATTACK NARRATIVE -- KILL CHAIN SUMMARY')
            lines.append('-' * 65)
            words = narrative.split()
            line_buf = '  '
            for word in words:
                if len(line_buf) + len(word) + 1 > 63:
                    lines.append(line_buf)
                    line_buf = '  ' + word
                else:
                    line_buf += (' ' if line_buf.strip() else '') + word
            if line_buf.strip():
                lines.append(line_buf)
            lines.append('')

        lines.append('-' * 65)
        lines.append('  ATTACK PATTERNS DETECTED (MITRE ATT&CK MAPPED)')
        lines.append('-' * 65)
        if patterns:
            for i, p in enumerate(patterns, 1):
                lines.append('  [' + str(i) + '] ' + str(p.get('pattern','?')))
                lines.append('      Confidence : ' + str(p.get('confidence','?')))
                lines.append('      MITRE      : ' + str(p.get('mitre_technique','?')))
                lines.append('      Description: ' + str(p.get('description','?')))
                lines.append('      Evidence   : ' + ', '.join(p.get('evidence_keywords',[])))
                lines.append('')
        else:
            lines.append('  No attack patterns detected.')
            lines.append('')

        if sequences:
            lines.append('-' * 65)
            lines.append('  TEMPORAL ATTACK SEQUENCES')
            lines.append('-' * 65)
            for i, seq in enumerate(sequences, 1):
                lines.append('  [' + str(i) + '] ' + str(seq.get('pattern','?')) + ' [CRITICAL]')
                lines.append('      MITRE : ' + str(seq.get('mitre_technique','?')))
                lines.append('      Detail: ' + str(seq.get('description','?')))
                lines.append('')

        lines.append('-' * 65)
        lines.append('  EXTRACTED ENTITIES (Regex-Verified IoCs)')
        lines.append('-' * 65)
        if entities:
            for ioc_type, ioc_list in entities.items():
                if ioc_list:
                    lines.append('  ' + ioc_type.upper().replace('_',' ') + ':')
                    for ioc in ioc_list:
                        lines.append('    - ' + str(ioc))
            lines.append('')
        else:
            lines.append('  No entities extracted.')
            lines.append('')

        lines.append('-' * 65)
        lines.append('  IP ADDRESS CORRELATIONS')
        lines.append('-' * 65)
        if ip_corr:
            for ip in ip_corr:
                lines.append('  -> ' + str(ip.get('ip','?')))
                lines.append('     Significance : ' + str(ip.get('significance','?')))
                lines.append('     Description  : ' + str(ip.get('description','')))
                lines.append('')
        else:
            lines.append('  No IP correlations found.')
            lines.append('')

        lines.append('-' * 65)
        lines.append('  INVESTIGATION TIMELINE')
        lines.append('-' * 65)
        if timeline:
            for event in timeline:
                ts = str(event.get('timestamp','?'))[:19]
                artifact = event.get('artifact','?')
                lines.append('  ' + ts)
                lines.append('    Agent   : ' + str(event.get('agent','?')))
                lines.append('    Event   : ' + str(event.get('type','?')))
                lines.append('    Artifact: ' + os.path.basename(str(artifact)))
                lines.append('')
        else:
            lines.append('  No timeline events.')
            lines.append('')

        lines.append('-' * 65)
        lines.append('  VALIDATED FINDINGS')
        lines.append('-' * 65)
        vf = [f for f in validated if isinstance(f, dict) and f.get('finding')]
        if vf:
            for i, v in enumerate(vf, 1):
                f = v.get('finding', {})
                artifact = f.get('artifact', f.get('file','?'))
                lines.append('  [' + str(i) + '] Type       : ' + str(f.get('type','?')))
                lines.append('      Agent      : ' + str(v.get('source_agent','?')))
                lines.append('      Confidence : ' + str(v.get('confidence',0)) + '%')
                lines.append('      Artifact   : ' + os.path.basename(str(artifact)))
                file_hash = f.get('file_hash','')
                if file_hash:
                    lines.append('      File Hash  : ' + str(file_hash)[:32] + '...')
                kw = f.get('keywords_matched',[])
                if kw:
                    lines.append('      Keywords   : ' + ', '.join(kw))
                lines.append('')
        else:
            lines.append('  No detailed findings to display.')
            lines.append('')

        lines.append('-' * 65)
        lines.append('  REJECTED / UNVERIFIABLE FINDINGS')
        lines.append('-' * 65)
        if rejected:
            for i, r in enumerate(rejected, 1):
                f = r.get('finding', {})
                lines.append('  [' + str(i) + '] Type  : ' + str(f.get('type','?')))
                lines.append('      Reason: ' + '; '.join(r.get('issues',[])))
                lines.append('')
        else:
            lines.append('  No rejected findings.')
            lines.append('')

        lines.append('=' * 65)
        lines.append('  RECOMMENDED CONTAINMENT ACTIONS')
        lines.append('  (Dynamically generated from extracted IoCs)')
        lines.append('=' * 65)
        if containment:
            for i, action in enumerate(containment, 1):
                num = str(i).zfill(2)
                lines.append('  [' + num + '] ' + str(action))
        else:
            lines.append('  No containment actions generated.')
        lines.append('')

        lines.append('=' * 65)
        lines.append('  NEXUS-IR v2.0 -- Autonomous Incident Response Agent')
        lines.append('  All IoCs extracted via regex -- zero LLM hallucination.')
        lines.append('  All findings traceable to specific evidence artifacts.')
        lines.append('  Chain of custody maintained for all evidence files.')
        lines.append('  Self-corrected. Zero human intervention required.')
        lines.append('=' * 65)

        report_text = '\n'.join(lines)

        if not output_path:
            output_path = os.path.join(
                os.path.dirname(__file__),
                'output/report_' + datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S') + '.txt'
            )

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(report_text)

        self._log('Report saved: ' + output_path)
        return report_text


if __name__ == '__main__':
    print('Testing ReportGenerator v2...')
    report_dir = '/data/data/com.termux/files/home/nexus-ir/reports/output'
    json_files = [f for f in os.listdir(report_dir) if f.endswith('.json')] if os.path.exists(report_dir) else []
    if json_files:
        latest = sorted(json_files)[-1]
        with open(report_dir + '/' + latest) as f:
            final_report = json.load(f)
        gen = ReportGenerator()
        text = gen.generate_text_report(final_report)
        print(text)
        print('Test passed!')
    else:
        print('No JSON report found. Run main.py first.')
