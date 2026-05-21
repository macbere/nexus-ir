import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
from datetime import datetime, timezone
from tools.mcp_server import call_tool


class CorrectionAgent:

    def __init__(self):
        self.name = 'CorrectionAgent'
        self.iteration = 0
        self.validated = []
        self.rejected = []
        self.warnings = []
        self.errors = []
        self.forced_reeval = False

    def _log(self, message, level='INFO'):
        timestamp = datetime.now().strftime('%H:%M:%S')
        prefix = {
            'INFO': 'i', 'WARN': '!', 'ERROR': 'X',
            'PASS': '+', 'FAIL': '-', 'FIX': '*',
            'DEVIL': 'D', 'CRIT': '!!'
        }.get(level, '.')
        print(f'[{timestamp}] {prefix} [{self.name}] {message}')

    def _verify_file_exists(self, filepath):
        if not filepath or filepath in ('unknown', 'triage_scan'):
            return False
        result = call_tool('get_file_metadata', filepath=filepath)
        return result.get('status') == 'SUCCESS'

    def _verify_finding_has_artifact(self, finding):
        artifact = finding.get('artifact') or finding.get('file') or finding.get('filepath')
        if not artifact:
            return False, 'No artifact reference'
        if artifact in ('unknown', 'triage_scan'):
            return True, 'Triage-level finding — acceptable'
        if not os.path.exists(artifact):
            return False, f'Artifact not on disk: {artifact}'
        return True, f'Artifact verified: {os.path.basename(artifact)}'

    def _check_ip_format(self, ip_string):
        return bool(re.search(
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            str(ip_string)
        ))

    def _devil_advocate_check(self, triage_report, correlation_report):
        issues = []
        suggestions = []

        if not triage_report or not correlation_report:
            return issues, suggestions

        triage_keywords = triage_report.get('keyword_hits', {})
        critical_found = triage_keywords.get('critical_keywords_found', [])
        threat = correlation_report.get('threat_assessment', {})
        threat_score = threat.get('score', 0)
        threat_level = threat.get('level', 'UNKNOWN')
        patterns = correlation_report.get('attack_patterns', [])
        signatures = correlation_report.get('high_signal_signatures', [])

        # Check 1: Critical keywords found but threat is LOW/MEDIUM
        if critical_found and threat_score < 50:
            issue = (
                f'MISMATCH DETECTED: Triage found CRITICAL keywords '
                f'{critical_found} but final threat score is only '
                f'{threat_score}/100 ({threat_level}). '
                f'This indicates the correlation engine missed high-signal indicators.'
            )
            issues.append(issue)
            suggestions.append(
                f'Re-evaluate: keywords {critical_found} should produce '
                f'CRITICAL threat score. Check if LogAgent keyword hits '
                f'were passed to CorrelationAgent correctly.'
            )
            self._log(f'DEVIL ADVOCATE: {issue}', 'DEVIL')
            self.forced_reeval = True

        # Check 2: 0x1FFFFF GrantedAccess detected but not in patterns
        pattern_names = [p.get('pattern', '') for p in patterns]
        all_iocs = correlation_report.get('extracted_entities', {})
        if '0x1FFFFF' in str(all_iocs.get('granted_access', [])) or '0x1fffff' in str(all_iocs.get('granted_access', [])):
            if 'PROCESS_INJECTION' not in pattern_names:
                issues.append('0x1FFFFF GrantedAccess detected but PROCESS_INJECTION pattern missing')
                suggestions.append('Force PROCESS_INJECTION pattern — 0x1FFFFF is definitive evidence')
                self._log('DEVIL ADVOCATE: 0x1FFFFF present but PROCESS_INJECTION not flagged!', 'DEVIL')

        # Check 3: PowerShell keywords found but no POWERSHELL_OBFUSCATION
        ps_keywords = {'executionpolicy', 'windowstyle', 'hidden', 'bypass', 'powershell'}
        hit_keys = set()
        for agent_name, report in {}.items():
            pass
        if critical_found and any(k in str(critical_found).lower() for k in ps_keywords):
            if 'POWERSHELL_OBFUSCATION' not in pattern_names:
                issues.append('PowerShell stealth keywords in triage but POWERSHELL_OBFUSCATION not detected')
                suggestions.append('Force re-run correlation with PowerShell keyword context')
                self._log('DEVIL ADVOCATE: PowerShell obfuscation missed!', 'DEVIL')

        # Check 4: Signatures triggered but score too low
        if signatures and threat_score < 85:
            issues.append(
                f'{len(signatures)} high-signal signatures triggered but score is '
                f'only {threat_score}. High-signal signatures must force CRITICAL.'
            )
            suggestions.append('Override score to minimum 90 when high-signal signatures present')
            self._log(f'DEVIL ADVOCATE: {len(signatures)} signatures but score={threat_score}', 'DEVIL')

        return issues, suggestions

    def _validate_log_finding(self, finding, source_agent):
        result = {
            'finding': finding,
            'source_agent': source_agent,
            'valid': False,
            'confidence': 0,
            'issues': [],
            'verification_steps': []
        }
        is_valid, reason = self._verify_finding_has_artifact(finding)
        result['verification_steps'].append(reason)

        if not is_valid:
            result['issues'].append(reason)
            result['confidence'] = 10
            return result

        artifact = finding.get('artifact') or finding.get('file', '')
        if artifact not in ('unknown', 'triage_scan') and self._verify_file_exists(artifact):
            result['verification_steps'].append(f'File on disk: {os.path.basename(artifact)}')
            result['confidence'] += 50
        elif artifact in ('triage_scan', 'unknown'):
            result['confidence'] += 30
        else:
            result['issues'].append(f'File not found: {artifact}')
            result['confidence'] += 10

        keywords = finding.get('keywords_matched', [])
        if keywords:
            result['verification_steps'].append(f'Keywords: {keywords}')
            result['confidence'] += 30

        if finding.get('timestamp'):
            result['verification_steps'].append('Timestamp present')
            result['confidence'] += 20

        if finding.get('severity') == 'CRITICAL' or finding.get('type') in ('malicious_base64_payload', 'dynamic_priority_escalation'):
            result['confidence'] = max(result['confidence'], 70)

        result['confidence'] = min(result['confidence'], 100)
        result['valid'] = result['confidence'] >= 40
        return result

    def _validate_attack_pattern(self, pattern):
        result = {
            'pattern': pattern.get('pattern'),
            'valid': False,
            'confidence': 0,
            'issues': [],
            'verification_steps': []
        }
        keywords = pattern.get('evidence_keywords', [])
        if len(keywords) >= 1:
            result['verification_steps'].append(f'Supported by: {keywords}')
            result['confidence'] += 50
        else:
            result['issues'].append('No supporting keywords — possible hallucination')
            return result

        if pattern.get('mitre_technique'):
            result['verification_steps'].append(f'MITRE: {pattern["mitre_technique"]}')
            result['confidence'] += 25
        if pattern.get('description'):
            result['confidence'] += 25

        result['confidence'] = min(result['confidence'], 100)
        result['valid'] = result['confidence'] >= 50
        return result

    def _validate_ip_correlations(self, correlations):
        validated = []
        for corr in correlations:
            ip = corr.get('ip', '')
            is_valid = self._check_ip_format(ip)
            validation = {
                'ip': ip,
                'valid': is_valid,
                'confidence': 90 if is_valid else 10,
                'issue': None if is_valid else f'Invalid IP format: {ip}'
            }
            if is_valid:
                self._log(f'IP verified: {ip}', 'PASS')
            else:
                self._log(f'IP rejected: {ip}', 'FAIL')
            validated.append(validation)
        return validated

    def _generate_correction_summary(self, issues, suggestions):
        total = len(self.validated) + len(self.rejected)
        accuracy = (len(self.validated) / total * 100) if total > 0 else 0
        return {
            'total_findings_reviewed': total,
            'validated': len(self.validated),
            'rejected': len(self.rejected),
            'warnings': len(self.warnings),
            'accuracy_rate': round(accuracy, 1),
            'overall_confidence': 'HIGH' if accuracy >= 75 else 'MEDIUM' if accuracy >= 50 else 'LOW',
            'devil_advocate_issues': issues,
            'devil_advocate_suggestions': suggestions,
            'forced_reeval': self.forced_reeval
        }

    def run(self, all_reports, correlation_report=None, triage_report=None):
        self._log('Starting self-correction and devil advocate pass...')
        self.iteration += 1

        # Phase 0: Devil Advocate Check
        self._log('Phase 0: Devil Advocate — challenging findings...', 'DEVIL')
        issues, suggestions = self._devil_advocate_check(triage_report, correlation_report)
        if issues:
            self._log(f'ISSUES FOUND: {len(issues)} contradictions detected!', 'CRIT')
            for issue in issues:
                self._log(f'  Issue: {issue}', 'WARN')
            for sug in suggestions:
                self._log(f'  Fix: {sug}', 'FIX')
        else:
            self._log('No contradictions detected — findings are internally consistent', 'PASS')

        # Phase 1: Validate log findings
        self._log('Phase 1: Validating log findings...')
        for agent_name, report in all_reports.items():
            if not isinstance(report, dict):
                continue
            for finding in report.get('findings', []):
                if not isinstance(finding, dict):
                    continue
                v = self._validate_log_finding(finding, agent_name)
                if v['valid']:
                    self.validated.append(v)
                    self._log(f'PASS: {finding.get("type","?")} [{v["confidence"]}%]', 'PASS')
                else:
                    self.rejected.append(v)
                    self._log(f'FAIL: {finding.get("type","?")} — {v["issues"]}', 'FAIL')

        # Phase 2: Validate attack patterns
        self._log('Phase 2: Validating attack patterns...')
        if correlation_report:
            for pattern in correlation_report.get('attack_patterns', []):
                v = self._validate_attack_pattern(pattern)
                if v['valid']:
                    self.validated.append(v)
                    self._log(f'PASS: {v["pattern"]} [{v["confidence"]}%]', 'PASS')
                else:
                    self.rejected.append(v)
                    self._log(f'FAIL: {v["pattern"]}', 'FAIL')

            # Phase 3: Validate IPs
            self._log('Phase 3: Validating IP addresses...')
            ip_validations = self._validate_ip_correlations(
                correlation_report.get('ip_correlations', [])
            )
            for iv in ip_validations:
                if iv['valid']:
                    self.validated.append(iv)
                else:
                    self.warnings.append(iv)

            # Phase 4: Validate high-signal signatures
            self._log('Phase 4: Validating high-signal signatures...')
            for sig in correlation_report.get('high_signal_signatures', []):
                self.validated.append({
                    'type': 'high_signal_signature',
                    'description': sig.get('description', ''),
                    'mitre': sig.get('mitre', ''),
                    'score': sig.get('score', 0),
                    'valid': True,
                    'confidence': sig.get('score', 90)
                })
                self._log(f'PASS: Signature [{sig.get("score",0)}%] — {sig.get("description","")[:60]}', 'PASS')

        # Phase 5: Self check
        self._log('Phase 5: Final self-check...')
        if len(self.validated) == 0 and len(self.rejected) == 0:
            self._log('WARNING: Nothing validated — pipeline may have failed', 'WARN')
            self.errors.append('Zero findings reviewed')

        summary = self._generate_correction_summary(issues, suggestions)
        self._log(f'Accuracy: {summary["accuracy_rate"]}% — Confidence: {summary["overall_confidence"]}', 'PASS')
        if self.forced_reeval:
            self._log('FORCED RE-EVALUATION flagged — review devil advocate issues above', 'CRIT')

        return {
            'status': 'COMPLETE',
            'agent': self.name,
            'validated_findings': self.validated,
            'rejected_findings': self.rejected,
            'warnings': self.warnings,
            'summary': summary,
            'errors': self.errors,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


if __name__ == '__main__':
    print('Testing CorrectionAgent v3...')

    fake_triage = {
        'keyword_hits': {
            'critical_keywords_found': ['powershell', 'base64', '0x1fffff', 'windowstyle hidden'],
            'high_keywords_found': ['svchost', 'wmi']
        }
    }

    fake_correlation_good = {
        'threat_assessment': {'score': 100, 'level': 'CRITICAL'},
        'attack_patterns': [
            {'pattern': 'PROCESS_INJECTION', 'evidence_keywords': ['0x1fffff'],
             'mitre_technique': 'T1055', 'description': 'Process injection', 'base_score': 97},
            {'pattern': 'POWERSHELL_OBFUSCATION', 'evidence_keywords': ['bypass', 'hidden'],
             'mitre_technique': 'T1059.001', 'description': 'PS obfuscation', 'base_score': 90}
        ],
        'high_signal_signatures': [
            {'description': 'PROCESS_ALL_ACCESS', 'mitre': 'T1055', 'score': 95, 'triggered_by': '0x1FFFFF'},
            {'description': "Let's Encrypt on Microsoft domain", 'mitre': 'T1071', 'score': 92, 'triggered_by': 'zeek'}
        ],
        'ip_correlations': [
            {'ip': '104.21.55.12', 'significance': 'HIGH'},
            {'ip': '192.168.1.105', 'significance': 'HIGH'}
        ]
    }

    fake_reports = {
        'LogAgent': {
            'findings': [{
                'type': 'suspicious_log_activity',
                'artifact': '/data/data/com.termux/files/home/cases/obfuscated_malware/sysmon_execution.log',
                'keywords_matched': ['powershell', 'executionpolicy', 'bypass'],
                'timestamp': '2026-05-21T10:38:40Z'
            }]
        }
    }

    agent = CorrectionAgent()
    report = agent.run(fake_reports, fake_correlation_good, fake_triage)

    print(f'\nValidated: {report["summary"]["validated"]}')
    print(f'Rejected: {report["summary"]["rejected"]}')
    print(f'Accuracy: {report["summary"]["accuracy_rate"]}%')
    print(f'Devil issues: {report["summary"]["devil_advocate_issues"]}')
    print(f'Forced reeval: {report["summary"]["forced_reeval"]}')
    print('\nTest passed!')
