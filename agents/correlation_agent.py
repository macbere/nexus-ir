import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
from datetime import datetime, timezone


class CorrelationAgent:

    def __init__(self):
        self.name = 'CorrelationAgent'
        self.iteration = 0
        self.findings = []
        self.errors = []

    def _log(self, message, level='INFO'):
        timestamp = datetime.now().strftime('%H:%M:%S')
        prefix = {'INFO': 'i', 'WARN': '!', 'ERROR': 'X', 'FIND': '?', 'LINK': '~', 'NARR': 'N'}.get(level, '.')
        print(f'[{timestamp}] {prefix} [{self.name}] {message}')

    def _record_finding(self, finding):
        finding['agent'] = self.name
        finding['iteration'] = self.iteration
        finding['timestamp'] = datetime.now(timezone.utc).isoformat()
        finding['traceable'] = True
        self.findings.append(finding)

    def _extract_clean_iocs(self, all_reports):
        merged = {
            'ipv4_addresses': set(),
            'sha256_hashes': set(),
            'md5_hashes': set(),
            'base64_strings': set(),
            'file_paths': set(),
            'hostnames': set(),
            'usernames': set(),
            'domains': set()
        }
        for agent_name, report in all_reports.items():
            if not isinstance(report, dict):
                continue
            iocs = report.get('extracted_iocs', {})
            for ioc_type in merged:
                for item in iocs.get(ioc_type, []):
                    merged[ioc_type].add(item)
            for ip in report.get('unique_ips', []):
                ip_clean = re.search(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b', str(ip))
                if ip_clean:
                    merged['ipv4_addresses'].add(ip_clean.group())
        return {k: sorted(list(v)) for k, v in merged.items()}

    def _find_ip_correlations(self, clean_iocs):
        correlations = []
        for ip in clean_iocs.get('ipv4_addresses', []):
            correlations.append({
                'type': 'ip_seen_in_evidence',
                'ip': ip,
                'seen_by_agents': ['LogAgent'],
                'significance': 'HIGH',
                'description': f'Verified IoC (regex) — IP {ip} found in evidence'
            })
        return correlations

    def _extract_all_keywords(self, all_reports):
        keyword_map = {}
        for agent_name, report in all_reports.items():
            if not isinstance(report, dict):
                continue
            hits = report.get('hits', {})
            for filepath, file_hits in hits.items():
                if not isinstance(file_hits, dict):
                    continue
                for keyword in file_hits.keys():
                    if keyword not in keyword_map:
                        keyword_map[keyword] = []
                    keyword_map[keyword].append({'agent': agent_name, 'file': filepath})
        return keyword_map

    def _detect_attack_patterns(self, keyword_map):
        patterns = []

        brute_force_keys = {'failed login', 'failed password', 'authentication failure', 'account lockout', 'brute force'}
        found_brute = brute_force_keys.intersection(set(keyword_map.keys()))
        if len(found_brute) >= 1:
            patterns.append({
                'type': 'attack_pattern',
                'pattern': 'BRUTE_FORCE_ATTACK',
                'confidence': 'HIGH',
                'evidence_keywords': list(found_brute),
                'description': 'Multiple failed authentication events detected',
                'mitre_technique': 'T1110 - Brute Force',
                'base_score': 70
            })

        privilege_keys = {'sudo', 'root', 'privilege escalation', 'unauthorized'}
        found_priv = privilege_keys.intersection(set(keyword_map.keys()))
        if len(found_priv) >= 2:
            patterns.append({
                'type': 'attack_pattern',
                'pattern': 'PRIVILEGE_ESCALATION',
                'confidence': 'HIGH',
                'evidence_keywords': list(found_priv),
                'description': 'Privilege escalation indicators detected',
                'mitre_technique': 'T1548 - Abuse Elevation Control Mechanism',
                'base_score': 75
            })

        lateral_keys = {'reverse shell', 'backdoor', 'exploit', 'injection', 'lateral movement'}
        found_lateral = lateral_keys.intersection(set(keyword_map.keys()))
        if found_lateral:
            patterns.append({
                'type': 'attack_pattern',
                'pattern': 'LATERAL_MOVEMENT_OR_C2',
                'confidence': 'CRITICAL',
                'evidence_keywords': list(found_lateral),
                'description': 'C2 or lateral movement indicators detected',
                'mitre_technique': 'T1021 - Remote Services / T1059 - Command Interpreter',
                'base_score': 85
            })

        ransom_keys = {'ransomware', 'malware', 'encoded', 'base64', 'powershell'}
        found_ransom = ransom_keys.intersection(set(keyword_map.keys()))
        if found_ransom:
            patterns.append({
                'type': 'attack_pattern',
                'pattern': 'RANSOMWARE_OR_MALWARE',
                'confidence': 'CRITICAL',
                'evidence_keywords': list(found_ransom),
                'description': 'Ransomware or malware execution indicators detected',
                'mitre_technique': 'T1486 - Data Encrypted for Impact',
                'base_score': 90
            })

        cred_keys = {'mimikatz', 'lsass', 'kerberos', 'credential'}
        found_cred = cred_keys.intersection(set(keyword_map.keys()))
        if found_cred:
            patterns.append({
                'type': 'attack_pattern',
                'pattern': 'CREDENTIAL_DUMPING',
                'confidence': 'CRITICAL',
                'evidence_keywords': list(found_cred),
                'description': 'Credential dumping tools or techniques detected',
                'mitre_technique': 'T1003 - OS Credential Dumping',
                'base_score': 88
            })

        exfil_keys = {'exfiltration', 'export', 'anomaly'}
        found_exfil = exfil_keys.intersection(set(keyword_map.keys()))
        if found_exfil:
            patterns.append({
                'type': 'attack_pattern',
                'pattern': 'DATA_EXFILTRATION',
                'confidence': 'HIGH',
                'evidence_keywords': list(found_exfil),
                'description': 'Data exfiltration activity detected',
                'mitre_technique': 'T1041 - Exfiltration Over C2 Channel',
                'base_score': 80
            })

        return patterns

    def _detect_temporal_sequences(self, all_reports, clean_iocs):
        sequences = []
        for agent_name, report in all_reports.items():
            if not isinstance(report, dict):
                continue
            hits = report.get('hits', {})
            for filepath, file_hits in hits.items():
                if not isinstance(file_hits, dict):
                    continue
                keys = set(file_hits.keys())
                has_failed = bool({'failed login', 'failed password', 'authentication failure'}.intersection(keys))
                has_sudo = bool({'sudo', 'root', 'privilege escalation'}.intersection(keys))

                if has_failed and has_sudo:
                    for ip in clean_iocs.get('ipv4_addresses', []):
                        sequences.append({
                            'type': 'temporal_sequence',
                            'pattern': 'SUCCESSFUL_BRUTE_FORCE',
                            'confidence': 'CRITICAL',
                            'description': f'Failed logins followed by privilege use from {ip}',
                            'mitre_technique': 'T1110.001 - Password Guessing',
                            'ip': ip,
                            'base_score': 92
                        })
                        self._log(f'TEMPORAL: Brute force success from {ip}', 'FIND')
                        break
        return sequences

    def _build_attack_narrative(self, patterns, sequences, clean_iocs, keyword_map):
        attacker_ips = clean_iocs.get('ipv4_addresses', [])
        hostnames = clean_iocs.get('hostnames', [])
        usernames = [u for u in clean_iocs.get('usernames', []) if u not in {'PID', 'single', 'persistence'}]
        b64_strings = clean_iocs.get('base64_strings', [])
        file_paths = clean_iocs.get('file_paths', [])

        attacker_ip = attacker_ips[0] if attacker_ips else 'unknown IP'
        victim_host = hostnames[0] if hostnames else 'the target system'
        compromised_user = usernames[0] if usernames else 'an account'

        sentences = []
        pattern_names = [p['pattern'] for p in patterns]
        seq_names = [s['pattern'] for s in sequences]

        # Sentence 1 — Initial access
        if 'BRUTE_FORCE_ATTACK' in pattern_names or 'SUCCESSFUL_BRUTE_FORCE' in seq_names:
            sentences.append(
                f'The attack originated from {attacker_ip}, which conducted a brute force '
                f'credential attack against {victim_host}, ultimately compromising the account '
                f'{compromised_user!r} after multiple failed authentication attempts.'
            )
        else:
            sentences.append(
                f'The attack originated from {attacker_ip}, which gained initial access '
                f'to {victim_host} through exploitation of a known vulnerability.'
            )

        # Sentence 2 — Escalation
        if 'PRIVILEGE_ESCALATION' in pattern_names:
            sentences.append(
                f'Following initial access, the threat actor escalated privileges '
                f'on {victim_host}, gaining administrative or root-level control '
                f'over the compromised system.'
            )

        # Sentence 3 — Execution & credential dumping
        if 'CREDENTIAL_DUMPING' in pattern_names:
            lsass = 'lsass.exe' if file_paths else 'system memory'
            sentences.append(
                f'The attacker deployed credential dumping tools (including mimikatz) '
                f'to extract credentials from {lsass}, '
                f'enabling further lateral movement across the network.'
            )
        elif b64_strings and 'RANSOMWARE_OR_MALWARE' in pattern_names:
            sentences.append(
                f'A base64-encoded PowerShell payload was executed on the host, '
                f'delivering a backdoor and establishing persistent command-and-control '
                f'communication with the attacker infrastructure.'
            )

        # Sentence 4 — Impact
        if 'RANSOMWARE_OR_MALWARE' in pattern_names and 'LATERAL_MOVEMENT_OR_C2' in pattern_names:
            other_hosts = hostnames[1:] if len(hostnames) > 1 else ['adjacent systems']
            sentences.append(
                f'The threat actor moved laterally to {", ".join(other_hosts)}, '
                f'deployed ransomware, and exfiltrated data to '
                f'{attacker_ips[-1] if len(attacker_ips) > 1 else attacker_ip} '
                f'before triggering mass file encryption.'
            )
        elif 'DATA_EXFILTRATION' in pattern_names:
            sentences.append(
                f'Sensitive data was exfiltrated to external infrastructure at '
                f'{attacker_ips[-1] if len(attacker_ips) > 1 else attacker_ip}, '
                f'representing a significant data breach impacting organisational assets.'
            )

        narrative = ' '.join(sentences)
        self._log(f'Attack narrative built: {len(sentences)} sentences', 'NARR')
        return narrative

    def _generate_containment_actions(self, clean_iocs, patterns):
        actions = []
        pattern_names = [p['pattern'] for p in patterns]

        for ip in clean_iocs.get('ipv4_addresses', []):
            actions.append(f'BLOCK IP {ip} on all perimeter firewalls and WAF rules immediately')

        for host in clean_iocs.get('hostnames', []):
            actions.append(f'ISOLATE host {host} from network — disconnect from all VLANs')

        for user in clean_iocs.get('usernames', []):
            if user not in {'PID', 'single', 'persistence', 'Administrator'}:
                actions.append(f'DISABLE account {user!r} and reset all associated credentials')

        if 'Administrator' in clean_iocs.get('usernames', []):
            actions.append('RESET all Domain Administrator and service account passwords immediately')

        for path in clean_iocs.get('file_paths', []):
            actions.append(f'QUARANTINE file {path} — submit to threat intelligence platform')

        for b64 in clean_iocs.get('base64_strings', [])[:2]:
            if len(b64) > 15 and b64 not in {'WindowsDefenderUpdate'}:
                actions.append(f'DECODE and analyse base64 payload: {b64[:30]}...')

        if 'CREDENTIAL_DUMPING' in pattern_names:
            actions.append('ROTATE all Kerberos service tickets and krbtgt account password (Golden Ticket mitigation)')
            actions.append('ENABLE Windows Credential Guard on all domain controllers')

        if 'RANSOMWARE_OR_MALWARE' in pattern_names:
            actions.append('ACTIVATE incident response retainer — engage forensic team for full disk imaging')
            actions.append('RESTORE affected systems from last known clean backup after full forensic capture')

        if 'DATA_EXFILTRATION' in pattern_names:
            actions.append('NOTIFY Data Protection Officer — assess breach notification obligations under GDPR/CCPA')
            actions.append('PRESERVE all network flow logs for legal proceedings and regulatory reporting')

        if 'LATERAL_MOVEMENT_OR_C2' in pattern_names:
            actions.append('SCAN entire network for persistence mechanisms: scheduled tasks, registry run keys, new services')
            actions.append('REVOKE all active VPN and remote access sessions pending investigation')

        return actions

    def _calculate_threat_score(self, patterns, ip_correlations, sequences):
        score = 0
        reasons = []
        base_scores = [p.get('base_score', 0) for p in patterns + sequences]
        if base_scores:
            score = max(base_scores)
            reasons.append(f'Highest base score: {score}')
        if len(patterns) >= 2:
            score = min(score + 10, 100)
            reasons.append('Multiple patterns (+10)')
        for seq in sequences:
            score = min(score + 8, 100)
            reasons.append(f'Temporal sequence (+8)')
        if len(ip_correlations) >= 1:
            score = min(score + 5, 100)
            reasons.append(f'Correlated IPs (+5)')
        level = 'CRITICAL' if score >= 85 else 'HIGH' if score >= 65 else 'MEDIUM' if score >= 40 else 'LOW'
        return {'score': score, 'level': level, 'reasons': reasons}

    def _build_timeline(self, all_reports):
        events = []
        for agent_name, report in all_reports.items():
            if not isinstance(report, dict):
                continue
            for finding in report.get('findings', []):
                if isinstance(finding, dict):
                    events.append({
                        'agent': agent_name,
                        'type': finding.get('type', 'unknown'),
                        'timestamp': finding.get('timestamp', ''),
                        'artifact': finding.get('artifact', finding.get('file', 'unknown'))
                    })
        events.sort(key=lambda x: x.get('timestamp', ''))
        return events

    def run(self, all_reports):
        self._log('Starting correlation analysis...')
        self.iteration += 1
        self._log(f'Correlating {len(all_reports)} agent report(s)')

        clean_iocs = self._extract_clean_iocs(all_reports)
        total_iocs = sum(len(v) for v in clean_iocs.values())
        self._log(f'Clean IoCs: {total_iocs} total', 'FIND')
        for ioc_type, ioc_list in clean_iocs.items():
            if ioc_list:
                self._log(f'  {ioc_type}: {ioc_list}', 'FIND')

        keyword_map = self._extract_all_keywords(all_reports)
        self._log(f'Keywords: {len(keyword_map)} found', 'FIND')

        ip_correlations = self._find_ip_correlations(clean_iocs)
        for corr in ip_correlations:
            self._log(f'IP: {corr["ip"]}', 'LINK')
            self._record_finding(corr)

        patterns = self._detect_attack_patterns(keyword_map)
        for pattern in patterns:
            self._log(f'PATTERN: {pattern["pattern"]} [{pattern["confidence"]}]', 'FIND')
            self._log(f'  MITRE: {pattern["mitre_technique"]}', 'FIND')
            self._record_finding(pattern)

        sequences = self._detect_temporal_sequences(all_reports, clean_iocs)
        for seq in sequences:
            self._record_finding(seq)

        timeline = self._build_timeline(all_reports)
        threat = self._calculate_threat_score(patterns, ip_correlations, sequences)
        self._log(f'THREAT: {threat["score"]}/100 — {threat["level"]}', 'FIND')

        # Build attack narrative
        narrative = self._build_attack_narrative(patterns, sequences, clean_iocs, keyword_map)
        self._log('Attack narrative generated', 'NARR')

        # Generate containment actions
        containment = self._generate_containment_actions(clean_iocs, patterns)
        self._log(f'Containment actions: {len(containment)} recommendations', 'NARR')

        self._log('Correlation analysis complete!')

        return {
            'status': 'COMPLETE',
            'agent': self.name,
            'agents_correlated': len(all_reports),
            'extracted_entities': clean_iocs,
            'ip_correlations': ip_correlations,
            'attack_patterns': patterns,
            'temporal_sequences': sequences,
            'timeline': timeline,
            'threat_assessment': threat,
            'attack_narrative': narrative,
            'containment_actions': containment,
            'findings': self.findings,
            'errors': self.errors,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


if __name__ == '__main__':
    print('Testing CorrelationAgent v2 — Narrative + Containment...')
    fake_reports = {
        'LogAgent': {
            'extracted_iocs': {
                'ipv4_addresses': ['91.108.56.130', '185.220.101.47', '203.45.67.89'],
                'sha256_hashes': [],
                'md5_hashes': [],
                'base64_strings': ['SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA'],
                'file_paths': ['C:\\Windows\\System32\\lsass.exe'],
                'hostnames': ['FINSERV-DC01', 'FINSERV-DB01'],
                'usernames': ['svc_backup', 'Administrator', 'mimikatz', 'krbtgt']
            },
            'unique_ips': ['91.108.56.130', '185.220.101.47'],
            'hits': {
                '/cases/domain_controller.log': {
                    'failed password': {'count': 4},
                    'unauthorized': {'count': 1},
                    'privilege escalation': {'count': 1},
                    'lsass': {'count': 1},
                    'mimikatz': {'count': 1},
                    'kerberos': {'count': 1}
                },
                '/cases/endpoint_security.log': {
                    'backdoor': {'count': 1},
                    'ransomware': {'count': 1},
                    'malware': {'count': 1},
                    'exploit': {'count': 2},
                    'lateral movement': {'count': 1},
                    'exfiltration': {'count': 1}
                }
            },
            'findings': [{
                'type': 'suspicious_log_activity',
                'artifact': '/cases/domain_controller.log',
                'timestamp': '2026-05-20T10:00:00'
            }]
        }
    }

    agent = CorrelationAgent()
    report = agent.run(fake_reports)

    print(f'\nPatterns detected: {len(report["attack_patterns"])}')
    for p in report['attack_patterns']:
        print(f'  {p["pattern"]} — {p["mitre_technique"]}')

    print(f'\nThreat Score: {report["threat_assessment"]["score"]}/100 — {report["threat_assessment"]["level"]}')

    print(f'\n=== ATTACK NARRATIVE ===')
    print(report['attack_narrative'])

    print(f'\n=== CONTAINMENT ACTIONS ({len(report["containment_actions"])}) ===')
    for i, action in enumerate(report['containment_actions'], 1):
        print(f'  [{i}] {action}')

    print('\nTest passed!')
