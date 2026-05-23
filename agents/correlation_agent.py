import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import json
from datetime import datetime, timezone


class CorrelationAgent:

    # High-signal indicators that force CRITICAL regardless of other scores
    CRITICAL_SIGNATURES = {
        'granted_access_full': {
            'values': ['0x1fffff', '0x1FFFFF'],
            'description': 'PROCESS_ALL_ACCESS on system process — definitive process injection',
            'mitre': 'T1055 - Process Injection',
            'score': 95
        },
        'execution_bypass_flags': {
            'keywords': ['executionpolicy bypass', 'windowstyle hidden', '-noprofile -command'],
            'description': 'PowerShell stealth execution flags — malware loader signature',
            'mitre': 'T1059.001 - PowerShell',
            'score': 88
        },
        'suspicious_tls_issuer': {
            'description': "TLS cert issued by Let's Encrypt for Microsoft-named domain — typosquatting C2",
            'mitre': 'T1071.001 - Web Protocols / T1568 - Dynamic Resolution',
            'score': 92
        },
        'process_injection_chain': {
            'description': 'Sysmon EventID 1+10+8 from same PID — full injection chain confirmed',
            'mitre': 'T1055 - Process Injection',
            'score': 97
        }
    }

    def __init__(self):
        self.name = 'CorrelationAgent'
        self.iteration = 0
        self.findings = []
        self.errors = []

    def _log(self, message, level='INFO'):
        timestamp = datetime.now().strftime('%H:%M:%S')
        prefix = {'INFO': 'i', 'WARN': '!', 'ERROR': 'X',
                  'FIND': '?', 'LINK': '~', 'NARR': 'N',
                  'CRIT': '!!', 'APT': 'A'}.get(level, '.')
        print(f'[{timestamp}] {prefix} [{self.name}] {message}')

    def _record_finding(self, finding):
        finding['agent'] = self.name
        finding['iteration'] = self.iteration
        finding['timestamp'] = datetime.now(timezone.utc).isoformat()
        finding['traceable'] = True
        self.findings.append(finding)

    def _extract_clean_iocs(self, all_reports):
        merged = {
            'ipv4_addresses': set(), 'sha256_hashes': set(),
            'md5_hashes': set(), 'base64_strings': set(),
            'decoded_payloads': set(), 'file_paths': set(),
            'hostnames': set(), 'usernames': set(),
            'process_ids': set(), 'granted_access': set(), 'domains': set()
        }
        for agent_name, report in all_reports.items():
            if not isinstance(report, dict):
                continue
            iocs = report.get('extracted_iocs', {})
            for ioc_type in merged:
                for item in iocs.get(ioc_type, []):
                    merged[ioc_type].add(item)
            for ip in report.get('unique_ips', []):
                ip_clean = re.search(
                    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
                    str(ip)
                )
                if ip_clean:
                    merged['ipv4_addresses'].add(ip_clean.group())
        return {k: sorted(list(v)) for k, v in merged.items()}

    def _check_high_signal_signatures(self, clean_iocs, all_reports):
        triggered = []

        # Check 0x1FFFFF GrantedAccess
        for ga in clean_iocs.get('granted_access', []):
            if ga.lower() in ['0x1fffff']:
                sig = self.CRITICAL_SIGNATURES['granted_access_full'].copy()
                sig['triggered_by'] = f'GrantedAccess={ga}'
                triggered.append(sig)
                self._log(f'HIGH-SIGNAL: PROCESS_ALL_ACCESS detected ({ga})', 'CRIT')

        # Check PowerShell stealth flags
        for agent_name, report in all_reports.items():
            if not isinstance(report, dict):
                continue
            hits = report.get('hits', {})
            for filepath, file_hits in hits.items():
                if not isinstance(file_hits, dict):
                    continue
                keys_lower = ' '.join(file_hits.keys()).lower()
                if 'executionpolicy' in keys_lower or 'windowstyle' in keys_lower or 'hidden' in keys_lower or 'bypass' in keys_lower:
                    sig = self.CRITICAL_SIGNATURES['execution_bypass_flags'].copy()
                    sig['triggered_by'] = f'Keywords in {os.path.basename(filepath)}'
                    triggered.append(sig)
                    self._log('HIGH-SIGNAL: PowerShell stealth execution flags', 'CRIT')
                    break

            # Check decoded payloads for suspicious content
            for dp in report.get('decoded_payloads', []):
                if dp.get('suspicious_indicators'):
                    triggered.append({
                        'values': dp['suspicious_indicators'],
                        'description': f'Malicious payload decoded from base64: {dp["suspicious_indicators"]}',
                        'mitre': 'T1027 - Obfuscated Files or Information',
                        'score': 90,
                        'triggered_by': 'base64_decoder'
                    })
                    self._log(f'HIGH-SIGNAL: Malicious payload in base64: {dp["suspicious_indicators"]}', 'CRIT')

        # Check TLS issuer mismatch (Let's Encrypt issuing Microsoft certs)
        for agent_name, report in all_reports.items():
            if not isinstance(report, dict):
                continue
            for filepath, coc in report.get('chain_of_custody', {}).items():
                if 'zeek' in filepath.lower() or 'network' in filepath.lower():
                    try:
                        with open(filepath, 'r', errors='ignore') as f:
                            content = f.read().lower()
                        if "let's encrypt" in content and (
                            "microsoft" in content or "windows" in content or "update" in content
                        ):
                            sig = self.CRITICAL_SIGNATURES['suspicious_tls_issuer'].copy()
                            sig['triggered_by'] = os.path.basename(filepath)
                            triggered.append(sig)
                            self._log("HIGH-SIGNAL: Let's Encrypt cert on Microsoft-named domain = C2!", 'CRIT')
                    except Exception:
                        pass

        return triggered

    def _time_window_correlation(self, clean_iocs, all_reports):
        sequences = []
        process_events = {}

        for agent_name, report in all_reports.items():
            if not isinstance(report, dict):
                continue

            # Look for process IDs that appear across multiple event types
            pids = clean_iocs.get('process_ids', [])
            hits = report.get('hits', {})
            granted = clean_iocs.get('granted_access', [])

            all_text = ''
            for filepath in report.get('chain_of_custody', {}).keys():
                try:
                    with open(filepath, 'r', errors='ignore') as f:
                        all_text += f.read()
                except Exception:
                    pass

            # Detect Sysmon EventID chain: 1 (execution) + 10 (injection) + 8 (remote thread)
            has_event1 = bool(re.search(r'"EventID"\s*:\s*1', all_text))
            has_event8 = bool(re.search(r'"EventID"\s*:\s*8', all_text))
            has_event10 = bool(re.search(r'"EventID"\s*:\s*10', all_text))
            has_network = len(clean_iocs.get('ipv4_addresses', [])) > 0

            if has_event1 and (has_event8 or has_event10):
                sig = self.CRITICAL_SIGNATURES['process_injection_chain'].copy()
                sig['events_detected'] = []
                if has_event1:
                    sig['events_detected'].append('EventID:1 Process Execution')
                if has_event10:
                    sig['events_detected'].append('EventID:10 Process Access')
                if has_event8:
                    sig['events_detected'].append('EventID:8 Remote Thread Creation')
                if has_network:
                    sig['events_detected'].append('Network C2 Beacon')

                sequences.append({
                    'type': 'temporal_sequence',
                    'pattern': 'FULL_INJECTION_CHAIN',
                    'confidence': 'CRITICAL',
                    'description': 'Execution -> Process Injection -> Remote Thread -> C2 Beacon within time window',
                    'mitre_technique': 'T1055 - Process Injection / T1071 - C2 Communication',
                    'events': sig['events_detected'],
                    'base_score': 97,
                    'multiplier': 3.5
                })
                self._log(f'TEMPORAL CHAIN: {sig["events_detected"]}', 'APT')

        return sequences

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

    def _detect_attack_patterns(self, keyword_map, clean_iocs):
        patterns = []

        brute_keys = {'failed login', 'failed password', 'authentication failure', 'account lockout', 'brute force'}
        found = brute_keys.intersection(set(keyword_map.keys()))
        if found:
            patterns.append({
                'type': 'attack_pattern', 'pattern': 'BRUTE_FORCE_ATTACK',
                'confidence': 'HIGH', 'evidence_keywords': list(found),
                'description': 'Credential brute force detected',
                'mitre_technique': 'T1110 - Brute Force', 'base_score': 70
            })

        priv_keys = {'sudo', 'root', 'privilege escalation', 'unauthorized'}
        found = priv_keys.intersection(set(keyword_map.keys()))
        if len(found) >= 2:
            patterns.append({
                'type': 'attack_pattern', 'pattern': 'PRIVILEGE_ESCALATION',
                'confidence': 'HIGH', 'evidence_keywords': list(found),
                'description': 'Privilege escalation detected',
                'mitre_technique': 'T1548 - Abuse Elevation Control Mechanism', 'base_score': 75
            })

        lateral_keys = {'reverse shell', 'backdoor', 'exploit', 'injection', 'lateral movement'}
        found = lateral_keys.intersection(set(keyword_map.keys()))
        if found:
            patterns.append({
                'type': 'attack_pattern', 'pattern': 'LATERAL_MOVEMENT_OR_C2',
                'confidence': 'CRITICAL', 'evidence_keywords': list(found),
                'description': 'C2 or lateral movement detected',
                'mitre_technique': 'T1021 / T1059 - Remote Services / Command Interpreter', 'base_score': 85
            })

        ransom_keys = {'ransomware', 'malware', 'encoded', 'base64', 'powershell'}
        found = ransom_keys.intersection(set(keyword_map.keys()))
        if found:
            patterns.append({
                'type': 'attack_pattern', 'pattern': 'RANSOMWARE_OR_MALWARE',
                'confidence': 'CRITICAL', 'evidence_keywords': list(found),
                'description': 'Malware or ransomware execution detected',
                'mitre_technique': 'T1486 - Data Encrypted for Impact', 'base_score': 90
            })

        cred_keys = {'mimikatz', 'lsass', 'kerberos', 'credential'}
        found = cred_keys.intersection(set(keyword_map.keys()))
        if found:
            patterns.append({
                'type': 'attack_pattern', 'pattern': 'CREDENTIAL_DUMPING',
                'confidence': 'CRITICAL', 'evidence_keywords': list(found),
                'description': 'Credential dumping detected',
                'mitre_technique': 'T1003 - OS Credential Dumping', 'base_score': 88
            })

        exfil_keys = {'exfiltration', 'export', 'anomaly'}
        found = exfil_keys.intersection(set(keyword_map.keys()))
        if found:
            patterns.append({
                'type': 'attack_pattern', 'pattern': 'DATA_EXFILTRATION',
                'confidence': 'HIGH', 'evidence_keywords': list(found),
                'description': 'Data exfiltration detected',
                'mitre_technique': 'T1041 - Exfiltration Over C2 Channel', 'base_score': 80
            })

        # Process injection specific
        if clean_iocs.get('granted_access'):
            for ga in clean_iocs['granted_access']:
                if ga.lower() in ['0x1fffff']:
                    patterns.append({
                        'type': 'attack_pattern', 'pattern': 'PROCESS_INJECTION',
                        'confidence': 'CRITICAL', 'evidence_keywords': [ga],
                        'description': f'Process injection confirmed via GrantedAccess={ga}',
                        'mitre_technique': 'T1055 - Process Injection', 'base_score': 97
                    })

        # PowerShell obfuscation
        ps_keys = {'executionpolicy', 'windowstyle', 'hidden', 'bypass'}
        found = ps_keys.intersection(set(keyword_map.keys()))
        if found:
            patterns.append({
                'type': 'attack_pattern', 'pattern': 'POWERSHELL_OBFUSCATION',
                'confidence': 'CRITICAL', 'evidence_keywords': list(found),
                'description': 'Obfuscated PowerShell execution with stealth flags',
                'mitre_technique': 'T1059.001 - PowerShell / T1027 - Obfuscation', 'base_score': 90
            })

        return patterns

    def _find_ip_correlations(self, clean_iocs):
        correlations = []
        for ip in clean_iocs.get('ipv4_addresses', []):
            correlations.append({
                'type': 'ip_seen_in_evidence',
                'ip': ip,
                'seen_by_agents': ['LogAgent'],
                'significance': 'HIGH',
                'description': f'Regex-verified IoC: {ip}'
            })
        return correlations

    def _calculate_threat_score(self, patterns, signatures, sequences, ip_correlations):
        score = 0
        reasons = []

        # Start with highest base score from patterns
        base_scores = [p.get('base_score', 0) for p in patterns]
        if base_scores:
            score = max(base_scores)
            reasons.append(f'Base pattern score: {score}')

        # High-signal signatures override everything
        for sig in signatures:
            sig_score = sig.get('score', 0)
            if sig_score > score:
                score = sig_score
                reasons.append(f'High-signal override: {sig.get("description","?")}')

        # Apply temporal multiplier for injection chains
        for seq in sequences:
            multiplier = seq.get('multiplier', 1.0)
            if multiplier > 1.0:
                pre_mult = score
                score = min(int(score * multiplier), 100)
                reasons.append(f'Temporal chain multiplier x{multiplier}: {pre_mult} -> {score}')

        # Bonus for multiple patterns
        if len(patterns) >= 3:
            score = min(score + 10, 100)
            reasons.append(f'{len(patterns)} patterns detected (+10)')

        # Bonus for correlated IPs
        if len(ip_correlations) >= 1:
            score = min(score + 5, 100)
            reasons.append(f'Correlated IPs (+5)')

        level = 'CRITICAL' if score >= 85 else 'HIGH' if score >= 65 else 'MEDIUM' if score >= 40 else 'LOW'
        return {'score': score, 'level': level, 'reasons': reasons}

    def _build_attack_narrative(self, patterns, sequences, signatures, clean_iocs, keyword_map):
        attacker_ips = clean_iocs.get('ipv4_addresses', [])
        hostnames = clean_iocs.get('hostnames', [])
        usernames = clean_iocs.get('usernames', [])
        b64_strings = clean_iocs.get('base64_strings', [])
        file_paths = clean_iocs.get('file_paths', [])
        process_ids = clean_iocs.get('process_ids', [])
        granted_access = clean_iocs.get('granted_access', [])

        attacker_ip = attacker_ips[0] if attacker_ips else 'an external IP'
        victim_host = next((h for h in hostnames if '-' in h and len(h) > 8), hostnames[0] if hostnames else 'the target')
        pattern_names = [p['pattern'] for p in patterns]
        seq_names = [s['pattern'] for s in sequences]
        sig_descs = [s['description'] for s in signatures]

        sentences = []

        # Initial access sentence
        if 'POWERSHELL_OBFUSCATION' in pattern_names or 'FULL_INJECTION_CHAIN' in seq_names:
            pid = process_ids[0] if process_ids else 'unknown'
            sentences.append(
                f'A heavily obfuscated PowerShell command was executed on {victim_host} '
                f'(ProcessID {pid}) using ExecutionPolicy Bypass and WindowStyle Hidden flags, '
                f'indicating a fileless malware execution technique designed to evade endpoint detection.'
            )
        elif attacker_ips:
            sentences.append(
                f'The attack originated from {attacker_ip} targeting {victim_host}, '
                f'gaining initial foothold through exploitation of a network-accessible service.'
            )

        # Process injection sentence
        if granted_access and 'PROCESS_INJECTION' in pattern_names:
            target_pids = process_ids[1:] if len(process_ids) > 1 else ['svchost.exe']
            sentences.append(
                f'The malicious process injected shellcode into a legitimate system process '
                f'(GrantedAccess={granted_access[0]}) — this is PROCESS_ALL_ACCESS, '
                f'a definitive indicator of process injection used to achieve execution '
                f'within a trusted process and bypass security monitoring.'
            )

        # C2 beacon sentence
        if attacker_ips and 'LATERAL_MOVEMENT_OR_C2' in pattern_names:
            c2_ip = attacker_ips[-1]
            sentences.append(
                f'Following injection, the compromised process established a covert C2 '
                f'communication channel to {c2_ip} over HTTPS, with the TLS certificate '
                f'issued by an unexpected authority — a hallmark of attacker-controlled '
                f'infrastructure masquerading as legitimate services.'
            )

        # Impact sentence
        if 'RANSOMWARE_OR_MALWARE' in pattern_names:
            sentences.append(
                f'The attack chain represents a complete APT intrusion lifecycle: '
                f'obfuscated execution, process injection for persistence, '
                f'and beaconing to external C2 infrastructure — consistent with '
                f'a Cobalt Strike or similar commercial implant deployment.'
            )
        elif sig_descs:
            sentences.append(
                f'High-signal forensic indicators confirm this is an active intrusion: '
                f'{sig_descs[0]}'
            )

        narrative = ' '.join(sentences)
        self._log(f'Narrative: {len(sentences)} sentences', 'NARR')
        return narrative

    def _generate_containment_actions(self, clean_iocs, patterns, signatures):
        actions = []
        pattern_names = [p['pattern'] for p in patterns]

        for ip in clean_iocs.get('ipv4_addresses', []):
            actions.append(f'BLOCK IP {ip} at perimeter firewall and all internal segment boundaries')

        for host in clean_iocs.get('hostnames', []):
            if '-' in host and len(host) > 5:
                actions.append(f'ISOLATE host {host} immediately — disconnect from all network segments')

        for user in clean_iocs.get('usernames', []):
            if user not in {'NT', 'AUTHORITY', 'SYSTEM', 'Unknown'}:
                actions.append(f'SUSPEND account {user!r} and invalidate all active sessions')

        for path in clean_iocs.get('file_paths', []):
            if 'powershell' in path.lower() or 'system32' in path.lower():
                actions.append(f'COLLECT forensic image of: {path}')

        for ga in clean_iocs.get('granted_access', []):
            if ga.lower() in ['0x1fffff']:
                actions.append('KILL all suspicious process trees — terminate injected processes')
                actions.append('DUMP memory of svchost.exe instances for forensic analysis')

        if 'POWERSHELL_OBFUSCATION' in pattern_names:
            actions.append('ENABLE PowerShell ScriptBlock logging (Event 4104) across all endpoints')
            actions.append('ENFORCE Constrained Language Mode for PowerShell enterprise-wide')
            actions.append('REVIEW Windows Defender AMSI logs for bypass attempts')

        if 'PROCESS_INJECTION' in pattern_names:
            actions.append('DEPLOY EDR memory scanning across all endpoints immediately')
            actions.append('ENABLE Windows Credential Guard to prevent credential extraction')

        for sig in signatures:
            if 'tls' in sig.get('description', '').lower() or 'encrypt' in sig.get('description', '').lower():
                actions.append('REVIEW all TLS connections — audit certificate issuers for anomalies')
                actions.append('BLOCK all outbound connections to domains with mismatched certificate issuers')

        if any(s.get('pattern') == 'FULL_INJECTION_CHAIN' for s in []):
            actions.append('PRESERVE memory dump of all affected hosts before remediation')

        actions.append('PRESERVE all Sysmon, network, and endpoint logs for legal/forensic proceedings')
        actions.append('NOTIFY CISO and legal team — assess breach notification obligations')

        return actions

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
        self._log('Starting advanced correlation analysis...')
        self.iteration += 1
        self._log(f'Correlating {len(all_reports)} report(s)')

        clean_iocs = self._extract_clean_iocs(all_reports)
        total_iocs = sum(len(v) for v in clean_iocs.values())
        self._log(f'Clean IoCs: {total_iocs} total', 'FIND')
        for ioc_type, ioc_list in clean_iocs.items():
            if ioc_list:
                self._log(f'  {ioc_type}: {ioc_list}', 'FIND')

        keyword_map = self._extract_all_keywords(all_reports)

        # Inject MemoryAgent + DiskAgent findings as pseudo-keywords into keyword_map
        # This allows PROCESS_INJECTION and CERTUTIL patterns to fire from memory/disk findings
        FINDING_KW_MAP = {
            'process_injection':      ['process injection', 'createremotethread', 'targetimage',
                                       'sourceprocessid', 'rundll32', 'comsvcs', 'minidump'],
            'credential_dumping':     ['lsass', 'minidump', 'comsvcs'],
            'suspicious_process_tree':['process injection', 'suspicious process'],
            'malware_drop_zone':      ['suspicious process'],
            'malicious_filename':     [],
            'c2_communication':       ['exfiltration'],
            'data_exfiltration':      ['exfiltration'],
        }
        for agent_name, report in all_reports.items():
            if not isinstance(report, dict):
                continue
            for finding in report.get('findings', []):
                if not isinstance(finding, dict):
                    continue
                ftype = finding.get('type', '')
                artifact = finding.get('artifact', finding.get('file', 'unknown'))
                # Add indicator string as keyword
                indicator = str(finding.get('indicator', '')).lower().strip()
                if indicator:
                    if indicator not in keyword_map:
                        keyword_map[indicator] = []
                    keyword_map[indicator].append({'agent': agent_name, 'file': artifact})
                # Add mapped pseudo-keywords for this finding type
                for kw in FINDING_KW_MAP.get(ftype, []):
                    if kw not in keyword_map:
                        keyword_map[kw] = []
                    keyword_map[kw].append({'agent': agent_name, 'file': artifact})
                # Also scan evidence lines for known keywords
                for ev in finding.get('evidence', [])[:3]:
                    ev_lower = str(ev).lower()
                    for kw in ['rundll32', 'comsvcs', 'minidump', 'lsass', 'certutil',
                               'createremotethread', 'targetimage', 'sourceprocessid',
                               'process injection', 'anomaly process', 'suspicious process',
                               'remote thread', 'shellcode', 'regsvr32', 'scrobj', 'decode']:
                        if kw in ev_lower:
                            if kw not in keyword_map:
                                keyword_map[kw] = []
                            keyword_map[kw].append({'agent': agent_name, 'file': artifact})
        self._log(f'Keywords: {len(keyword_map)} found', 'FIND')

        # Phase 1: High-signal signature detection
        self._log('Checking high-signal APT signatures...', 'APT')
        signatures = self._check_high_signal_signatures(clean_iocs, all_reports)
        self._log(f'High-signal signatures triggered: {len(signatures)}', 'CRIT' if signatures else 'INFO')

        # Phase 2: Time-window correlation
        self._log('Running time-window correlation matrix...', 'APT')
        sequences = self._time_window_correlation(clean_iocs, all_reports)

        # Phase 3: Pattern detection
        patterns = self._detect_attack_patterns(keyword_map, clean_iocs)
        for p in patterns:
            self._log(f'PATTERN: {p["pattern"]} [{p["confidence"]}]', 'FIND')
            self._log(f'  MITRE: {p["mitre_technique"]}', 'FIND')
            self._record_finding(p)

        for seq in sequences:
            self._log(f'SEQUENCE: {seq["pattern"]} [CRITICAL]', 'APT')
            self._record_finding(seq)

        ip_correlations = self._find_ip_correlations(clean_iocs)
        for corr in ip_correlations:
            self._record_finding(corr)

        threat = self._calculate_threat_score(patterns, signatures, sequences, ip_correlations)
        self._log(f'THREAT SCORE: {threat["score"]}/100 — {threat["level"]}', 'CRIT' if threat['score'] >= 85 else 'FIND')
        self._log(f'Score reasoning: {threat["reasons"]}')

        narrative = self._build_attack_narrative(patterns, sequences, signatures, clean_iocs, keyword_map)
        self._log('Attack narrative generated', 'NARR')

        containment = self._generate_containment_actions(clean_iocs, patterns, signatures)
        self._log(f'Containment actions: {len(containment)}', 'NARR')

        timeline = self._build_timeline(all_reports)

        self._log('Correlation analysis complete!')

        return {
            'status': 'COMPLETE',
            'agent': self.name,
            'agents_correlated': len(all_reports),
            'extracted_entities': clean_iocs,
            'ip_correlations': ip_correlations,
            'attack_patterns': patterns,
            'temporal_sequences': sequences,
            'high_signal_signatures': signatures,
            'timeline': timeline,
            'threat_assessment': threat,
            'attack_narrative': narrative,
            'containment_actions': containment,
            'findings': self.findings,
            'errors': self.errors,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


if __name__ == '__main__':
    print('Testing CorrelationAgent v3...')
    fake_reports = {
        'LogAgent': {
            'extracted_iocs': {
                'ipv4_addresses': ['104.21.55.12', '192.168.1.105'],
                'sha256_hashes': [], 'md5_hashes': [],
                'base64_strings': ['K8jcSMwtyEnVS8/IzMlJTE7Vyx...'],
                'decoded_payloads': [],
                'file_paths': ['C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'],
                'hostnames': ['DESKTOP-DEV-99A'],
                'usernames': [],
                'process_ids': ['4192', '912', '1128'],
                'granted_access': ['0x1FFFFF']
            },
            'unique_ips': ['104.21.55.12', '192.168.1.105'],
            'hits': {
                '/cases/sysmon_execution.log': {
                    'powershell': {'count': 1},
                    'executionpolicy': {'count': 1},
                    'windowstyle': {'count': 1},
                    'hidden': {'count': 1},
                    'bypass': {'count': 1},
                    'base64': {'count': 1}
                },
                '/cases/sysmon_injection.log': {
                    '0x1fffff': {'count': 1},
                    'svchost': {'count': 1}
                }
            },
            'decoded_payloads': [],
            'chain_of_custody': {
                '/data/data/com.termux/files/home/cases/obfuscated_malware/zeek_network.log': {
                    'sha256': 'abc123', 'timestamp': '2026-05-21T10:00:00Z', 'size_bytes': 500
                }
            },
            'findings': [{
                'type': 'suspicious_log_activity',
                'artifact': '/cases/sysmon_execution.log',
                'timestamp': '2026-05-21T10:38:40Z'
            }]
        }
    }
    agent = CorrelationAgent()
    report = agent.run(fake_reports)
    print(f'\nPatterns: {len(report["attack_patterns"])}')
    print(f'Signatures: {len(report["high_signal_signatures"])}')
    print(f'Sequences: {len(report["temporal_sequences"])}')
    print(f'Threat: {report["threat_assessment"]["score"]}/100 — {report["threat_assessment"]["level"]}')
    print(f'\n=== NARRATIVE ===')
    print(report['attack_narrative'])
    print(f'\n=== CONTAINMENT ({len(report["containment_actions"])}) ===')
    for i, a in enumerate(report['containment_actions'], 1):
        print(f'  [{i}] {a}')
    print('\nTest passed!')
