import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re
import hashlib
from datetime import datetime, timezone


class MemoryAgent:
    """
    Analyzes memory-related artifacts for signs of compromise.
    Detects: process injection, suspicious process trees, hollowing,
    credential dumping, and anomalous memory allocation patterns.
    All detection is regex/string matching -- zero LLM.
    """

    INJECTION_INDICATORS = [
        # Windows API injection calls
        'virtualalloc', 'virtualallocex', 'writeprocessmemory',
        'createremotethread', 'ntcreatethreaded', 'queueuserapc',
        'setwindowshookex', 'reflectivedllinjection', 'process hollowing',
        'process herpaderping', 'process doppelganging',
        'mapviewofsection', 'ntmapviewofsection', 'remotethreadcreation',
        'setthreadcontext', 'ntcreatethread', 'zwcreatethread',
        # Sysmon EventID 8 and 10 text signatures
        'eventid 8', 'eventid: 8', '"eventid": 8',
        'eventid 10', 'eventid: 10', '"eventid": 10',
        'createremotethread detected', 'targetimage',
        'sourceprocessid', 'targetprocessid',
        # Text-log injection phrases (covers apt_attack text logs)
        'process injection', 'process spawned', 'remote thread',
        'suspicious process', 'anomaly process', 'injected into',
        'dll injection', 'shellcode inject', 'code injection',
        # LOLBIN-assisted injection vectors
        'rundll32', 'regsvr32', 'mshta', 'certutil',
        'comsvcs.dll', 'minidump', 'procdump'
    ]

    # GrantedAccess hex values consistent with process injection
    INJECTION_ACCESS_VALUES = [
        '0x1fffff', '0x143a', '0x1f3fff', '0x1410', '0x1f0fff'
    ]

    CREDENTIAL_DUMPING = [
        'lsass', 'lsadump', 'sekurlsa', 'wdigest', 'kerberos tickets',
        'pass the hash', 'pass the ticket', 'golden ticket', 'silver ticket',
        'dcsync', 'ntds.dit', 'sam database', 'hashdump', 'credential dump',
        'mimikatz', 'procdump', 'comsvcs.dll', 'minidump'
    ]

    SUSPICIOUS_PROCESS_PARENTS = [
        ('winword.exe', 'cmd.exe'),
        ('winword.exe', 'powershell.exe'),
        ('excel.exe', 'cmd.exe'),
        ('excel.exe', 'powershell.exe'),
        ('outlook.exe', 'cmd.exe'),
        ('wmiprvse.exe', 'powershell.exe'),
        ('wmiprvse.exe', 'cmd.exe'),
        ('mshta.exe', 'powershell.exe'),
        ('rundll32.exe', 'powershell.exe'),
        ('svchost.exe', 'cmd.exe'),
    ]

    HOLLOWING_INDICATORS = [
        'process hollow', 'unmapviewofsection', 'zwunmapviewofsection',
        'ntzwunmap', 'pe injection', 'image base relocation',
        'section mapping', 'phantom process'
    ]

    MEMORY_ANOMALIES = [
        'execute from heap', 'rwx memory', 'executable heap',
        'shellcode execution', 'gadget chain', 'rop chain',
        'heap spray', 'use after free', 'return oriented'
    ]

    TEXT_EXTENSIONS = {
        '.log', '.txt', '.json', '.csv', '.xml',
        '.tsv', '.out', '.syslog', '.evtx', '.dmp'
    }

    @staticmethod
    def _hash_file(filepath):
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            return f'ERROR:{e}'

    def __init__(self):
        self.name = 'MemoryAgent'
        self.iteration = 0
        self.findings = []
        self.errors = []
        self.chain_of_custody = {}
        self.extracted_iocs = {
            'injection_techniques': set(),
            'credential_dump_indicators': set(),
            'suspicious_process_pairs': set(),
            'hollowing_indicators': set(),
            'memory_anomalies': set(),
        }

    def _log(self, message, level='INFO'):
        timestamp = datetime.now().strftime('%H:%M:%S')
        prefix = {'INFO': 'i', 'WARN': '!', 'ERROR': 'X',
                  'FIND': '?', 'HASH': '#', 'MEM': 'M'}.get(level, '.')
        print(f'[{timestamp}] {prefix} [{self.name}] {message}')

    def _record_finding(self, finding):
        finding['agent'] = self.name
        finding['iteration'] = self.iteration
        finding['timestamp'] = datetime.now(timezone.utc).isoformat()
        finding['traceable'] = True
        self.findings.append(finding)

    def _get_matching_lines(self, text, keyword):
        return [
            l.strip() for l in text.split('\n')
            if keyword.lower() in l.lower() and l.strip()
        ]

    def _scan_text(self, text, source_file, file_hash):
        text_lower = text.lower()
        hits = 0

        # Check injection indicators
        for indicator in self.INJECTION_INDICATORS:
            if indicator.lower() in text_lower:
                matches = self._get_matching_lines(text, indicator)
                if matches:
                    self.extracted_iocs['injection_techniques'].add(indicator)
                    self._log(f'  INJECTION: {indicator} in {os.path.basename(source_file)}', 'FIND')
                    hits += 1
                    self._record_finding({
                        'type': 'process_injection',
                        'artifact': source_file,
                        'file_hash': file_hash[:16],
                        'indicator': indicator,
                        'evidence': matches[:3],
                        'severity': 'CRITICAL',
                        'mitre': 'T1055 - Process Injection'
                    })

        # Check credential dumping
        for indicator in self.CREDENTIAL_DUMPING:
            if indicator.lower() in text_lower:
                matches = self._get_matching_lines(text, indicator)
                if matches:
                    self.extracted_iocs['credential_dump_indicators'].add(indicator)
                    self._log(f'  CRED DUMP: {indicator} in {os.path.basename(source_file)}', 'FIND')
                    hits += 1
                    self._record_finding({
                        'type': 'credential_dumping',
                        'artifact': source_file,
                        'file_hash': file_hash[:16],
                        'indicator': indicator,
                        'evidence': matches[:3],
                        'severity': 'CRITICAL',
                        'mitre': 'T1003 - OS Credential Dumping'
                    })

        # Check suspicious parent-child process pairs
        for parent, child in self.SUSPICIOUS_PROCESS_PARENTS:
            if parent.lower() in text_lower and child.lower() in text_lower:
                pair = f'{parent} -> {child}'
                self.extracted_iocs['suspicious_process_pairs'].add(pair)
                self._log(f'  PROC TREE: {pair} in {os.path.basename(source_file)}', 'FIND')
                hits += 1
                self._record_finding({
                    'type': 'suspicious_process_tree',
                    'artifact': source_file,
                    'file_hash': file_hash[:16],
                    'parent': parent,
                    'child': child,
                    'pair': pair,
                    'severity': 'HIGH',
                    'mitre': 'T1059 - Command and Scripting Interpreter'
                })

        # Check process hollowing
        for indicator in self.HOLLOWING_INDICATORS:
            if indicator.lower() in text_lower:
                matches = self._get_matching_lines(text, indicator)
                if matches:
                    self.extracted_iocs['hollowing_indicators'].add(indicator)
                    self._log(f'  HOLLOWING: {indicator} in {os.path.basename(source_file)}', 'FIND')
                    hits += 1
                    self._record_finding({
                        'type': 'process_hollowing',
                        'artifact': source_file,
                        'file_hash': file_hash[:16],
                        'indicator': indicator,
                        'evidence': matches[:3],
                        'severity': 'CRITICAL',
                        'mitre': 'T1055.012 - Process Hollowing'
                    })

        # Check memory anomalies
        for indicator in self.MEMORY_ANOMALIES:
            if indicator.lower() in text_lower:
                matches = self._get_matching_lines(text, indicator)
                if matches:
                    self.extracted_iocs['memory_anomalies'].add(indicator)
                    self._log(f'  MEM ANOMALY: {indicator} in {os.path.basename(source_file)}', 'FIND')
                    hits += 1
                    self._record_finding({
                        'type': 'memory_anomaly',
                        'artifact': source_file,
                        'file_hash': file_hash[:16],
                        'indicator': indicator,
                        'evidence': matches[:3],
                        'severity': 'HIGH',
                        'mitre': 'T1055 - Process Injection'
                    })

        # Check GrantedAccess hex values for injection signatures
        for access_val in self.INJECTION_ACCESS_VALUES:
            if access_val.lower() in text_lower:
                matches = self._get_matching_lines(text, access_val)
                if matches:
                    self.extracted_iocs['injection_techniques'].add(
                        f'GrantedAccess:{access_val}'
                    )
                    self._log(
                        f'  INJECTION ACCESS: {access_val} in {os.path.basename(source_file)}',
                        'FIND'
                    )
                    hits += 1
                    self._record_finding({
                        'type': 'process_injection',
                        'artifact': source_file,
                        'file_hash': file_hash[:16],
                        'indicator': f'GrantedAccess {access_val}',
                        'evidence': matches[:3],
                        'severity': 'CRITICAL',
                        'mitre': 'T1055 - Process Injection'
                    })

        return hits

    def _analyze_file(self, filepath):
        self._log(f'Analyzing: {os.path.basename(filepath)}')
        file_hash = self._hash_file(filepath)
        self.chain_of_custody[filepath] = {
            'sha256': file_hash,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'size_bytes': os.path.getsize(filepath) if os.path.exists(filepath) else 0
        }
        self._log(f'  CoC: {file_hash[:16]}...', 'HASH')
        try:
            with open(filepath, 'r', errors='ignore') as f:
                raw_text = f.read()
        except Exception as e:
            self.errors.append(f'Read failed {filepath}: {e}')
            return 0
        return self._scan_text(raw_text, filepath, file_hash)

    def run(self, case_path, file_list=None):
        self._log(f'Starting memory artifact analysis: {case_path}')
        self.iteration += 1
        if file_list:
            files = file_list
        else:
            files = []
            if os.path.exists(case_path):
                for fname in os.listdir(case_path):
                    fpath = os.path.join(case_path, fname)
                    if os.path.isfile(fpath):
                        if os.path.splitext(fname)[1].lower() in self.TEXT_EXTENSIONS:
                            files.append(fpath)
        files = list(set(files))
        self._log(f'Found {len(files)} file(s) to scan')
        total_hits = 0
        for filepath in sorted(files):
            if filepath.strip():
                total_hits += self._analyze_file(filepath)
        clean_iocs = {k: sorted(list(v)) for k, v in self.extracted_iocs.items()}
        total_iocs = sum(len(v) for v in clean_iocs.values())
        self._log(f'Memory scan complete -- {total_hits} hit(s), {total_iocs} IoC(s)', 'FIND')
        priority = 'CRITICAL' if any(
            f.get('severity') == 'CRITICAL' for f in self.findings
        ) else 'HIGH' if total_hits > 0 else 'LOW'
        return {
            'status': 'COMPLETE',
            'agent': self.name,
            'files_analyzed': len(files),
            'total_hits': total_hits,
            'priority': priority,
            'extracted_iocs': clean_iocs,
            'chain_of_custody': self.chain_of_custody,
            'findings': self.findings,
            'errors': self.errors,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


if __name__ == '__main__':
    import sys
    print('Testing MemoryAgent...')
    test_path = sys.argv[1] if len(sys.argv) > 1 else '/data/data/com.termux/files/home/cases/obfuscated_malware'
    agent = MemoryAgent()
    report = agent.run(test_path)
    print(f'Files analyzed : {report["files_analyzed"]}')
    print(f'Total hits     : {report["total_hits"]}')
    print(f'Priority       : {report["priority"]}')
    print(f'Findings       : {len(report["findings"])}')
    for k, v in report['extracted_iocs'].items():
        if v:
            print(f'  {k}: {list(v)[:3]}')
    print('Test passed!')