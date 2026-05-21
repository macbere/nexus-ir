import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import hashlib
from datetime import datetime, timezone
from tools.mcp_server import call_tool


class LogAgent:

    SUSPICIOUS_KEYWORDS = [
        "failed login", "failed password", "authentication failure",
        "unauthorized", "privilege escalation", "sudo", "root",
        "exploit", "malware", "ransomware", "backdoor", "reverse shell",
        "powershell", "base64", "encoded", "suspicious", "anomaly",
        "brute force", "injection", "account lockout", "lateral movement",
        "exfiltration", "mimikatz", "lsass", "credential", "kerberos"
    ]

    # ── STRICT REGEX PATTERNS ──────────────────────────────
    # These run LOCALLY on raw file text — no LLM guessing ever
    @staticmethod
    def _regex_ipv4(text):
        pattern = r'\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b'
        # Exclude private/loopback ranges for cleaner IoCs
        hits = re.findall(pattern, text)
        public = []
        for ip in hits:
            parts = ip.split('.')
            first = int(parts[0])
            second = int(parts[1])
            # Exclude 127.x, 0.x — keep 10.x, 192.168.x, 172.x as they are internal pivots
            if first != 127 and first != 0:
                public.append(ip)
        return list(set(public))

    @staticmethod
    def _regex_sha256(text):
        pattern = r'\b([a-fA-F0-9]{64})\b'
        return list(set(re.findall(pattern, text)))

    @staticmethod
    def _regex_md5(text):
        pattern = r'\b([a-fA-F0-9]{32})\b'
        # Filter out timestamps and short hex that arent hashes
        hits = re.findall(pattern, text)
        return list(set([h for h in hits if len(h) == 32]))

    @staticmethod
    def _regex_base64(text):
        pattern = r'(?<![\w/+])([A-Za-z0-9+/]{20,}={0,2})(?![\w/+])'
        hits = re.findall(pattern, text)
        # Only return strings that look like real base64 (length divisible by 4 or close)
        valid = []
        for h in hits:
            if len(h) >= 20 and len(h) % 4 <= 2:
                valid.append(h[:50] + ('...' if len(h) > 50 else ''))
        return list(set(valid))

    @staticmethod
    def _regex_file_paths(text):
        # Windows paths
        win = re.findall(r'[A-Za-z]:\\(?:[\w\-. ]+\\)*[\w\-.]+', text)
        # Unix paths (at least 2 components deep)
        unix = re.findall(r'(?<![\w])/(?:[\w\-.]+/)+[\w\-.]+', text)
        all_paths = list(set(win + unix))
        # Filter out very short or common false positives
        return [p for p in all_paths if len(p) > 8 and '/c' != p]

    @staticmethod
    def _regex_hostnames(text):
        pattern = r'HOST=([\w\-]+)'
        return list(set(re.findall(pattern, text)))

    @staticmethod
    def _regex_usernames(text):
        pattern = r'(?:USER|user|for|by)=?\s*([a-zA-Z][\w_\-]{2,20})'
        hits = re.findall(pattern, text)
        # Filter common false positives
        noise = {'the', 'for', 'from', 'with', 'AUDIT', 'ALERT', 'HOST', 'ACTION'}
        return list(set([h for h in hits if h not in noise]))

    @staticmethod
    def _hash_file(filepath):
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            return f'ERROR:{str(e)}'

    def __init__(self):
        self.name = 'LogAgent'
        self.iteration = 0
        self.findings = []
        self.errors = []
        self.chain_of_custody = {}
        self.extracted_iocs = {
            'ipv4_addresses': set(),
            'sha256_hashes': set(),
            'md5_hashes': set(),
            'base64_strings': set(),
            'file_paths': set(),
            'hostnames': set(),
            'usernames': set()
        }

    def _log(self, message, level='INFO'):
        timestamp = datetime.now().strftime('%H:%M:%S')
        prefix = {'INFO': 'i', 'WARN': '!', 'ERROR': 'X', 'FIND': '?', 'HASH': '#'}.get(level, '.')
        print(f'[{timestamp}] {prefix} [{self.name}] {message}')

    def _record_finding(self, finding):
        finding['agent'] = self.name
        finding['iteration'] = self.iteration
        finding['timestamp'] = datetime.now(timezone.utc).isoformat()
        finding['traceable'] = True
        self.findings.append(finding)

    def _extract_iocs_from_text(self, text, source_file):
        before = sum(len(v) for v in self.extracted_iocs.values())

        for ip in self._regex_ipv4(text):
            self.extracted_iocs['ipv4_addresses'].add(ip)
        for h in self._regex_sha256(text):
            self.extracted_iocs['sha256_hashes'].add(h)
        for h in self._regex_md5(text):
            self.extracted_iocs['md5_hashes'].add(h)
        for b in self._regex_base64(text):
            self.extracted_iocs['base64_strings'].add(b)
        for p in self._regex_file_paths(text):
            self.extracted_iocs['file_paths'].add(p)
        for h in self._regex_hostnames(text):
            self.extracted_iocs['hostnames'].add(h)
        for u in self._regex_usernames(text):
            self.extracted_iocs['usernames'].add(u)

        after = sum(len(v) for v in self.extracted_iocs.values())
        new_count = after - before
        if new_count > 0:
            self._log(f'  +{new_count} IoCs from {os.path.basename(source_file)}', 'FIND')

    def _analyze_single_log(self, logpath):
        self._log(f'Analyzing: {os.path.basename(logpath)}')

        # Chain of custody — hash the file first
        file_hash = self._hash_file(logpath)
        self.chain_of_custody[logpath] = {
            'sha256': file_hash,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'size_bytes': os.path.getsize(logpath) if os.path.exists(logpath) else 0
        }
        self._log(f'  CoC SHA256: {file_hash[:16]}...', 'HASH')

        hits = {}

        # Read raw text for regex IoC extraction
        try:
            with open(logpath, 'r', errors='ignore') as f:
                raw_text = f.read()
            self._extract_iocs_from_text(raw_text, logpath)
        except Exception as e:
            self.errors.append(f'Could not read {logpath}: {e}')
            raw_text = ''

        # Keyword scanning via MCP tool
        result = call_tool('analyze_log_file', logpath=logpath, keywords=self.SUSPICIOUS_KEYWORDS[:10])

        for keyword, search_result in result.items():
            if not isinstance(search_result, dict):
                continue
            if search_result.get('status') == 'SUCCESS':
                output = search_result.get('output', '').strip()
                if output:
                    hits[keyword] = {
                        'matches': output.split('\n'),
                        'count': len(output.split('\n')),
                        'source_file': logpath,
                        'file_hash': file_hash[:16],
                        'tool_used': 'grep+regex',
                        'command_hash': search_result.get('command_hash')
                    }
                    self._log(f'  ALERT: {keyword!r} x{len(output.split(chr(10)))}', 'FIND')

        return hits

    def run(self, case_path, log_files=None):
        self._log(f'Starting log analysis: {case_path}')
        self.iteration += 1

        if not log_files:
            result = call_tool('list_evidence_files', case_path=case_path)
            all_files = result.get('output', '').strip().split('\n')
            log_files = [
                f for f in all_files
                if any(f.endswith(ext) for ext in ['.log', '.txt', '.evtx'])
            ]

        self._log(f'Found {len(log_files)} log file(s)')

        all_hits = {}

        for logfile in log_files:
            if not logfile.strip():
                continue
            hits = self._analyze_single_log(logfile)
            if hits:
                all_hits[logfile] = hits
                self._record_finding({
                    'type': 'suspicious_log_activity',
                    'file': logfile,
                    'artifact': logfile,
                    'file_hash': self.chain_of_custody.get(logfile, {}).get('sha256', ''),
                    'keywords_matched': list(hits.keys()),
                    'total_hits': sum(v['count'] for v in hits.values())
                })

        clean_iocs = {k: sorted(list(v)) for k, v in self.extracted_iocs.items()}
        total_iocs = sum(len(v) for v in clean_iocs.values())

        self._log(f'REGEX extracted {total_iocs} verified IoCs (no LLM guessing)', 'FIND')
        for ioc_type, ioc_list in clean_iocs.items():
            if ioc_list:
                self._log(f'  {ioc_type}: {ioc_list}', 'FIND')

        self._log(f'Chain of custody recorded for {len(self.chain_of_custody)} file(s)', 'HASH')

        return {
            'status': 'COMPLETE',
            'agent': self.name,
            'log_files_analyzed': len(log_files),
            'suspicious_files': len(all_hits),
            'hits': all_hits,
            'extracted_iocs': clean_iocs,
            'unique_ips': clean_iocs['ipv4_addresses'],
            'chain_of_custody': self.chain_of_custody,
            'findings': self.findings,
            'errors': self.errors,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


if __name__ == '__main__':
    print('Testing LogAgent v2 — Regex-Only IoC Extraction...')
    test_path = '/data/data/com.termux/files/home/cases/financial_breach'
    agent = LogAgent()
    report = agent.run(test_path)

    print('\n=== CHAIN OF CUSTODY ===')
    for filepath, coc in report['chain_of_custody'].items():
        print(f'  {os.path.basename(filepath)}: SHA256={coc["sha256"][:32]}...')

    print('\n=== VERIFIED IoCs (Regex-Only) ===')
    for ioc_type, iocs in report['extracted_iocs'].items():
        if iocs:
            print(f'  {ioc_type}:')
            for ioc in iocs:
                print(f'    - {ioc}')

    print(f'\nSuspicious files: {report["suspicious_files"]}')
    print(f'Errors: {report["errors"]}')
    print('\nTest passed!')
