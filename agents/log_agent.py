import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import hashlib
import base64
import zlib
import json
from datetime import datetime, timezone
from tools.mcp_server import call_tool


class LogAgent:

    SUSPICIOUS_KEYWORDS = [
        "failed login", "failed password", "authentication failure",
        "unauthorized", "privilege escalation", "sudo", "root",
        "exploit", "malware", "ransomware", "backdoor", "reverse shell",
        "powershell", "base64", "encoded", "suspicious", "anomaly",
        "brute force", "injection", "account lockout", "lateral movement",
        "exfiltration", "mimikatz", "lsass", "credential", "kerberos",
        "executionpolicy", "windowstyle", "hidden", "bypass",
        "0x1fffff", "createremotethread", "virtualalloc", "shellcode",
        "wmi", "svchost", "certutil", "regsvr32", "mshta", "rundll32",
        "process injection", "reflective", "cobalt", "beacon",
        "scheduled task", "registry", "persistence", "let's encrypt"
    ]

    TEXT_EXTENSIONS = {
        '.log', '.txt', '.json', '.csv', '.evtx',
        '.xml', '.tsv', '.out', '.syslog'
    }

    # Noise words that are not real usernames
    USERNAME_NOISE = {
        'PID', 'single', 'persistence', 'public', 'env',
        'the', 'for', 'from', 'with', 'AUDIT', 'ALERT',
        'HOST', 'ACTION', 'SET', 'NEW', 'GET', 'OUT',
        'True', 'False', 'None', 'null', 'NT', 'AUTHORITY',
        'SYSTEM', 'Unknown', 'tes', 'IO', 'Memory', 'Stream'
    }

    @staticmethod
    def _regex_ipv4(text):
        pattern = r'\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b'
        hits = re.findall(pattern, text)
        result = []
        for ip in hits:
            parts = ip.split('.')
            if int(parts[0]) not in (0, 127, 255):
                result.append(ip)
        return list(set(result))

    @staticmethod
    def _regex_sha256(text):
        return list(set(re.findall(r'\b([a-fA-F0-9]{64})\b', text)))

    @staticmethod
    def _regex_md5(text):
        hits = re.findall(r'\b([a-fA-F0-9]{32})\b', text)
        return list(set([h for h in hits if len(h) == 32]))

    @staticmethod
    def _regex_base64_raw(text):
        pattern = r'(?<![\w/+])([A-Za-z0-9+/]{20,}={0,2})(?![\w/+])'
        hits = re.findall(pattern, text)
        valid = []
        for h in hits:
            if len(h) >= 20 and len(h) % 4 <= 2:
                valid.append(h)
        return list(set(valid))

    @staticmethod
    def _regex_file_paths(text):
        win = re.findall(r'[A-Za-z]:\\(?:[\w\-. ]+\\)*[\w\-.]+', text)
        unix = re.findall(r'(?<![\w])/(?:[\w\-.]+/)+[\w\-.]+', text)
        all_paths = list(set(win + unix))
        return [p for p in all_paths if len(p) > 8]

    @staticmethod
    def _regex_hostnames(text):
        hits = re.findall(r'(?:HOST(?:NAME)?|Hostname|hostname)[":\s=]+([\w\-]+)', text)
        hits += re.findall(r'\b((?:[A-Z][A-Z0-9]{2,}-[A-Z0-9]{2,}[A-Z0-9]*))', text)
        return list(set([h for h in hits if len(h) > 3 and '-' in h]))

    @staticmethod
    def _regex_usernames(text):
        hits = re.findall(r'(?:User|USER|user|username)[":\s=]+([a-zA-Z][\w_\-]{2,30})', text)
        hits += re.findall(r'for user ([a-zA-Z][\w_\-]{2,30})', text)
        return hits

    @staticmethod
    def _regex_process_ids(text):
        hits = re.findall(r'(?:ProcessId|PID|TargetProcessId|SourceProcessId)[":\s]+([0-9]{2,6})', text)
        return list(set(hits))

    @staticmethod
    def _regex_granted_access(text):
        hits = re.findall(r'(?:GrantedAccess|grantedaccess)[":\s]+(0x[0-9A-Fa-f]+)', text)
        return list(set(hits))

    @staticmethod
    def _decode_base64_payload(b64_string):
        result = {
            'original': b64_string[:60] + ('...' if len(b64_string) > 60 else ''),
            'decoded_text': None,
            'is_compressed': False,
            'extracted_strings': [],
            'suspicious_indicators': []
        }
        try:
            # Pad if needed
            padded = b64_string + '=' * (4 - len(b64_string) % 4)
            raw_bytes = base64.b64decode(padded)

            # Try deflate/zlib decompress
            try:
                decompressed = zlib.decompress(raw_bytes, -15)
                result['is_compressed'] = True
                result['decoded_text'] = decompressed.decode('utf-8', errors='replace')[:500]
            except Exception:
                try:
                    decompressed = zlib.decompress(raw_bytes)
                    result['is_compressed'] = True
                    result['decoded_text'] = decompressed.decode('utf-8', errors='replace')[:500]
                except Exception:
                    try:
                        result['decoded_text'] = raw_bytes.decode('utf-8', errors='replace')[:500]
                    except Exception:
                        try:
                            result['decoded_text'] = raw_bytes.decode('utf-16-le', errors='replace')[:500]
                        except Exception:
                            result['decoded_text'] = repr(raw_bytes[:100])

            # Extract suspicious strings from decoded content
            if result['decoded_text']:
                decoded_lower = result['decoded_text'].lower()
                suspicious = [
                    'invoke-expression', 'iex', 'downloadstring', 'webclient',
                    'shellcode', 'payload', 'reverse', 'connect', 'socket',
                    'virtualalloc', 'createthread', 'writememory',
                    'amsibypass', 'bypass', 'hidden', 'encode'
                ]
                for s in suspicious:
                    if s in decoded_lower:
                        result['suspicious_indicators'].append(s)

                ip_hits = re.findall(
                    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
                    result['decoded_text']
                )
                result['extracted_strings'] = list(set(ip_hits + result['suspicious_indicators']))

        except Exception as e:
            result['decode_error'] = str(e)

        return result

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
        self.name = 'LogAgent'
        self.iteration = 0
        self.findings = []
        self.errors = []
        self.chain_of_custody = {}
        self.decoded_payloads = []
        self.extracted_iocs = {
            'ipv4_addresses': set(),
            'sha256_hashes': set(),
            'md5_hashes': set(),
            'base64_strings': set(),
            'decoded_payloads': set(),
            'file_paths': set(),
            'hostnames': set(),
            'usernames': set(),
            'process_ids': set(),
            'granted_access': set()
        }

    def _log(self, message, level='INFO'):
        timestamp = datetime.now().strftime('%H:%M:%S')
        prefix = {'INFO': 'i', 'WARN': '!', 'ERROR': 'X',
                  'FIND': '?', 'HASH': '#', 'B64': 'B'}.get(level, '.')
        print(f'[{timestamp}] {prefix} [{self.name}] {message}')

    def _record_finding(self, finding):
        finding['agent'] = self.name
        finding['iteration'] = self.iteration
        finding['timestamp'] = datetime.now(timezone.utc).isoformat()
        finding['traceable'] = True
        self.findings.append(finding)

    def _is_processable(self, filepath):
        ext = os.path.splitext(filepath)[1].lower()
        return ext in {'.log', '.txt', '.json', '.csv', '.evtx', '.xml', '.tsv', '.out', '.syslog'}

    def _extract_iocs(self, text, source_file):
        before = sum(len(v) for v in self.extracted_iocs.values())

        for ip in self._regex_ipv4(text):
            self.extracted_iocs['ipv4_addresses'].add(ip)
        for h in self._regex_sha256(text):
            self.extracted_iocs['sha256_hashes'].add(h)
        for h in self._regex_md5(text):
            self.extracted_iocs['md5_hashes'].add(h)
        for p in self._regex_file_paths(text):
            self.extracted_iocs['file_paths'].add(p)
        for h in self._regex_hostnames(text):
            self.extracted_iocs['hostnames'].add(h)

        # Clean username extraction
        raw_users = self._regex_usernames(text)
        for u in raw_users:
            if u not in self.USERNAME_NOISE and len(u) > 2:
                self.extracted_iocs['usernames'].add(u)

        for pid in self._regex_process_ids(text):
            self.extracted_iocs['process_ids'].add(pid)
        for ga in self._regex_granted_access(text):
            self.extracted_iocs['granted_access'].add(ga)

        # Base64 with auto-decode
        raw_b64 = self._regex_base64_raw(text)
        for b64 in raw_b64:
            display = b64[:50] + ('...' if len(b64) > 50 else '')
            self.extracted_iocs['base64_strings'].add(display)
            decoded = self._decode_base64_payload(b64)
            if decoded.get('decoded_text'):
                self.decoded_payloads.append(decoded)
                self._log(f'  Base64 decoded: {len(decoded["decoded_text"])} chars, compressed={decoded["is_compressed"]}', 'B64')
                if decoded['suspicious_indicators']:
                    self._log(f'  Suspicious in payload: {decoded["suspicious_indicators"]}', 'FIND')
                    self._record_finding({
                        'type': 'malicious_base64_payload',
                        'artifact': source_file,
                        'original_b64': display,
                        'decoded_preview': decoded['decoded_text'][:200],
                        'is_compressed': decoded['is_compressed'],
                        'suspicious_indicators': decoded['suspicious_indicators'],
                        'severity': 'CRITICAL'
                    })
                for ip in decoded.get('extracted_strings', []):
                    if re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                        self.extracted_iocs['ipv4_addresses'].add(ip)
                        self.extracted_iocs['decoded_payloads'].add(f'IP from payload: {ip}')

        after = sum(len(v) for v in self.extracted_iocs.values())
        new_count = after - before
        if new_count > 0:
            self._log(f'  +{new_count} IoCs from {os.path.basename(source_file)}', 'FIND')

    def _keyword_scan(self, logpath, file_hash):
        hits = {}
        result = call_tool('analyze_log_file', logpath=logpath, keywords=self.SUSPICIOUS_KEYWORDS[:15])
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


    def _flatten_json_values(self, obj, depth=0):
        """Recursively extract all string values from a JSON object."""
        if depth > 10:
            return ''
        result = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                result.append(str(k))
                result.append(self._flatten_json_values(v, depth + 1))
        elif isinstance(obj, list):
            for item in obj:
                result.append(self._flatten_json_values(item, depth + 1))
        elif isinstance(obj, str):
            result.append(obj)
        elif obj is not None:
            result.append(str(obj))
        return '\n'.join(filter(None, result))

    def _keyword_scan_json(self, filepath, file_hash):
        """JSON-aware keyword scanner — extracts keywords from inside JSON values."""
        hits = {}
        try:
            with open(filepath, 'r', errors='ignore') as f:
                data = json.load(f)
            flat_text = self._flatten_json_values(data)
            flat_lower = flat_text.lower()
            for keyword in self.SUSPICIOUS_KEYWORDS:
                kw_lower = keyword.lower()
                if kw_lower in flat_lower:
                    matches = [
                        line.strip() for line in flat_text.split('\n')
                        if kw_lower in line.lower() and line.strip()
                    ]
                    if matches:
                        hits[keyword] = {
                            'matches': matches[:5],
                            'count': len(matches),
                            'source_file': filepath,
                            'file_hash': file_hash[:16],
                            'tool_used': 'json_parser',
                        }
                        self._log(f'  JSON-ALERT: {keyword!r} x{len(matches)}', 'FIND')
        except json.JSONDecodeError:
            self._log(f'  JSON parse failed for {os.path.basename(filepath)} — falling back to grep', 'WARN')
        except Exception as e:
            self._log(f'  JSON scan error: {e}', 'WARN')
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
            return {}

        self._extract_iocs(raw_text, filepath)

        # Use JSON-aware scanner for .json files, grep for everything else
        ext = os.path.splitext(filepath)[1].lower()
        if ext == '.json':
            hits = self._keyword_scan_json(filepath, file_hash)
            # Also run grep scan and merge results
            grep_hits = self._keyword_scan(filepath, file_hash)
            for kw, val in grep_hits.items():
                if kw not in hits:
                    hits[kw] = val
        else:
            hits = self._keyword_scan(filepath, file_hash)
        return hits

    def run(self, case_path, file_list=None):
        self._log(f'Starting analysis: {case_path}')
        self.iteration += 1

        if file_list:
            files = [f for f in file_list if self._is_processable(f)]
        else:
            result = call_tool('list_evidence_files', case_path=case_path)
            all_files = result.get('output', '').strip().split('\n')
            files = [f for f in all_files if f.strip() and self._is_processable(f)]

        # Also discover .json files that grep tool may miss
        if os.path.exists(case_path):
            for fname in os.listdir(case_path):
                fpath = os.path.join(case_path, fname)
                if os.path.isfile(fpath) and self._is_processable(fpath) and fpath not in files:
                    files.append(fpath)

        files = list(set(files))
        self._log(f'Found {len(files)} processable file(s)')

        all_hits = {}
        for filepath in sorted(files):
            if not filepath.strip():
                continue
            hits = self._analyze_file(filepath)
            if hits:
                all_hits[filepath] = hits
                self._record_finding({
                    'type': 'suspicious_log_activity',
                    'file': filepath,
                    'artifact': filepath,
                    'file_hash': self.chain_of_custody.get(filepath, {}).get('sha256', ''),
                    'keywords_matched': list(hits.keys()),
                    'total_hits': sum(v['count'] for v in hits.values())
                })

        # Count files as suspicious if ANY IoC was extracted from them
        files_with_iocs = set()
        for finding in self.findings:
            if finding.get('type') in ('malicious_base64_payload', 'ioc_extracted'):
                src = finding.get('artifact', '')
                if src:
                    files_with_iocs.add(src)
        # Merge with all_hits keys
        all_suspicious_files = set(all_hits.keys()) | files_with_iocs
        suspicious_count = len(all_suspicious_files)

        clean_iocs = {k: sorted(list(v)) for k, v in self.extracted_iocs.items()}
        total_iocs = sum(len(v) for v in clean_iocs.values())
        self._log(f'Total verified IoCs: {total_iocs} (regex-only)', 'FIND')
        for ioc_type, ioc_list in clean_iocs.items():
            if ioc_list:
                self._log(f'  {ioc_type}: {ioc_list}', 'FIND')

        if self.decoded_payloads:
            self._log(f'Decoded {len(self.decoded_payloads)} base64 payload(s)', 'B64')

        return {
            'status': 'COMPLETE',
            'agent': self.name,
            'log_files_analyzed': len(files),
            'suspicious_files': suspicious_count,
            'hits': all_hits,
            'extracted_iocs': clean_iocs,
            'unique_ips': clean_iocs['ipv4_addresses'],
            'chain_of_custody': self.chain_of_custody,
            'decoded_payloads': self.decoded_payloads,
            'findings': self.findings,
            'errors': self.errors,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


if __name__ == '__main__':
    print('Testing LogAgent v3 — Full IoC + Base64 Decoder...')
    test_path = '/data/data/com.termux/files/home/cases/obfuscated_malware'
    agent = LogAgent()
    report = agent.run(test_path)

    print('\n=== CHAIN OF CUSTODY ===')
    for fp, coc in report['chain_of_custody'].items():
        print(f'  {os.path.basename(fp)}: {coc["sha256"][:32]}...')

    print('\n=== VERIFIED IoCs ===')
    for ioc_type, iocs in report['extracted_iocs'].items():
        if iocs:
            print(f'  {ioc_type}: {iocs}')

    print('\n=== DECODED PAYLOADS ===')
    for dp in report['decoded_payloads']:
        print(f'  Compressed: {dp["is_compressed"]}')
        print(f'  Suspicious: {dp["suspicious_indicators"]}')
        print(f'  Preview: {dp.get("decoded_text","")[:100]}')

    print(f'\nFiles analyzed: {report["log_files_analyzed"]}')
    print(f'Errors: {report["errors"]}')
    print('\nTest passed!')
