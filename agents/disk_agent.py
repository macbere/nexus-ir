import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re
import hashlib
from datetime import datetime, timezone


class DiskAgent:
    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js',
        '.hta', '.scr', '.pif', '.com', '.cpl', '.msi', '.jar'
    }
    MALWARE_DROP_PATHS = [
        'temp', 'tmp', 'appdata', 'users/public', 'programdata',
        'windows/temp', 'recycle', '$recycle', '/tmp/', '/var/tmp/'
    ]
    PERSISTENCE_PATHS = [
        'startup', 'start menu', 'runonce', '/tasks/', 'scheduled tasks',
        '/etc/cron', '/etc/init.d', '/etc/rc', '.bashrc', '.profile',
        'system32/drivers'
    ]
    SUSPICIOUS_FILENAMES = [
        'mimikatz', 'meterpreter', 'cobalt', 'beacon', 'empire',
        'powersploit', 'invoke-', 'psexec', 'wce.exe', 'fgdump',
        'gsecdump', 'procdump', 'dumpert', 'nanodump',
        'cobaltstrike', 'metasploit', 'shellcode', 'payload',
        'exploit', 'rootkit', 'keylogger', 'ransomware',
        'cryptor', 'locker', 'wiper', 'destroyer'
    ]
    TEXT_EXTENSIONS = {
        '.log', '.txt', '.json', '.csv', '.xml',
        '.tsv', '.out', '.syslog', '.evtx'
    }

    DOUBLE_EXT_RE = re.compile(
        r'\b\w+\.(pdf|doc|docx|xls|jpg|png)\.exe\b', re.IGNORECASE
    )

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

    @staticmethod
    def _regex_file_paths(text):
        win  = re.findall(r'[A-Za-z]:\\(?:[\w\-. ]+\\)*[\w\-.]+', text)
        unix = re.findall(r'(?<![\w])/(?:[\w\-.]+/)+[\w\-.]+', text)
        return list(set(win + unix))

    def __init__(self):
        self.name = 'DiskAgent'
        self.iteration = 0
        self.findings = []
        self.errors = []
        self.chain_of_custody = {}
        self.extracted_iocs = {
            'suspicious_executables': set(),
            'drop_zone_paths': set(),
            'persistence_paths': set(),
            'double_extension_files': set(),
            'malicious_filenames': set(),
        }

    def _log(self, message, level='INFO'):
        timestamp = datetime.now().strftime('%H:%M:%S')
        prefix = {'INFO': 'i', 'WARN': '!', 'ERROR': 'X',
                  'FIND': '?', 'HASH': '#', 'DISK': 'D'}.get(level, '.')
        print(f'[{timestamp}] {prefix} [{self.name}] {message}')

    def _record_finding(self, finding):
        finding['agent'] = self.name
        finding['iteration'] = self.iteration
        finding['timestamp'] = datetime.now(timezone.utc).isoformat()
        finding['traceable'] = True
        self.findings.append(finding)

    def _scan_text(self, text, source_file, file_hash):
        text_lower = text.lower()
        hits = 0

        for drop_path in self.MALWARE_DROP_PATHS:
            if drop_path.lower() in text_lower:
                matches = [l.strip() for l in text.split('\n')
                           if drop_path.lower() in l.lower() and l.strip()]
                if matches:
                    for m in matches[:3]:
                        self.extracted_iocs['drop_zone_paths'].add(m[:120])
                    self._log(f'  DROP ZONE: {drop_path} in {os.path.basename(source_file)}', 'FIND')
                    hits += 1
                    self._record_finding({
                        'type': 'malware_drop_zone',
                        'artifact': source_file,
                        'file_hash': file_hash[:16],
                        'path_pattern': drop_path,
                        'evidence': matches[:3],
                        'severity': 'HIGH'
                    })

        for pers_path in self.PERSISTENCE_PATHS:
            if pers_path.lower() in text_lower:
                matches = [l.strip() for l in text.split('\n')
                           if pers_path.lower() in l.lower() and l.strip()]
                if matches:
                    for m in matches[:3]:
                        self.extracted_iocs['persistence_paths'].add(m[:120])
                    self._log(f'  PERSISTENCE: {pers_path} in {os.path.basename(source_file)}', 'FIND')
                    hits += 1
                    self._record_finding({
                        'type': 'persistence_mechanism',
                        'artifact': source_file,
                        'file_hash': file_hash[:16],
                        'path_pattern': pers_path,
                        'evidence': matches[:3],
                        'severity': 'CRITICAL'
                    })

        for fname in self.SUSPICIOUS_FILENAMES:
            if fname.lower() in text_lower:
                matches = [l.strip() for l in text.split('\n')
                           if fname.lower() in l.lower() and l.strip()]
                if matches:
                    self.extracted_iocs['malicious_filenames'].add(fname)
                    self._log(f'  MALICIOUS FILE: {fname} in {os.path.basename(source_file)}', 'FIND')
                    hits += 1
                    self._record_finding({
                        'type': 'malicious_filename',
                        'artifact': source_file,
                        'file_hash': file_hash[:16],
                        'filename_pattern': fname,
                        'evidence': matches[:3],
                        'severity': 'CRITICAL'
                    })

        double_ext = self.DOUBLE_EXT_RE.findall(text)
        if double_ext:
            for ext in double_ext:
                self.extracted_iocs['double_extension_files'].add(ext)
            self._log(f'  DOUBLE-EXT: {double_ext} in {os.path.basename(source_file)}', 'FIND')
            hits += 1
            self._record_finding({
                'type': 'double_extension_masquerade',
                'artifact': source_file,
                'file_hash': file_hash[:16],
                'extensions_found': double_ext,
                'severity': 'CRITICAL'
            })

        for path in self._regex_file_paths(text):
            for ext in self.SUSPICIOUS_EXTENSIONS:
                if path.lower().endswith(ext):
                    self.extracted_iocs['suspicious_executables'].add(path[:120])

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
        self._log(f'Starting disk artifact analysis: {case_path}')
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
        self._log(f'Disk scan complete -- {total_hits} hit(s), {total_iocs} IoC(s)', 'FIND')
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
    print('Testing DiskAgent...')
    test_path = sys.argv[1] if len(sys.argv) > 1 else '/data/data/com.termux/files/home/cases/obfuscated_malware'
    agent = DiskAgent()
    report = agent.run(test_path)
    print(f'Files analyzed : {report["files_analyzed"]}')
    print(f'Total hits     : {report["total_hits"]}')
    print(f'Priority       : {report["priority"]}')
    print(f'Findings       : {len(report["findings"])}')
    for k, v in report['extracted_iocs'].items():
        if v:
            print(f'  {k}: {list(v)[:3]}')
    print('Test passed!')