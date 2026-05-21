import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import hashlib
from datetime import datetime, timezone
from tools.mcp_server import call_tool


class TriageAgent:

    CRITICAL_KEYWORDS = [
        "ransomware", "backdoor", "base64", "powershell",
        "reverse shell", "exploit", "malware", "encoded",
        "lateral movement", "exfiltration", "c2", "command and control",
        "mimikatz", "lsass", "kerberoast", "golden ticket",
        "executionpolicy bypass", "windowstyle hidden", "0x1fffff",
        "process injection", "createremotethread", "virtualalloc",
        "reflective", "shellcode", "cobalt strike", "metasploit"
    ]

    HIGH_KEYWORDS = [
        "failed login", "failed password", "authentication failure",
        "unauthorized", "privilege escalation", "sudo", "root",
        "brute force", "injection", "anomaly", "account lockout",
        "wmi", "scheduled task", "registry", "persistence",
        "svchost", "certutil", "regsvr32", "mshta", "rundll32"
    ]

    # All text-based extensions NEXUS-IR can process
    TEXT_EXTENSIONS = {
        '.log', '.txt', '.json', '.csv', '.evtx',
        '.xml', '.tsv', '.out', '.syslog'
    }

    def __init__(self):
        self.name = 'TriageAgent'
        self.iteration = 0
        self.findings = []
        self.errors = []
        self.keyword_hits = {}
        self.file_hashes = {}

    def _log(self, message, level='INFO'):
        timestamp = datetime.now().strftime('%H:%M:%S')
        prefix = {'INFO': 'i', 'WARN': '!', 'ERROR': 'X',
                  'FIND': '?', 'CRIT': '!!', 'HASH': '#'}.get(level, '.')
        print(f'[{timestamp}] {prefix} [{self.name}] {message}')

    def _record_finding(self, finding):
        finding['agent'] = self.name
        finding['iteration'] = self.iteration
        finding['timestamp'] = datetime.now(timezone.utc).isoformat()
        finding['traceable'] = True
        self.findings.append(finding)

    def _hash_file(self, filepath):
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            return f'ERROR:{e}'

    def _is_text_file(self, filepath):
        ext = os.path.splitext(filepath)[1].lower()
        return ext in self.TEXT_EXTENSIONS

    def _scan_file_for_keywords(self, filepath):
        found_critical = []
        found_high = []
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read().lower()
            for kw in self.CRITICAL_KEYWORDS:
                if kw in content:
                    found_critical.append(kw)
            for kw in self.HIGH_KEYWORDS:
                if kw in content:
                    found_high.append(kw)
        except Exception as e:
            self.errors.append(f'Keyword scan failed {filepath}: {e}')
        return {'critical': found_critical, 'high': found_high}

    def _discover_all_files(self, case_path):
        all_files = []
        if not os.path.exists(case_path):
            return all_files
        for fname in os.listdir(case_path):
            fpath = os.path.join(case_path, fname)
            if os.path.isfile(fpath) and self._is_text_file(fpath):
                all_files.append(fpath)
        return sorted(all_files)

    def _categorize_files(self, files):
        categories = {
            'disk_images': [], 'memory_dumps': [], 'log_files': [],
            'network_captures': [], 'registry_files': [],
            'json_artifacts': [], 'csv_data': [], 'unknown': []
        }
        ext_map = {
            '.E01': 'disk_images', '.dd': 'disk_images', '.img': 'disk_images',
            '.raw': 'memory_dumps', '.mem': 'memory_dumps', '.dmp': 'memory_dumps',
            '.log': 'log_files', '.txt': 'log_files', '.evtx': 'log_files',
            '.syslog': 'log_files', '.out': 'log_files',
            '.pcap': 'network_captures', '.pcapng': 'network_captures',
            '.reg': 'registry_files', '.hive': 'registry_files',
            '.json': 'json_artifacts',
            '.csv': 'csv_data', '.tsv': 'csv_data'
        }
        for filepath in files:
            ext = os.path.splitext(filepath)[1].lower()
            cat = ext_map.get(ext, 'unknown')
            categories[cat].append(filepath)
        return categories

    def _assess_priority(self, files):
        all_critical = []
        all_high = []
        for filepath in files:
            result = self._scan_file_for_keywords(filepath)
            all_critical.extend(result['critical'])
            all_high.extend(result['high'])

        self.keyword_hits = {
            'critical_keywords_found': list(set(all_critical)),
            'high_keywords_found': list(set(all_high))
        }

        if all_critical:
            self._log(f'CRITICAL keywords: {list(set(all_critical))}', 'CRIT')
            self._record_finding({
                'type': 'dynamic_priority_escalation',
                'reason': 'Critical keywords found in evidence',
                'keywords': list(set(all_critical)),
                'artifact': 'triage_scan',
                'priority_set': 'CRITICAL'
            })
            return 'CRITICAL'
        if all_high:
            self._log(f'HIGH keywords: {list(set(all_high))}', 'FIND')
            return 'HIGH'
        return 'MEDIUM'

    def _build_plan(self, categories, priority):
        plan = []
        analyzable = (
            categories.get('log_files', []) +
            categories.get('json_artifacts', []) +
            categories.get('csv_data', []) +
            categories.get('unknown', [])
        )
        if analyzable:
            plan.append({'agent': 'LogAgent', 'reason': f'{len(analyzable)} text artifact(s) detected', 'priority': 1})
        if categories.get('disk_images'):
            plan.append({'agent': 'DiskAgent', 'reason': 'Disk images present', 'priority': 2})
        if categories.get('memory_dumps'):
            plan.append({'agent': 'MemoryAgent', 'reason': 'Memory dumps present', 'priority': 3})
        if categories.get('network_captures'):
            plan.append({'agent': 'NetworkAgent', 'reason': 'Network captures present', 'priority': 4})
        plan.append({'agent': 'CorrelationAgent', 'reason': 'Always runs', 'priority': 5})
        plan.append({'agent': 'CorrectionAgent', 'reason': 'Always runs', 'priority': 6})
        return sorted(plan, key=lambda x: x['priority'])

    def run(self, case_path):
        self._log(f'Starting triage: {case_path}')
        self.iteration += 1

        files = self._discover_all_files(case_path)
        self._log(f'Discovered {len(files)} processable file(s)', 'FIND')

        for f in files:
            fhash = self._hash_file(f)
            self.file_hashes[f] = fhash
            self._log(f'  CoC: {os.path.basename(f)} -> {fhash[:16]}...', 'HASH')

        categories = self._categorize_files(files)
        for cat, flist in categories.items():
            if flist:
                self._log(f'  {cat}: {len(flist)} file(s)', 'FIND')
                self._record_finding({
                    'type': 'evidence_detected',
                    'category': cat,
                    'count': len(flist),
                    'files': [os.path.basename(f) for f in flist[:5]],
                    'artifact': flist[0] if flist else 'unknown'
                })

        priority = self._assess_priority(files)
        self._log(f'Priority: {priority}', 'FIND')

        plan = self._build_plan(categories, priority)
        self._log(f'Plan: {len(plan)} agents', 'FIND')
        for step in plan:
            self._log(f'  -> {step["agent"]}: {step["reason"]}')

        return {
            'status': 'COMPLETE',
            'agent': self.name,
            'case_path': case_path,
            'priority': priority,
            'keyword_hits': self.keyword_hits,
            'all_files': files,
            'evidence_types': categories,
            'total_files': len(files),
            'investigation_plan': plan,
            'file_hashes': self.file_hashes,
            'findings': self.findings,
            'errors': self.errors,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


if __name__ == '__main__':
    print('Testing TriageAgent v3...')
    test_path = '/data/data/com.termux/files/home/cases/obfuscated_malware'
    agent = TriageAgent()
    report = agent.run(test_path)
    print(f'Files found: {report["total_files"]}')
    print(f'Priority: {report["priority"]}')
    print(f'Keywords: {report["keyword_hits"]}')
    print(f'Plan: {[p["agent"] for p in report["investigation_plan"]]}')
    print('Test passed!')
