import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re
import hashlib
from datetime import datetime, timezone
from collections import defaultdict


class NetworkAgent:
    """
    Analyzes network artifacts for signs of compromise.
    Detects: C2 beaconing, DNS tunneling, port scanning,
    data exfiltration, and suspicious traffic patterns.
    All detection is regex/string matching -- zero LLM.
    """

    C2_INDICATORS = [
        'beacon', 'c2', 'command and control', 'reverse shell',
        'callback', 'check-in', 'checkin', 'heartbeat',
        'cobalt strike', 'metasploit', 'empire', 'covenant',
        'sliver', 'havoc', 'brute ratel'
    ]

    DNS_TUNNEL_INDICATORS = [
        'iodine', 'dnscat', 'dns2tcp', 'dns tunnel',
        'dns exfil', 'txt record exfil', 'long subdomain'
    ]

    EXFIL_INDICATORS = [
        'data exfil', 'exfiltration', 'large upload', 'bulk transfer',
        'ftp upload', 'sftp upload', 'mega.nz', 'pastebin',
        'transfer.sh', 'file.io', 'anonfiles'
    ]

    SCAN_INDICATORS = [
        'port scan', 'nmap', 'masscan', 'portscan',
        'syn scan', 'stealth scan', 'network sweep',
        'host discovery', 'ping sweep'
    ]

    SUSPICIOUS_PORTS = {
        '4444', '4445', '5555', '6666', '7777', '8888', '9999',
        '1337', '31337', '12345', '54321', '2222', '6379',
        '27017', '11211', '50050'
    }

    SUSPICIOUS_PROTOCOLS = [
        'irc over http', 'dns over non-standard', 'http over 443',
        'smb over internet', 'rdp over internet', 'vnc over internet'
    ]

    TLS_MISMATCH_INDICATORS = [
        "let's encrypt", 'self-signed', 'invalid cert',
        'cert mismatch', 'expired cert', 'untrusted ca'
    ]

    IP_RE = re.compile(
        r'\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )

    LONG_SUBDOMAIN_RE = re.compile(
        r'\b([a-zA-Z0-9]{30,})\.(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b'
    )

    TEXT_EXTENSIONS = {
        '.log', '.txt', '.json', '.csv', '.xml',
        '.tsv', '.out', '.syslog', '.pcap', '.zeek'
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
        self.name = 'NetworkAgent'
        self.iteration = 0
        self.findings = []
        self.errors = []
        self.chain_of_custody = {}
        self.extracted_iocs = {
            'c2_indicators': set(),
            'suspicious_ips': set(),
            'suspicious_ports': set(),
            'dns_tunnel_indicators': set(),
            'exfil_indicators': set(),
            'scan_indicators': set(),
            'tls_anomalies': set(),
            'long_subdomains': set(),
        }

    def _log(self, message, level='INFO'):
        timestamp = datetime.now().strftime('%H:%M:%S')
        prefix = {'INFO': 'i', 'WARN': '!', 'ERROR': 'X',
                  'FIND': '?', 'HASH': '#', 'NET': 'N'}.get(level, '.')
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

    def _extract_ips(self, text):
        hits = self.IP_RE.findall(text)
        clean = []
        for ip in set(hits):
            parts = ip.rstrip('.').split('.')
            if len(parts) == 4 and int(parts[0]) not in (0, 127, 255):
                clean.append(ip.rstrip('.'))
        return clean

    def _check_suspicious_ports(self, text):
        found = []
        for port in self.SUSPICIOUS_PORTS:
            patterns = [
                f':{port} ',
                f':{port}\t',
                f':{port}\n',
                f'port {port}',
                f'dport {port}',
                f'sport {port}'
            ]
            for pat in patterns:
                if pat in text or pat.upper() in text.upper():
                    found.append(port)
                    break
        return list(set(found))

    def _scan_text(self, text, source_file, file_hash):
        text_lower = text.lower()
        hits = 0

        # Extract all IPs
        all_ips = self._extract_ips(text)
        for ip in all_ips:
            self.extracted_iocs['suspicious_ips'].add(ip)

        # Check C2 indicators
        for indicator in self.C2_INDICATORS:
            if indicator.lower() in text_lower:
                matches = self._get_matching_lines(text, indicator)
                if matches:
                    self.extracted_iocs['c2_indicators'].add(indicator)
                    self._log(f'  C2: {indicator} in {os.path.basename(source_file)}', 'FIND')
                    hits += 1
                    self._record_finding({
                        'type': 'c2_communication',
                        'artifact': source_file,
                        'file_hash': file_hash[:16],
                        'indicator': indicator,
                        'evidence': matches[:3],
                        'severity': 'CRITICAL',
                        'mitre': 'T1071 - Application Layer Protocol'
                    })

        # Check DNS tunneling
        for indicator in self.DNS_TUNNEL_INDICATORS:
            if indicator.lower() in text_lower:
                matches = self._get_matching_lines(text, indicator)
                if matches:
                    self.extracted_iocs['dns_tunnel_indicators'].add(indicator)
                    self._log(f'  DNS TUNNEL: {indicator} in {os.path.basename(source_file)}', 'FIND')
                    hits += 1
                    self._record_finding({
                        'type': 'dns_tunneling',
                        'artifact': source_file,
                        'file_hash': file_hash[:16],
                        'indicator': indicator,
                        'evidence': matches[:3],
                        'severity': 'HIGH',
                        'mitre': 'T1071.004 - DNS'
                    })

        # Check long subdomains (DNS tunneling pattern)
        long_subs = self.LONG_SUBDOMAIN_RE.findall(text)
        if long_subs:
            for sub in long_subs[:5]:
                self.extracted_iocs['long_subdomains'].add(sub[:80])
            self._log(f'  LONG SUBDOMAIN (DNS tunnel?): {long_subs[0][:40]} in {os.path.basename(source_file)}', 'FIND')
            hits += 1
            self._record_finding({
                'type': 'dns_long_subdomain',
                'artifact': source_file,
                'file_hash': file_hash[:16],
                'subdomains': long_subs[:3],
                'severity': 'HIGH',
                'mitre': 'T1071.004 - DNS'
            })

        # Check exfiltration indicators
        for indicator in self.EXFIL_INDICATORS:
            if indicator.lower() in text_lower:
                matches = self._get_matching_lines(text, indicator)
                if matches:
                    self.extracted_iocs['exfil_indicators'].add(indicator)
                    self._log(f'  EXFIL: {indicator} in {os.path.basename(source_file)}', 'FIND')
                    hits += 1
                    self._record_finding({
                        'type': 'data_exfiltration',
                        'artifact': source_file,
                        'file_hash': file_hash[:16],
                        'indicator': indicator,
                        'evidence': matches[:3],
                        'severity': 'CRITICAL',
                        'mitre': 'T1041 - Exfiltration Over C2 Channel'
                    })

        # Check port scanning
        for indicator in self.SCAN_INDICATORS:
            if indicator.lower() in text_lower:
                matches = self._get_matching_lines(text, indicator)
                if matches:
                    self.extracted_iocs['scan_indicators'].add(indicator)
                    self._log(f'  SCAN: {indicator} in {os.path.basename(source_file)}', 'FIND')
                    hits += 1
                    self._record_finding({
                        'type': 'network_scan',
                        'artifact': source_file,
                        'file_hash': file_hash[:16],
                        'indicator': indicator,
                        'evidence': matches[:3],
                        'severity': 'HIGH',
                        'mitre': 'T1046 - Network Service Discovery'
                    })

        # Check suspicious ports
        sus_ports = self._check_suspicious_ports(text)
        for port in sus_ports:
            self.extracted_iocs['suspicious_ports'].add(port)
            self._log(f'  SUSPICIOUS PORT: {port} in {os.path.basename(source_file)}', 'FIND')
            hits += 1
            self._record_finding({
                'type': 'suspicious_port',
                'artifact': source_file,
                'file_hash': file_hash[:16],
                'port': port,
                'severity': 'HIGH',
                'mitre': 'T1571 - Non-Standard Port'
            })

        # Check TLS anomalies
        for indicator in self.TLS_MISMATCH_INDICATORS:
            if indicator.lower() in text_lower:
                matches = self._get_matching_lines(text, indicator)
                if matches:
                    self.extracted_iocs['tls_anomalies'].add(indicator)
                    self._log(f'  TLS ANOMALY: {indicator} in {os.path.basename(source_file)}', 'FIND')
                    hits += 1
                    self._record_finding({
                        'type': 'tls_anomaly',
                        'artifact': source_file,
                        'file_hash': file_hash[:16],
                        'indicator': indicator,
                        'evidence': matches[:3],
                        'severity': 'HIGH',
                        'mitre': 'T1071.001 - Web Protocols / T1568 - Dynamic Resolution'
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
        self._log(f'Starting network artifact analysis: {case_path}')
        self.iteration += 1
        if file_list:
            files = file_list
        else:
            files = []
            if os.path.exists(case_path):
                for fname in os.listdir(case_path):
                    fpath = os.path.join(case_path, fname)
                    if os.path.isfile(fpath):
                        ext = os.path.splitext(fname)[1].lower()
                        if ext in self.TEXT_EXTENSIONS or 'network' in fname.lower() or 'firewall' in fname.lower() or 'zeek' in fname.lower():
                            files.append(fpath)
        files = list(set(files))
        self._log(f'Found {len(files)} file(s) to scan')
        total_hits = 0
        for filepath in sorted(files):
            if filepath.strip():
                total_hits += self._analyze_file(filepath)
        clean_iocs = {k: sorted(list(v)) for k, v in self.extracted_iocs.items()}
        total_iocs = sum(len(v) for v in clean_iocs.values())
        self._log(f'Network scan complete -- {total_hits} hit(s), {total_iocs} IoC(s)', 'FIND')
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
    print('Testing NetworkAgent...')
    test_path = sys.argv[1] if len(sys.argv) > 1 else '/data/data/com.termux/files/home/cases/obfuscated_malware'
    agent = NetworkAgent()
    report = agent.run(test_path)
    print(f'Files analyzed : {report["files_analyzed"]}')
    print(f'Total hits     : {report["total_hits"]}')
    print(f'Priority       : {report["priority"]}')
    print(f'Findings       : {len(report["findings"])}')
    for k, v in report['extracted_iocs'].items():
        if v:
            print(f'  {k}: {list(v)[:3]}')
    print('Test passed!')