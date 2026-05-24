# NEXUS-IR v3.0
## Autonomous Incident Response Agent
### Find Evil! Hackathon -- SANS Institute 2026

> "Find Evil." Two words. One command. Complete APT investigation in under 1.5 seconds.

## Quickstart
pip install -r requirements.txt
python main.py /path/to/case/folder

## What Makes NEXUS-IR Different

### Native Multi-Format Support
Processes .log, .json, .csv, .txt, .evtx, .xml natively.
No file renaming required. Drop any artifact folder and run.

### Regex-Only IoC Extraction
Zero LLM hallucination. Pure Python re.findall() extracts:
IPv4 addresses, SHA256/MD5 hashes, base64 strings,
file paths, hostnames, usernames, process IDs, GrantedAccess values.

### Automatic Base64 Decoder
Detects and decodes base64 payloads. Handles zlib/deflate
compression. Extracts IPs and suspicious strings from decoded content.

### Chain of Custody
SHA256 hash every evidence file on load.
Full tamper detection with timestamp records.

### High-Signal APT Signatures
Forces CRITICAL instantly when:
- GrantedAccess=0x1FFFFF (PROCESS_ALL_ACCESS)
- PowerShell ExecutionPolicy Bypass + WindowStyle Hidden
- TLS cert issued by unexpected CA for Microsoft-named domain

### Time-Window Correlation Matrix
Sysmon EventID 1 (execution) + 10 (process access) +
8 (remote thread) = FULL_INJECTION_CHAIN with 3.5x score multiplier.

### Devil Advocate Self-Correction
Actively challenges its own findings. Catches mismatches between
triage keywords and final threat scores. Flags contradictions and
forces re-evaluation.

### MITRE ATT&CK Coverage
T1055 Process Injection, T1059.001 PowerShell,
T1027 Obfuscation, T1486 Ransomware, T1110 Brute Force,
T1548 Privilege Escalation, T1021 Lateral Movement,
T1041 Exfiltration, T1003 Credential Dumping, T1071 C2

## Test Results
| Case | Priority | Threat | Score | Time |
|------|----------|--------|-------|------|
| APT Obfuscated Malware | CRITICAL | CRITICAL | 100/100 | 0.9s |
| Financial Institution Breach | CRITICAL | CRITICAL | 100/100 | 1.4s |
| Ransomware | CRITICAL | CRITICAL | 95/100 | 0.4s |
| Brute Force | HIGH | HIGH | 80/100 | 0.4s |

## Architecture
1. TRIAGE AGENT -- Dynamic priority, CoC hashing, all formats
2. LOG AGENT -- Regex IoC extraction, base64 decoder
3. CORRELATION AGENT -- APT signatures, time-window matrix
4. CORRECTION AGENT -- Devil advocate, contradiction detection
5. REPORT GENERATOR -- Kill chain narrative, containment actions

## Guardrails
rm, dd, shred, wget, curl, ssh -- blocked in Python code.
AI cannot run destructive commands regardless of evidence content.

## License
MIT -- Built by the community, for the community.
