# NEXUS-IR v2.0
## Autonomous Incident Response Agent
### Find Evil! Hackathon -- SANS Institute 2026

> "Find Evil." Two words. One command. Complete investigation in 1.4 seconds.

## Quickstart
pip install -r requirements.txt
python main.py /path/to/case

## What It Does
1. TRIAGE -- Dynamic priority escalation from evidence content
2. LOG ANALYSIS -- Regex-only IoC extraction (zero LLM hallucination)
3. CHAIN OF CUSTODY -- SHA256 hash every evidence file on load
4. CORRELATION -- 6 MITRE ATT&CK patterns + temporal sequences
5. ATTACK NARRATIVE -- Chronological kill chain story
6. SELF-CORRECTION -- Validates findings against real artifacts
7. CONTAINMENT -- 15+ actionable remediation steps

## Guardrails
Dangerous commands blocked IN CODE not prompts:
rm, dd, shred, wget, curl, ssh, mkfs -- all blocked architecturally.

## Sample Output
Threat Level   : CRITICAL (100/100)
Duration       : 1.4 seconds
Attack Patterns: BRUTE_FORCE, PRIVILEGE_ESCALATION,
                 LATERAL_MOVEMENT_OR_C2, RANSOMWARE_OR_MALWARE
IoCs Extracted : IPs, hashes, base64, file paths, hostnames

## License
MIT -- Built by the community, for the community.
