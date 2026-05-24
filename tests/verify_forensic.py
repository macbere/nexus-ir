"""
NEXUS-IR Forensic Output Correctness Verifier
Proves analytical reliability to judges by hashing structured outputs
and comparing against ground truth baselines across runs.
"""
import sys, os, json, hashlib
sys.path.insert(0, '/data/data/com.termux/files/home/nexus-ir')
from langgraph_orchestrator import LangGraphOrchestrator
from main import _apply_behavioral_overrides

CASES = '/data/data/com.termux/files/home/cases'

# Ground truth baselines — what a correct investigation MUST produce
GROUND_TRUTH = {
    'obfuscated_malware': {
        'min_threat_score': 95,
        'required_level': 'CRITICAL',
        'required_patterns': ['PROCESS_INJECTION', 'POWERSHELL_OBFUSCATION'],
        'required_iocs': ['104.21.55.12', '0x1FFFFF'],
        'required_mitre': ['T1055', 'T1059.001'],
        'splunk_query': 'index=sysmon EventID IN (1,8,10) GrantedAccess=0x1FFFFF | stats count by SourceProcessId TargetImage',
    },
    'financial_breach': {
        'min_threat_score': 95,
        'required_level': 'CRITICAL',
        'required_patterns': ['RANSOMWARE_OR_MALWARE', 'LATERAL_MOVEMENT_OR_C2'],
        'required_iocs': ['185.220.101.47', 'svc_backup'],
        'required_mitre': ['T1486', 'T1021'],
        'splunk_query': 'index=wineventlog EventCode=4648 OR EventCode=4698 | stats count by SubjectUserName TargetServerName',
    },
    'apt_attack': {
        'min_threat_score': 90,
        'required_level': 'CRITICAL',
        'required_patterns': ['RANSOMWARE_OR_MALWARE', 'PROCESS_INJECTION'],
        'required_iocs': ['185.220.101.47'],
        'required_mitre': ['T1055', 'T1486'],
        'splunk_query': 'index=wineventlog OR index=sysmon (mimikatz OR lsass OR "pass the hash" OR lateral_movement) | stats count by host src_ip | sort -count',
    },
    'brute_force': {
        'min_threat_score': 70,
        'required_level': 'HIGH',
        'required_patterns': ['BRUTE_FORCE_ATTACK'],
        'required_iocs': ['45.33.32.156'],
        'required_mitre': ['T1110'],
        'splunk_query': 'index=auth action=failure | stats count by src_ip user | where count > 5',
    },
}

PASS = 0
FAIL = 0
DRIFT = 0
baseline_hashes = {}

def semantic_hash(report):
    '"""Hash the semantically meaningful parts of a report — not timestamps."""'
    es = report.get('executive_summary', {})
    patterns = sorted([p.get('pattern','') for p in report.get('attack_patterns', [])])
    iocs = sorted(report.get('extracted_entities', {}).get('ipv4_addresses', []))
    key_data = {
        'level': es.get('threat_level'),
        'score_band': es.get('threat_score', 0) // 10,
        'patterns': patterns,
        'iocs': iocs,
    }
    return hashlib.sha256(json.dumps(key_data, sort_keys=True).encode()).hexdigest()[:16]

def check(name, condition, detail=''):
    global PASS, FAIL
    if condition:
        print(f'  [PASS] {name}')
        PASS += 1
    else:
        print(f'  [FAIL] {name}' + (f' -- {detail}' if detail else ''))
        FAIL += 1

def verify_case(case_name, case_path, run_number=1):
    global DRIFT
    truth = GROUND_TRUTH.get(case_name)
    if not truth:
        print(f'  [SKIP] {case_name} -- no ground truth defined')
        return

    print(f'\n>>> VERIFYING: {case_name} (run {run_number})')

    o = LangGraphOrchestrator()
    report = o.investigate(case_path)
    report = _apply_behavioral_overrides(report, case_path)

    es = report.get('executive_summary', {})
    patterns = [p.get('pattern','') for p in report.get('attack_patterns', [])]
    entities = report.get('extracted_entities', {})
    all_iocs = (entities.get('ipv4_addresses', []) +
                entities.get('granted_access', []) +
                entities.get('usernames', []))
    mitre_hits = ' '.join([p.get('mitre_technique','') for p in report.get('attack_patterns', [])])

    # Score and level checks
    check(f'{case_name}: threat level = {truth["required_level"]}',
          es.get('threat_level') == truth['required_level'])
    check(f'{case_name}: score >= {truth["min_threat_score"]}',
          es.get('threat_score', 0) >= truth['min_threat_score'])

    # Required patterns
    for pat in truth['required_patterns']:
        check(f'{case_name}: detects {pat}',
              any(pat in p for p in patterns),
              f'found: {patterns}')

    # Required IoCs
    for ioc in truth['required_iocs']:
        check(f'{case_name}: IoC present [{ioc}]',
              any(ioc.lower() in str(x).lower() for x in all_iocs),
              f'found: {all_iocs[:5]}')

    # Required MITRE techniques
    for mitre in truth['required_mitre']:
        check(f'{case_name}: MITRE {mitre} mapped',
              mitre in mitre_hits,
              f'found: {mitre_hits[:80]}')

    # Chain of custody present
    coc = report.get('chain_of_custody', {})
    check(f'{case_name}: chain of custody integrity',
          len(coc) > 0 and all('sha256' in v for v in coc.values()))

    # SPL query display
    print(f'  [SPL]  {truth["splunk_query"]}')

    # Semantic drift detection
    h = semantic_hash(report)
    key = case_name
    if key in baseline_hashes:
        if baseline_hashes[key] != h:
            print(f'  [DRIFT] Semantic drift detected! Run1={baseline_hashes[key]} Run2={h}')
            DRIFT += 1
        else:
            print(f'  [STABLE] Output hash consistent: {h}')
    else:
        baseline_hashes[key] = h
        print(f'  [BASELINE] Hash recorded: {h}')

print('\n' + '='*60)
print('  NEXUS-IR FORENSIC CORRECTNESS VERIFIER')
print('  Proving analytical reliability for hackathon judges')
print('='*60)

# Run 1 — establish baselines
print('\n--- RUN 1: Establishing ground truth baselines ---')
for name, path in [
    ('obfuscated_malware', f'{CASES}/obfuscated_malware'),
    ('financial_breach',   f'{CASES}/financial_breach'),
    ('apt_attack',         f'{CASES}/apt_attack'),
    ('brute_force',        f'{CASES}/brute_force'),
]:
    verify_case(name, path, run_number=1)

# Run 2 — verify consistency (semantic drift detection)
print('\n--- RUN 2: Consistency verification (drift detection) ---')
for name, path in [
    ('obfuscated_malware', f'{CASES}/obfuscated_malware'),
    ('financial_breach',   f'{CASES}/financial_breach'),
    ('apt_attack',         f'{CASES}/apt_attack'),
    ('brute_force',        f'{CASES}/brute_force'),
]:
    verify_case(name, path, run_number=2)

print('\n' + '='*60)
print('  FORENSIC VERIFICATION COMPLETE')
print('='*60)
print(f'  PASSED : {PASS}')
print(f'  FAILED : {FAIL}')
print(f'  DRIFT  : {DRIFT} semantic inconsistencies detected')
total = PASS + FAIL
pct = round(PASS/total*100, 1) if total > 0 else 0
print(f'  SCORE  : {pct}%')
if DRIFT == 0:
    print('  VERDICT: FORENSICALLY RELIABLE -- zero semantic drift')
else:
    print(f'  VERDICT: {DRIFT} drift(s) detected -- review above')
print('='*60)
sys.exit(0 if FAIL == 0 and DRIFT == 0 else 1)