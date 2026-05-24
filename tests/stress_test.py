"""
NEXUS-IR Heavy Stress Test Suite
Runs all 10 cases and validates detection accuracy, scoring, and pipeline stability.
"""
import sys, os, time
sys.path.insert(0, '/data/data/com.termux/files/home/nexus-ir')

from langgraph_orchestrator import LangGraphOrchestrator
from main import _apply_behavioral_overrides

CASES = '/data/data/com.termux/files/home/cases'

PASS = 0
FAIL = 0
results = []

def check(name, condition, detail=''):
    global PASS, FAIL
    if condition:
        print(f'    [PASS] {name}')
        PASS += 1
    else:
        print(f'    [FAIL] {name}' + (f' -- {detail}' if detail else ''))
        FAIL += 1

def run_case(name, case_dir, expected_level, expected_min_score,
             expected_patterns=None, should_not_escalate=False):
    global results
    print(f'\n>>> CASE: {name}')
    print(f'    Path: {case_dir}')
    start = time.time()
    try:
        o = LangGraphOrchestrator()
        r = o.investigate(case_dir)
        r = _apply_behavioral_overrides(r, case_dir)
        duration = round(time.time() - start, 2)
        es = r.get('executive_summary', {})
        level = es.get('threat_level', 'UNKNOWN')
        score = es.get('threat_score', 0)
        validated = es.get('findings_validated', 0)
        rejected = es.get('findings_rejected', 0)
        patterns = [p.get('pattern', '') for p in r.get('attack_patterns', [])]
        coc = r.get('chain_of_custody', {})
        trace = r.get('execution_trace', [])
        auto_fixed = es.get('auto_remediated', 0)
        print(f'    Level : {level} ({score}/100)')
        print(f'    Time  : {duration}s')
        print(f'    Valid : {validated} | Rejected: {rejected} | Auto-fixed: {auto_fixed}')
        print(f'    Patterns: {patterns}')
        check(f'{name}: threat level = {expected_level}', level == expected_level)
        check(f'{name}: score >= {expected_min_score}', score >= expected_min_score)
        check(f'{name}: zero rejected findings', rejected == 0)
        check(f'{name}: chain of custody present', len(coc) > 0)
        check(f'{name}: execution trace present', len(trace) > 0)
        if expected_patterns:
            for pat in expected_patterns:
                found = any(pat.upper() in p.upper() for p in patterns)
                check(f'{name}: detects {pat}', found)
        if should_not_escalate:
            check(f'{name}: correctly NOT escalated to CRITICAL', level != 'CRITICAL')
        results.append({'case': name, 'level': level, 'score': score,
                        'duration': duration, 'validated': validated,
                        'rejected': rejected, 'patterns': patterns, 'status': 'OK'})
    except Exception as e:
        duration = round(time.time() - start, 2)
        print(f'    [ERROR] {e}')
        check(f'{name}: pipeline completes without error', False, str(e))
        results.append({'case': name, 'level': 'ERROR', 'score': 0,
                        'duration': duration, 'status': 'ERROR', 'error': str(e)})

# ════════════════════════════════════════════════════════════
print('\n' + '='*60)
print('  NEXUS-IR HEAVY STRESS TEST')
print('  Testing all 10 cases for detection accuracy & stability')
print('='*60)

# CASE 1: Known-good baseline
run_case(
    'Obfuscated Malware (baseline)',
    f'{CASES}/obfuscated_malware',
    expected_level='CRITICAL',
    expected_min_score=95,
    expected_patterns=['PROCESS_INJECTION', 'POWERSHELL_OBFUSCATION']
)

# CASE 2: Financial breach multi-agent
run_case(
    'Financial Breach (multi-agent)',
    f'{CASES}/financial_breach',
    expected_level='CRITICAL',
    expected_min_score=95,
    expected_patterns=['RANSOMWARE_OR_MALWARE', 'LATERAL_MOVEMENT_OR_C2']
)

# CASE 3: APT full kill chain
run_case(
    'APT Attack (full kill chain)',
    f'{CASES}/apt_attack',
    expected_level='CRITICAL',
    expected_min_score=90,
    expected_patterns=['PROCESS_INJECTION', 'RANSOMWARE_OR_MALWARE']
)

# CASE 4: Ransomware
run_case(
    'Ransomware',
    f'{CASES}/ransomware',
    expected_level='CRITICAL',
    expected_min_score=90,
    expected_patterns=['RANSOMWARE_OR_MALWARE']
)

# CASE 5: Brute force — must NOT over-escalate
run_case(
    'Brute Force (no over-escalation)',
    f'{CASES}/brute_force',
    expected_level='HIGH',
    expected_min_score=70,
    should_not_escalate=True
)

# CASE 6: LOLBIN Invasion — behavioral override T1218.010
run_case(
    'LOLBIN Invasion (T1218.010 override)',
    f'{CASES}/lolbin_invasion',
    expected_level='CRITICAL',
    expected_min_score=85,
    expected_patterns=['LOLBIN_INVASION']
)

# CASE 7: Defense Blinding — wevtutil + lsass dump
run_case(
    'Defense Blinding (T1070.001 override)',
    f'{CASES}/defense_blinding',
    expected_level='CRITICAL',
    expected_min_score=90,
    expected_patterns=['DEFENSE_EVASION']
)

# CASE 8: ICMP Tunnel Exfil — T1095 override
run_case(
    'ICMP Tunnel Exfiltration (T1095 override)',
    f'{CASES}/icmp_tunnel',
    expected_level='CRITICAL',
    expected_min_score=80,
    expected_patterns=['ICMP_TUNNEL']
)

# CASE 9: Stealth Evasion — certutil + process injection
run_case(
    'Stealth Evasion (certutil + injection)',
    f'{CASES}/stealth_evasion',
    expected_level='CRITICAL',
    expected_min_score=80,
    expected_patterns=['PROCESS_INJECTION']
)

# CASE 10: Insider Threat — low and slow, must NOT score CRITICAL
run_case(
    'Insider Threat (false-positive control)',
    f'{CASES}/insider',
    expected_level='HIGH',
    expected_min_score=60,
    should_not_escalate=True
)

# ════════════════════════════════════════════════════════════
print('\n' + '='*60)
print('  STRESS TEST SCORECARD')
print('='*60)
print(f'  {"CASE":<40} {"LEVEL":<10} {"SCORE":<8} {"TIME":<8} {"STATUS"}')
print('  ' + '-'*58)
for r in results:
    level = r.get('level', '?')
    score = r.get('score', 0)
    dur   = r.get('duration', 0)
    stat  = r.get('status', '?')
    name  = r['case'][:38]
    print(f'  {name:<40} {level:<10} {score:<8} {dur:<8} {stat}')
print('='*60)
print(f'  PASSED : {PASS}')
print(f'  FAILED : {FAIL}')
total = PASS + FAIL
score_pct = round(PASS / total * 100, 1) if total > 0 else 0
print(f'  SCORE  : {score_pct}%')
print('='*60)
if FAIL == 0:
    print('  ALL STRESS TESTS PASSED')
else:
    print(f'  {FAIL} failure(s) — review above')
sys.exit(0 if FAIL == 0 else 1)