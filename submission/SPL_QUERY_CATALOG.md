# SPL Query Catalog — NEXUS-IR
## Find Evil! Hackathon — SANS Institute 2026

| Case | MITRE Technique | SPL Query | Notes |
|---|---|---|---|
| obfuscated_malware | T1055, T1059.001 | `index=sysmon EventID IN (1,8,10) GrantedAccess=0x1FFFFF \| stats count by SourceProcessId TargetImage` | Precise Sysmon filtering |
| financial_breach | T1486, T1021 | `index=wineventlog EventCode=4648 OR EventCode=4698 \| stats count by SubjectUserName TargetServerName` | Windows event correlation |
| apt_attack | T1055, T1486 | `index=wineventlog OR index=sysmon (mimikatz OR lsass OR "pass the hash" OR lateral_movement) \| stats count by host src_ip \| sort -count` | REFINED: scoped index, added sort |
| brute_force | T1110 | `index=auth action=failure \| stats count by src_ip user \| where count > 5` | Threshold-based detection |
