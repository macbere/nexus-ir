import re

def assess_behavioral_threats(logs, current_score):
    bonus_score = 0
    triggered_mitre = []
    
    log_string = str(logs).lower()
    
    # 1. LOLBin & Scriptlet Remote Delivery (T1218.010)
    if "regsvr32.exe" in log_string and ("/i:http" in log_string or "scrobj.dll" in log_string):
        bonus_score += 75
        triggered_mitre.append("T1218.010 - Regsvr32 Signed Binary Execution")
        
    # 2. Alternate Data Stream Persistence (T1564.004)
    if (":evil.js" in log_string or "text:" in log_string) and "eventid\": 11" in log_string:
        bonus_score += 45
        triggered_mitre.append("T1564.004 - NTFS Alternate Data Streams")

    # 3. Log Clearing / Defense Evasion (T1070.001)
    if "wevtutil.exe" in log_string and "cl " in log_string:
        bonus_score += 80
        triggered_mitre.append("T1070.001 - Clear Windows Event Logs")

    # 4. Network Tunneling via Protocol Abuse (T1048 / T1095)
    entropy_match = re.search(r"entropy[^>]*>\s*([0-9.]+)", log_string)
    if entropy_match:
        entropy_val = float(entropy_match.group(1))
        if entropy_val > 7.0 and "icmp" in log_string:
            bonus_score += 85
            triggered_mitre.append("T1095 - Non-Application Layer Protocol (ICMP Tunneling)")

    # Normalize output so the max cap is 100
    final_score = min(100, current_score + bonus_score)
    return final_score, list(set(triggered_mitre))

print("✅ Behavioral rules engine patch generated successfully.")
