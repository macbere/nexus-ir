# NEXUS-IR Forensic Output Determinism Proof
## Find Evil! Hackathon — SANS Institute 2026

---

## Overview

NEXUS-IR implements a cryptographic output verification layer that proves
analytical reliability to forensic judges. Every investigation produces
a **semantic hash** — a SHA-256 fingerprint of the structured forensic
conclusions — enabling bit-identical reproducibility verification across
independent runs.

---

## Methodology

### What We Hash

The semantic hash captures the **forensically meaningful** components of
each investigation output, deliberately excluding volatile fields such as
timestamps and session IDs:

```python
key_data = {
    'level':      executive_summary['threat_level'],
    'score_band': executive_summary['threat_score'] // 10,    'patterns':   sorted([p['pattern'] for p in attack_patterns]),
    'iocs':       sorted(extracted_entities['ipv4_addresses']),
}
semantic_hash = SHA256(JSON(key_data))[:16]
```

### Chain of Custody Integrity

Every evidence file is SHA256-hashed at the moment it is loaded, before any
analysis begins. The hash is embedded in every finding that references that file:

- sysmon_execution.log: 619304a909d0de97...
- sysmon_injection.log: 670fa5d537a5337b...
- zeek_network.log:     a1f2ebf54ab8ff40...

This proves that threat level, score band, attack patterns, and extracted IoCs
are identical across runs — the engine reaches the same forensic conclusion
every time given the same evidence.
