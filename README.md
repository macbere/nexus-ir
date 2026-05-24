# NEXUS-IR — Autonomous Incident Response Agent

A forensic AI that takes a folder of logs and gives you a threat assessment, attack narrative, MITRE-mapped patterns, extracted IoCs, and containment actions. No human in the loop. Runs on an Android phone.

---

## Why I Built This

Here is the actual problem: a ransomware infection starts spreading at 2 AM. The on-call analyst gets paged. They open their laptop, VPN in, pull logs, try to figure out what they are looking at. Meanwhile the worm is moving laterally. By the time a specialist IR team arrives, it has been 45 minutes.

I wanted a tool that could do the first-pass triage in under 2 seconds. Not "here are some alerts" — I mean full kill-chain reconstruction, with the specific files and offsets that support each finding, and a recommended containment list.

The mobile constraint was intentional. IR happens in places where you do not have a workstation. Air-gapped ICS networks. Remote sites. Hospital floors. If this runs on a phone, it runs everywhere, and it runs offline, which matters when the network you are analyzing might be the network you are also depending on.

---

## What It Actually Does

7 agents run in a LangGraph state machine:

1. **TriageAgent** — discovers all processable files, SHA-256 hashes every one of them for chain of custody, keyword-scans for 25+ critical indicators, sets priority
2. **LogAgent** — regex-only IoC extraction (IPv4, SHA-256, MD5, base64, file paths, hostnames, usernames, process IDs, GrantedAccess hex values), auto-decodes base64 payloads through deflate/zlib/UTF-8/UTF-16LE
3. **DiskAgent** — malware drop zone detection, persistence path scanning, double-extension masquerade detection, LOLBIN filename matching
4. **MemoryAgent** — process injection signatures (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, Sysmon EventID 8/10), credential dumping indicators, suspicious parent-child process pairs
5. **NetworkAgent** — C2 beaconing patterns, DNS tunneling, ICMP covert channels, suspicious port detection, TLS certificate anomalies
6. **CorrelationAgent** — cross-references all 5 agent outputs, runs APT signature matching, Sysmon EventID chain detection (1+10+8 = confirmed injection), calculates threat score with temporal multipliers
7. **CorrectionAgent** — the devil advocate. Challenges its own output. Catches contradictions. Auto-remediates missing patterns. Feeds fixes back into the loop.

Ten case types tested: obfuscated malware, financial breach, APT kill chain, ransomware, brute force, LOLBIN invasion, defense blinding, ICMP tunneling, stealth evasion, insider threat.

Output for every run: JSON report, text report, PDF report. All findings traceable to specific artifact files with their SHA-256 hashes.

---

## Architecture

The design I kept coming back to was: what if the agent could catch its own mistakes?

Here is the loop:

    Triage > Log > Disk > Memory > Network > Correlation > Correction
       |
    [problems found?]
       /                   YES                NO
       |                  |
    Increment            Report    iteration
       |
    Correlation
    (re-run with fixed state)

The CorrectionAgent runs what I call a "devil advocate" pass. It looks at what CorrelationAgent concluded and asks: does this make sense given what TriageAgent found? Specific checks:

- If triage found PowerShell stealth keywords but POWERSHELL_OBFUSCATION is not in the patterns, that is a contradiction. Flag it, inject the missing pattern, set forced_reeval = True.
- If 0x1FFFFF GrantedAccess is in the IoCs but PROCESS_INJECTION is not in patterns, inject it.
- If high-signal signatures triggered but the score is below 85, boost it.

When forced_reeval is true, the LangGraph conditional edge routes back to Correlation instead of forward to Report. Max 3 iterations to prevent infinite loops. The injected patterns persist in state across iterations via injected_patterns: list in the NexusState TypedDict, so they survive the re-run.

This was the bug that took the longest to find. CorrectionAgent was injecting patterns into the correlation report dict, but CorrelationAgent on re-run was rebuilding everything from all_reports, which overwrote the fix. The solution was threading injected patterns through LangGraph state as a first-class field and re-applying them at the start of every Correlation node execution.

### Guardrails

The guardrails live in tools/mcp_server.py as Python code:

    FORBIDDEN_COMMANDS = ["rm", "dd", "shred", "wget", "curl", "ssh", "mkfs"]

This check runs before any command executes. The AI cannot override it with prompt manipulation because it is not in a prompt. It is a Python if-statement. There is no model output that makes "rm" in cmd.split()[0] return False.

IoC extraction is regex-only. No LLM guessing IPs, hashes, or paths. The threat narrative uses an LLM, but that is clearly labeled as inference. The hard forensic facts are deterministic.

### Android/Termux

Running on ARM64 inside Termux on an Android phone. Not a demo environment, that is the actual development and testing machine. Every agent has to work within ~2GB of available RAM after Android takes its cut.

The thermal throttling was annoying. Under 20 rapid-fire runs, execution time drifted from 0.4s to 0.7s. Took me a while to figure out it was just the ARM Cortex throttling its clock frequency, not a code problem. Cooldown test confirmed it: with 3-second gaps between runs, zero drift. In real usage you are cold-starting once per investigation, so this does not matter operationally. But I wanted to understand it, not just accept it.

---

## Proof It Works

I am not going to ask you to take my word for any of this.

Unit tests: 78/78 passing. Every agent tested independently plus end-to-end.

Stress tests: 63/63 across all 10 case types. Zero false positives (brute force stays HIGH, insider threat stays HIGH, neither gets escalated to CRITICAL).

Forensic verification: Ran 4 cases twice each, hashed the structured outputs, compared hashes across runs. Zero semantic drift.

    [STABLE] obfuscated_malware  hash: 0db5c92b5cd735e0
    [STABLE] financial_breach    hash: 0c096616feb0a75f
    [STABLE] apt_attack          hash: 0817d380ec38ff7c
    [STABLE] brute_force         hash: 347f8684ee8843e4
    VERDICT: FORENSICALLY RELIABLE -- zero semantic drift

Volumetric pressure test: 43/43 across all phases. Parallel speedup confirmed (3 concurrent investigations faster than 3x sequential).
Full details in submission/BENCHMARK_SUMMARY.md and submission/DETERMINISM_PROOF.md.

---

## Hackathon Criteria

### Autonomous Execution Quality (25pts)

The LangGraph loop is the answer here. The agent detects errors in its own output, fixes them, and decides whether to re-run or proceed. All of this happens without human intervention between input and output.

Concrete: run python3 main.py ~/cases/obfuscated_malware and watch the correction agent fire at timestamp [HH:MM:SS] D [CorrectionAgent] DEVIL ADVOCATE: PowerShell obfuscation missed! followed by * AUTO-FIX: Injected POWERSHELL_OBFUSCATION pattern. That is the loop working. The agent caught its own mistake.

The execution trace in every JSON report (execution_trace field) logs every node execution with timestamps and iteration counts. Judges can audit any finding back to the exact tool call that produced it.

### IR Accuracy (25pts)

64/64 forensic verification checks. Zero hallucinations on IoC extraction because IoCs are extracted by regex, not LLM. Every finding references the specific artifact file by path and SHA-256 hash prefix.

The determinism proof is in tests/verify_forensic.py. Run it. It will produce identical hash outputs on any machine with the same evidence files.

### Breadth and Depth of Analysis (25pts)

7 specialized agents. 10 MITRE ATT&CK techniques mapped. 10 case types covering the full range from script-kiddie brute force to multi-stage APT with process injection and LSASS credential dumping. The system handles JSON, CSV, log, evtx, XML, syslog, and pcap artifacts.

The SPL query catalog (submission/SPL_QUERY_CATALOG.md) has 9 validated queries mapped to specific MITRE techniques. These are generated from the same regex-verified IoCs that feed the analysis.

### Constraint Implementation (25pts)

tools/mcp_server.py contains the forbidden command list as Python code. agents/log_agent.py contains only static method regex functions for IoC extraction. There is no code path where an LLM output directly executes a command or identifies an IP address.

The SHA-256 chain of custody is in _hash_file() in every agent. It runs at load time, before analysis. The hash is stored in chain_of_custody[filepath] and embedded in finding[file_hash] for every finding that references that file.

---

## Demo Walkthrough

Prerequisites:

- Python 3.10+
- pip install langgraph langchain anthropic langchain-groq fpdf2 python-dotenv requests rich
- For LLM narrative generation: add GROQ_API_KEY=your_key to .env (free at console.groq.com). Without it, the system still works — it uses template-based narratives for the 3-sentence attack summary.

Clone and set up:

    git clone https://github.com/macbere/nexus-ir.git
    cd nexus-ir
    pip install -r requirements.txt

The fastest demo is the obfuscated malware case. It shows the full loop including devil advocate:
    python3 main.py ~/cases/obfuscated_malware

You will see the LangGraph nodes firing in sequence. Look for the devil advocate section:

    [HH:MM:SS] D [CorrectionAgent] DEVIL ADVOCATE: PowerShell obfuscation missed!
    [HH:MM:SS] * [CorrectionAgent] AUTO-FIX: Injected POWERSHELL_OBFUSCATION pattern

For the financial breach case, which shows all 7 agents finding different things:

    python3 main.py ~/cases/financial_breach

MemoryAgent will find lsass, golden ticket, mimikatz. NetworkAgent will find reverse shell, port 4444, data exfil. DiskAgent will find malware drop zones and malicious filenames. All of this feeds into CorrelationAgent as pseudo-keywords.

To run the full test suite:

    python3 tests/test_nexus.py 2>/dev/null
    python3 tests/stress_test.py 2>/dev/null
    python3 tests/verify_forensic.py 2>/dev/null

Reports land in reports/output/ as JSON, TXT, and PDF. The JSON has the full execution trace. The PDF is designed for handing to a non-technical stakeholder.

To test your own evidence: drop any logs, JSON, CSV, or EVTX files into a folder and point the tool at it:

    python3 main.py /path/to/your/case/folder

---

## Submission Artifacts

Four documents in submission/ that back up the claims in this README:

- BENCHMARK_SUMMARY.md — full stress test results with tables. Phase-by-phase breakdown of throughput, parallel speedup, burst drift analysis, and hackathon scoring alignment.
- DETERMINISM_PROOF.md — methodology for the cryptographic output verification, chain-of-custody file hashes for the obfuscated malware case, and the actual [STABLE] hash outputs from 2 independent runs.
- SPL_QUERY_CATALOG.md — 9 SPL queries mapped to MITRE techniques, including the before/after for the apt_attack query that was refactored from index=* to scoped index=wineventlog OR index=sysmon. Each query is validated against the test cases.
- MOBILE_FORENSICS_JUSTIFICATION.md — technical rationale for the Android/Termux deployment, including the scaling projection (same code, ~10x faster on server hardware), operational advantages for air-gapped and field environments, and a breakdown of how the memory constraints made the codebase better.

---

## Honest Limitations

Three stub agents exist in the codebase (disk_agent.py, memory_agent.py, network_agent.py) that are fully implemented but not integrated into the legacy orchestrator.py. They are wired into the LangGraph orchestrator but the old linear orchestrator still uses just 4 agents. If you use main.py (which uses LangGraph), you get all 7. If something routes through the fallback, you get 4.

The system handles text-exportable artifacts well. It does not parse raw binary memory dumps, PCAP files directly, or Windows registry hives. For those you would need a preprocessing step to extract the text representations first.

LLM narrative generation is optional and currently uses Groq free tier with llama-3.3-70b-versatile. Without an API key the attack narrative falls back to templates. The templates are decent but not as specific as the LLM output.

The PDF generator uses Courier because fpdf2 Unicode support with custom fonts requires font files I did not want to bundle. The PDFs are readable and professional but not beautiful.
With more time, I would build proper PCAP parsing into NetworkAgent, add a web UI for non-CLI users, implement proper LangGraph persistence so investigations can be paused and resumed, and add a Splunk HEC integration so the agent can query live data instead of just analyzing exported logs.

---

## Acknowledgments

SANS Institute for running Find Evil. The hackathon premise is exactly right — the gap between "something happened" and "we know what happened" is where defenders lose. Tools that close that gap faster matter.

The LangGraph team for documentation that actually explains state reducers. The fpdf2 maintainers for a library that works on ARM Android without modification.

And the Android thermal management system, which taught me more about ARM clock frequency scaling than I ever wanted to know.

---

*NEXUS-IR v4.5.0 — Find Evil! Hackathon, SANS Institute 2026*
*Built in Termux. Tested at 2 AM. Ships as-is.*
