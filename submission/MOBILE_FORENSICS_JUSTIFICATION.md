# Mobile Forensics Justification — NEXUS-IR
## Find Evil! Hackathon — SANS Institute 2026

---

## Why Android/Termux?

NEXUS-IR is intentionally designed for mobile deployment as a **field-deployable
IR triage tool**. This is not a limitation — it is an architectural choice thataddresses real operational gaps in incident response.

### Operational Advantages

1.  **Offline-Capable Triage**: Works when SaaS/cloud tools are unavailable due to network segmentation during active incidents.
2.  **Sub-Minute Time-to-Decision**: Cold start <1.2s enables correct containment decisions before specialist IR teams arrive.
3.  **Zero Cloud Dependency**: No data leaves the device. Critical for healthcare, government, and air-gapped environments.
4.  **Forensic Defensibility**: Cryptographic determinism proof eliminates AI hallucination skepticism during high-stress incidents.
5.  **Chain of Custody at Point of Collection**: Evidence hashing occurs at load time, before any analysis, preserving legal admissibility.

### Resource Constraints as Design Drivers

Android's memory and thermal constraints forced disciplined engineering:
- 7 specialized agents instead of one monolithic LLM call
- LangGraph state isolation verified under concurrent execution
- Thermal throttling characterized and documented, not hidden
- All guardrails implemented in code, not prompts

These constraints produced a more robust, auditable system than unconstrained cloud development would have.
