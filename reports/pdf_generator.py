import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from datetime import datetime, timezone
from fpdf import FPDF


class PDFReport(FPDF):
    """Custom FPDF subclass with header and footer."""

    def header(self):
        self.set_font('Courier', 'B', 9)
        self.set_text_color(180, 0, 0)
        self.cell(0, 6, 'NEXUS-IR -- AUTONOMOUS INCIDENT RESPONSE REPORT', align='C')
        self.set_text_color(0, 0, 0)
        self.ln(4)
        self.set_draw_color(180, 0, 0)
        self.set_line_width(0.4)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def footer(self):
        self.set_y(-12)
        self.set_font('Courier', 'I', 7)
        self.set_text_color(120, 120, 120)
        self.cell(0, 5,
            f'NEXUS-IR | Find Evil! Hackathon SANS 2026 | Page {self.page_no()} | Regex-only IoC extraction',
            align='C'
        )
        self.set_text_color(0, 0, 0)


class PDFReportGenerator:

    def __init__(self):
        self.name = "PDFReportGenerator"

    def _clean(self, text):
        """Replace unicode characters that Courier cannot encode."""
        replacements = {
            '—': '--',   # em dash
            '–': '-',    # en dash
            '’': "'",    # right single quote
            '‘': "'",    # left single quote
            '“': '"',    # left double quote
            '”': '"',    # right double quote
            '…': '...',  # ellipsis
            'é': 'e',    # e acute
            'à': 'a',    # a grave
        }
        text = str(text)
        for char, replacement in replacements.items():
            text = text.replace(char, replacement)
        # Final fallback: strip anything still outside latin-1
        return text.encode('latin-1', errors='replace').decode('latin-1')

    def _log(self, message):
        print(f'[{datetime.now().strftime("%H:%M:%S")}] # [{self.name}] {message}')

    def _section_header(self, pdf, title):
        """Red section divider with white text."""
        pdf.set_fill_color(180, 0, 0)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Courier", "B", 9)
        pdf.cell(0, 6, f"  {title}", fill=True, ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)

    def _row(self, pdf, label, value, label_w=52):
        """Two-column label: value row."""
        pdf.set_font("Courier", "B", 8)
        pdf.cell(label_w, 5, f"  {label}", ln=False)
        pdf.set_font("Courier", "", 8)
        val_str = self._clean(str(value)[:90])
        pdf.cell(0, 5, val_str, ln=True)

    def _body_text(self, pdf, text, indent=4):
        """Wrapped body text."""
        pdf.set_font("Courier", "", 8)
        pdf.set_x(10 + indent)
        pdf.multi_cell(0, 4.5, self._clean(str(text)[:500]), ln=True)
        pdf.set_x(10)

    def _badge(self, pdf, text, color):
        """Inline coloured badge (CRITICAL/HIGH/etc)."""
        r, g, b = {
            "CRITICAL": (180, 0, 0),
            "HIGH":     (200, 100, 0),
            "MEDIUM":   (180, 160, 0),
            "LOW":      (0, 140, 0),
        }.get(color, (80, 80, 80))
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Courier", "B", 8)
        pdf.cell(len(text) * 2.2 + 4, 5, f" {text} ", fill=True, ln=False)
        pdf.set_text_color(0, 0, 0)
        pdf.set_fill_color(255, 255, 255)

    def generate_pdf_report(self, final_report, output_path=None):
        es          = final_report.get("executive_summary", {})
        patterns    = final_report.get("attack_patterns", [])
        validated   = final_report.get("validated_findings", [])
        rejected    = final_report.get("rejected_findings", [])
        timeline    = final_report.get("timeline", [])
        ip_corr     = final_report.get("ip_correlations", [])
        session_id  = final_report.get("session_id", "UNKNOWN")
        duration    = final_report.get("duration_seconds", 0)
        narrative   = final_report.get("attack_narrative", "")
        containment = final_report.get("containment_actions", [])
        sequences   = final_report.get("temporal_sequences", [])
        entities    = final_report.get("extracted_entities", {})
        coc         = final_report.get("chain_of_custody", {})
        lg_iters    = final_report.get("langgraph_iterations", 1)
        auto_fixed  = es.get("auto_remediated", 0)
        version     = final_report.get("nexus_ir_version", "4.0.0")

        pdf = PDFReport()
        pdf.set_margins(10, 16, 10)
        pdf.set_auto_page_break(auto=True, margin=14)
        pdf.add_page()

        # ── COVER BLOCK ──────────────────────────────────────
        pdf.set_fill_color(20, 20, 20)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Courier", "B", 13)
        pdf.cell(0, 10, "  NEXUS-IR  |  Find Evil! SANS 2026", fill=True, ln=True)
        pdf.set_font("Courier", "", 8)
        pdf.set_fill_color(40, 40, 40)
        pdf.cell(0, 5,
            self._clean(f"  Session: {session_id}    Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}    Duration: {duration}s    Version: {version}"),
            fill=True, ln=True
        )
        pdf.set_text_color(0, 0, 0)
        pdf.ln(4)

        # ── EXECUTIVE SUMMARY ────────────────────────────────
        self._section_header(pdf, "EXECUTIVE SUMMARY")

        threat_level = es.get("threat_level", "UNKNOWN")
        threat_score = es.get("threat_score", 0)
        pdf.set_font("Courier", "", 8)
        pdf.cell(52, 5, "  Threat Level:", ln=False)
        self._badge(pdf, f"{threat_level}  {threat_score}/100", threat_level)
        pdf.ln(6)

        self._row(pdf, "Case Priority:",    es.get("case_priority", "?"))
        self._row(pdf, "Files Scanned:",    es.get("total_files_analyzed", 0))
        self._row(pdf, "Attack Patterns:",  es.get("attack_patterns_detected", 0))
        self._row(pdf, "IPs Identified:",   es.get("unique_ips_found", 0))
        self._row(pdf, "Findings Valid:",   es.get("findings_validated", 0))
        self._row(pdf, "Findings Rejected:",es.get("findings_rejected", 0))
        self._row(pdf, "Confidence:",       es.get("overall_confidence", "?"))
        self._row(pdf, "Auto-Remediated:",  f"{auto_fixed} pattern(s) injected by devil advocate")
        self._row(pdf, "LangGraph Iters:",  lg_iters)
        pdf.ln(3)

        # ── CHAIN OF CUSTODY ────────────────────────────────
        if coc:
            self._section_header(pdf, "CHAIN OF CUSTODY -- EVIDENCE INTEGRITY")
            for filepath, info in coc.items():
                fname = os.path.basename(filepath)
                self._row(pdf, "File:", fname)
                self._row(pdf, "SHA256:", str(info.get("sha256", "?"))[:64])
                self._row(pdf, "Size:", f"{info.get('size_bytes', 0)} bytes")
                self._row(pdf, "Hashed at:", str(info.get("timestamp", "?"))[:25])
                pdf.ln(2)

        # ── ATTACK NARRATIVE ────────────────────────────────
        if narrative:
            self._section_header(pdf, "ATTACK NARRATIVE -- KILL CHAIN SUMMARY")
            self._body_text(pdf, narrative)
            pdf.ln(2)

        # ── ATTACK PATTERNS ─────────────────────────────────
        self._section_header(pdf, "ATTACK PATTERNS DETECTED (MITRE ATT&CK MAPPED)")
        if patterns:
            for i, p in enumerate(patterns, 1):
                conf   = str(p.get("confidence", "?"))
                name   = str(p.get("pattern", "?"))
                fixed  = " [AUTO-FIXED]" if p.get("injected_by") else ""
                pdf.set_font("Courier", "B", 8)
                pdf.cell(0, 5, self._clean(f"  [{i}] {name}{fixed}"), ln=True)
                self._row(pdf, "    Confidence:", conf)
                self._row(pdf, "    MITRE:",      p.get("mitre_technique", "?"))
                self._row(pdf, "    Evidence:",   ", ".join(p.get("evidence_keywords", [])))
                desc = str(p.get("description", ""))
                if desc:
                    pdf.set_font("Courier", "I", 7)
                    pdf.set_x(14)
                    pdf.multi_cell(0, 4, self._clean(f"    {desc[:120]}"), ln=True)
                    pdf.set_x(10)
                pdf.ln(1)
        else:
            self._body_text(pdf, "No attack patterns detected.")
        pdf.ln(2)

        # ── TEMPORAL SEQUENCES ──────────────────────────────
        if sequences:
            self._section_header(pdf, "TEMPORAL ATTACK SEQUENCES")
            for i, seq in enumerate(sequences, 1):
                pdf.set_font("Courier", "B", 8)
                pdf.cell(0, 5, f"  [{i}] {seq.get('pattern','?')}", ln=True)
                self._row(pdf, "    MITRE:",  seq.get("mitre_technique", "?"))
                self._row(pdf, "    Detail:", seq.get("description", "?"))
                pdf.ln(1)
            pdf.ln(2)

        # ── EXTRACTED ENTITIES ──────────────────────────────
        self._section_header(pdf, "EXTRACTED ENTITIES (Regex-Verified IoCs)")
        if entities:
            for ioc_type, ioc_list in entities.items():
                if ioc_list:
                    pdf.set_font("Courier", "B", 8)
                    pdf.cell(0, 5, f"  {ioc_type.upper().replace('_', ' ')}:", ln=True)
                    pdf.set_font("Courier", "", 7)
                    for ioc in ioc_list[:20]:
                        pdf.cell(0, 4, f"    - {str(ioc)[:90]}", ln=True)
            pdf.ln(2)
        else:
            self._body_text(pdf, "No entities extracted.")
            pdf.ln(2)

        # ── IP CORRELATIONS ─────────────────────────────────
        self._section_header(pdf, "IP ADDRESS CORRELATIONS")
        if ip_corr:
            for ip in ip_corr:
                self._row(pdf, "  IP:", ip.get("ip", "?"))
                self._row(pdf, "  Significance:", ip.get("significance", "?"))
                desc = ip.get("description", "")
                if desc:
                    self._row(pdf, "  Detail:", desc[:80])
                pdf.ln(1)
        else:
            self._body_text(pdf, "No IP correlations found.")
        pdf.ln(2)

        # ── VALIDATED FINDINGS ──────────────────────────────
        self._section_header(pdf, "VALIDATED FINDINGS")
        vf = [f for f in validated if isinstance(f, dict) and f.get("finding")]
        if vf:
            for i, v in enumerate(vf, 1):
                f        = v.get("finding", {})
                artifact = f.get("artifact", f.get("file", "?"))
                conf     = v.get("confidence", 0)
                pdf.set_font("Courier", "B", 8)
                pdf.cell(0, 5, f"  [{i}] {f.get('type','?')}", ln=True)
                self._row(pdf, "    Agent:",      v.get("source_agent", "?"))
                self._row(pdf, "    Confidence:", f"{conf}%")
                self._row(pdf, "    Artifact:",   os.path.basename(str(artifact)))
                fh = f.get("file_hash", "")
                if fh:
                    self._row(pdf, "    Hash:",   str(fh)[:32] + "...")
                kw = f.get("keywords_matched", [])
                if kw:
                    self._row(pdf, "    Keywords:", ", ".join(kw)[:80])
                pdf.ln(1)
        else:
            self._body_text(pdf, "No detailed findings to display.")
        pdf.ln(2)

        # ── REJECTED FINDINGS ───────────────────────────────
        if rejected:
            self._section_header(pdf, "REJECTED / UNVERIFIABLE FINDINGS")
            for i, r in enumerate(rejected, 1):
                f = r.get("finding", {})
                pdf.set_font("Courier", "B", 8)
                pdf.cell(0, 5, f"  [{i}] {f.get('type','?')}", ln=True)
                self._row(pdf, "    Reason:", "; ".join(r.get("issues", [])))
                pdf.ln(1)
            pdf.ln(2)

        # ── TIMELINE ────────────────────────────────────────
        if timeline:
            self._section_header(pdf, "INVESTIGATION TIMELINE")
            for event in timeline[:30]:
                ts       = str(event.get("timestamp", "?"))[:19]
                artifact = os.path.basename(str(event.get("artifact", "?")))
                pdf.set_font("Courier", "", 7)
                pdf.cell(0, 4,
                    self._clean(f"  {ts}  |  {event.get('agent','?'):20}  |  {event.get('type','?'):30}  |  {artifact}"),
                    ln=True
                )
            pdf.ln(2)

        # ── CONTAINMENT ACTIONS ─────────────────────────────
        self._section_header(pdf, "RECOMMENDED CONTAINMENT ACTIONS")
        if containment:
            pdf.set_font("Courier", "", 8)
            for i, action in enumerate(containment, 1):
                pdf.cell(0, 5, self._clean(f"  [{str(i).zfill(2)}] {str(action)[:90]}"), ln=True)
        else:
            self._body_text(pdf, "No containment actions generated.")
        pdf.ln(3)

        # ── FOOTER BLOCK ────────────────────────────────────
        pdf.set_fill_color(20, 20, 20)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Courier", "I", 7)
        pdf.cell(0, 5,
            "  NEXUS-IR -- All IoCs regex-extracted. Zero LLM hallucination. All findings artifact-traceable.",
            fill=True, ln=True
        )
        pdf.set_text_color(0, 0, 0)

        # ── SAVE ────────────────────────────────────────────
        if not output_path:
            output_path = os.path.join(
                os.path.dirname(__file__),
                "output/report_" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S") + ".pdf"
            )
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        pdf.output(output_path)
        self._log(f"PDF report saved: {output_path}")
        return output_path
