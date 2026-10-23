"""PDF incident report: everything a reader needs on paper - summary, the analyst's findings, every alert with
its MITRE ATT&CK technique, the proposed responses and the devices seen.

Uses fpdf2 with its built-in fonts, so characters outside Latin-1 are replaced.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime

from fpdf import FPDF

SEV_COLOURS = {"high": (198, 40, 40), "medium": (178, 106, 0), "low": (0, 131, 143), "info": (96, 125, 139)}
REPLACEMENTS = {"–": "-", "—": "-", "‘": "'", "’": "'", "“": '"', "”": '"',
                "…": "...", "→": "->", "•": "-", "⚠": "!", " ": " "}


def _t(text) -> str:
    text = str(text if text is not None else "")
    for a, b in REPLACEMENTS.items():
        text = text.replace(a, b)
    return text.encode("latin-1", "replace").decode("latin-1")


def _when(ts) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "-"


class _PDF(FPDF):
    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(120)
        self.cell(0, 6, _t(f"Network Traffic Monitor - incident report - page {self.page_no()}/{{nb}}"),
                  align="C")


def build_pdf(snapshot: dict, analysis: dict, responses: list[dict], source: str) -> bytes:
    """analysis: {"report": markdown text, "by": who wrote it}."""
    pdf = _PDF(format="A4")
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(True, margin=16)
    pdf.set_margins(16, 16, 16)
    pdf.add_page()
    width = pdf.w - pdf.l_margin - pdf.r_margin

    def heading(text, size=13):
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", size)
        pdf.set_text_color(20, 30, 45)
        pdf.multi_cell(width, 7, _t(text), new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(220)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + width, pdf.get_y())
        pdf.ln(2)

    def para(text, size=10, style="", colour=(30, 30, 30), indent=0):
        pdf.set_font("Helvetica", style, size)
        pdf.set_text_color(*colour)
        pdf.set_x(pdf.l_margin + indent)
        pdf.multi_cell(width - indent, 5, _t(text), align="L", new_x="LMARGIN", new_y="NEXT")

    # Title
    counts = snapshot.get("alert_counts", {})
    risk = "High" if counts.get("high") else "Medium" if counts.get("medium") else "Low"
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(20, 30, 45)
    pdf.cell(width, 10, "Network Security Incident Report", new_x="LMARGIN", new_y="NEXT")
    para(f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} - source: {source}", 9, colour=(100, 100, 100))
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*SEV_COLOURS.get(risk.lower(), (30, 30, 30)))
    pdf.cell(width, 8, _t(f"Overall risk: {risk}"), new_x="LMARGIN", new_y="NEXT")

    first = snapshot.get("last_ts", 0) - snapshot.get("duration", 0) if snapshot.get("last_ts") else None
    facts = [("Period", f"{_when(first)} to {_when(snapshot.get('last_ts'))}"),
             ("Traffic", f"{snapshot.get('packets', 0):,} packets, {snapshot.get('bytes', 0) / 1e6:.1f} MB"),
             ("Local devices", str(len(snapshot.get("devices", [])))),
             ("Alerts", ", ".join(f"{counts[s]} {s}" for s in ("high", "medium", "low", "info") if s in counts)
              or "none")]
    if snapshot.get("intel"):
        facts.append(("Threat intelligence", f"{snapshot['intel']['indicators']:,} indicators checked"))
    if snapshot.get("ml"):
        facts.append(("Machine learning", snapshot["ml"].get("state", "-")))
    for label, value in facts:
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(60)
        pdf.cell(42, 6, _t(label))
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(30)
        pdf.multi_cell(width - 42, 6, _t(value), new_x="LMARGIN", new_y="NEXT")

    # Analyst findings (markdown -> simple PDF formatting)
    heading(f"Analyst findings ({analysis.get('by', 'analyst')})")
    for raw in (analysis.get("report") or "No analysis available.").splitlines():
        line = raw.rstrip()
        if not line.strip():
            pdf.ln(1.5)
            continue
        clean = re.sub(r"\*\*(.+?)\*\*", r"\1", line).replace("`", "")
        h = re.match(r"^(#{1,4})\s+(.*)", clean)
        bullet = re.match(r"^(\s*)[-*]\s+(.*)", clean)
        if h:
            para(h.group(2), 12 if len(h.group(1)) <= 2 else 10.5, "B", (20, 30, 45))
        elif bullet:
            para("- " + bullet.group(2), 9.5, indent=4 + (4 if len(bullet.group(1)) >= 2 else 0))
        else:
            para(clean, 9.5)

    # Alerts table
    heading("Alerts")
    cols = [("Time", 30), ("Severity", 18), ("Type", 30), ("Source", 32), ("MITRE ATT&CK", width - 110)]
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_fill_color(240, 243, 246)
    pdf.set_text_color(60)
    for name, w in cols:
        pdf.cell(w, 6, _t(name), border=0, fill=True)
    pdf.ln()
    for a in sorted(snapshot.get("alerts", []), key=lambda x: x["ts"]):
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(30)
        pdf.cell(30, 5, _t(_when(a["ts"])[11:]))
        pdf.set_text_color(*SEV_COLOURS.get(a["severity"], (30, 30, 30)))
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.cell(18, 5, _t(a["severity"].upper()))
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(30)
        pdf.cell(30, 5, _t(a["kind"]))
        pdf.cell(32, 5, _t(a["source"][:20]))
        pdf.cell(width - 110, 5, _t(", ".join(m["id"] for m in a.get("mitre", [])) or "-"),
                 new_x="LMARGIN", new_y="NEXT")
        para(a["message"] + ("  [handled: " + (a.get("ack_note") or "yes") + "]" if a.get("acked") else ""),
             8, colour=(90, 90, 90), indent=4)
        pdf.ln(0.8)

    # MITRE techniques
    techniques = {}
    for a in snapshot.get("alerts", []):
        for m in a.get("mitre", []):
            techniques.setdefault(m["id"], m)
    if techniques:
        heading("MITRE ATT&CK techniques observed")
        uses = Counter(m["id"] for a in snapshot.get("alerts", []) for m in a.get("mitre", []))
        for tid, m in sorted(techniques.items()):
            para(f"{tid}  {m['name']}  ({m['tactic']}) - {uses[tid]} alert(s)", 9.5)
            para(m["url"], 8, colour=(31, 111, 235), indent=4)

    # Responses
    heading("Proposed responses")
    if not responses:
        para("No responses proposed.", 9.5)
    for r in responses:
        para(f"[{r['status'].upper()}] {r['title']}", 10, "B",
             (46, 125, 50) if r["status"] == "approved" else (90, 90, 90) if r["status"] == "dismissed" else (20, 30, 45))
        para(r["reason"], 8.5, colour=(90, 90, 90), indent=4)
        para("Router: " + r["commands"]["router"], 8.5, indent=4)
        pdf.ln(1)
    para("Nothing is applied automatically; approved rules must be reviewed and applied by a person.", 8,
         "I", (120, 120, 120))

    # Devices
    heading("Devices on the local network")
    for d in snapshot.get("devices", []):
        para(f"{d['ip']}   MAC {d.get('mac') or '-'}   first seen {_when(d['first_seen'])[11:]}   "
             f"{d['packets']:,} packets", 9)
    if snapshot.get("geo") and snapshot["geo"].get("attribution"):
        pdf.ln(3)
        para(snapshot["geo"]["attribution"], 7.5, colour=(130, 130, 130))
    return bytes(pdf.output())
