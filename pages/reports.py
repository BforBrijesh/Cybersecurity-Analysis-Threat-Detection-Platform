"""
Reports Page — Professional PDF security report generator.
"""

import streamlit as st
import io
from datetime import datetime
from database.db import get_all_scans_for_report, get_dashboard_stats


# Severity that should NOT appear in the report (invalid / bad input records)
_SKIP_SEVERITIES = {"Invalid", "invalid"}


def _clean(val: str, maxlen: int = 60) -> str:
    """Sanitize a string for safe display in PDF — strip HTML/JS, truncate."""
    import re
    if not val:
        return "—"
    val = str(val)
    # Remove HTML tags (e.g. <script>alert(1)</script>)
    val = re.sub(r'<[^>]+>', '', val)
    # Remove javascript: and data: URI schemes (XSS vectors)
    val = re.sub(r'(?i)javascript\s*:', '[removed]', val)
    val = re.sub(r'(?i)data\s*:', '[removed]', val)
    val = re.sub(r'(?i)vbscript\s*:', '[removed]', val)
    # Remove Python code artifacts
    if 'import streamlit' in val or 'def render' in val:
        return "[invalid input]"
    val = val.strip()
    if len(val) > maxlen:
        val = val[:maxlen - 1] + "…"
    return val or "—"


def _filter_rows(rows: list) -> list:
    """Remove rows with Invalid severity from report data."""
    return [r for r in rows if r.get("severity", "") not in _SKIP_SEVERITIES]


def _generate_pdf(data: dict, stats: dict) -> bytes:
    """Generate a clean, professional PDF security report."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table,
            TableStyle, HRFlowable, KeepTogether,
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

        W, H = A4
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=1.8*cm, leftMargin=1.8*cm,
            topMargin=1.8*cm,   bottomMargin=1.8*cm,
            title="CyberShield AI Security Report",
            author="CyberShield AI",
        )

        # ── Color palette ──────────────────────────────────────────────────
        C_NAVY    = colors.HexColor("#0f172a")
        C_BLUE    = colors.HexColor("#2563eb")
        C_RED     = colors.HexColor("#dc2626")
        C_ORANGE  = colors.HexColor("#f97316")
        C_YELLOW  = colors.HexColor("#ca8a04")
        C_GREEN   = colors.HexColor("#16a34a")
        C_GRAY    = colors.HexColor("#64748b")
        C_LIGHT   = colors.HexColor("#f8fafc")
        C_BORDER  = colors.HexColor("#e2e8f0")
        C_HDR_BG  = colors.HexColor("#1e293b")
        C_HDR_FG  = colors.white
        C_ROW_ALT = colors.HexColor("#f0f4ff")
        C_WHITE   = colors.white

        SEV_COLOR = {
            "Critical": C_RED,
            "High":     C_ORANGE,
            "Medium":   C_YELLOW,
            "Low":      C_GREEN,
            "Info":     C_BLUE,
        }

        # ── Styles ─────────────────────────────────────────────────────────
        styles = getSampleStyleSheet()

        s_title = ParagraphStyle(
            "ReportTitle",
            fontName="Helvetica-Bold",
            fontSize=26,
            textColor=C_NAVY,
            spaceAfter=4,
            alignment=TA_CENTER,
            leading=30,
        )
        s_subtitle = ParagraphStyle(
            "Subtitle",
            fontName="Helvetica",
            fontSize=12,
            textColor=C_GRAY,
            spaceAfter=2,
            alignment=TA_CENTER,
        )
        s_section = ParagraphStyle(
            "Section",
            fontName="Helvetica-Bold",
            fontSize=14,
            textColor=C_BLUE,
            spaceBefore=18,
            spaceAfter=6,
            leading=18,
        )
        s_body = ParagraphStyle(
            "Body",
            fontName="Helvetica",
            fontSize=9,
            textColor=C_NAVY,
            leading=13,
            spaceAfter=3,
        )
        s_caption = ParagraphStyle(
            "Caption",
            fontName="Helvetica-Oblique",
            fontSize=8,
            textColor=C_GRAY,
            spaceAfter=2,
            alignment=TA_CENTER,
        )
        s_footer = ParagraphStyle(
            "Footer",
            fontName="Helvetica",
            fontSize=7.5,
            textColor=C_GRAY,
            alignment=TA_CENTER,
        )

        # ── Table base style — now handled inside build_table ──────────────
        usable_w = W - 3.6*cm   # total usable width

        def build_table(headers: list, col_w: list, rows_list: list,
                        sev_col: int | None = None,
                        sev_values: list | None = None) -> Table:
            """
            headers    — column header strings
            col_w      — column widths list
            rows_list  — list of lists (already formatted strings)
            sev_col    — index of severity column (for color coding)
            sev_values — list of raw severity strings matching rows_list order
            """
            header_row = [Paragraph(f"<b>{h}</b>", ParagraphStyle(
                "TH", fontName="Helvetica-Bold", fontSize=8.5,
                textColor=C_HDR_FG, alignment=TA_LEFT, leading=11,
            )) for h in headers]
            table_data = [header_row] + rows_list

            # Build style
            style = [
                ("BACKGROUND",    (0, 0), (-1, 0),  C_HDR_BG),
                ("TEXTCOLOR",     (0, 0), (-1, 0),  C_HDR_FG),
                ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, 0),  8.5),
                ("BOTTOMPADDING", (0, 0), (-1, 0),  7),
                ("TOPPADDING",    (0, 0), (-1, 0),  7),
                ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE",      (0, 1), (-1, -1), 8),
                ("TOPPADDING",    (0, 1), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 7),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 7),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
                ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
                ("LINEBELOW",     (0, 0), (-1, 0),  1.2, C_BLUE),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("WORDWRAP",      (0, 0), (-1, -1), True),
            ]
            # Color-code severity column using pre-extracted sev_values
            if sev_col is not None and sev_values:
                for ri, sev in enumerate(sev_values, 1):
                    clr = SEV_COLOR.get(sev, C_GRAY)
                    style.append(("TEXTCOLOR", (sev_col, ri), (sev_col, ri), clr))
                    style.append(("FONTNAME",  (sev_col, ri), (sev_col, ri), "Helvetica-Bold"))

            t = Table(table_data, colWidths=col_w, repeatRows=1)
            t.setStyle(TableStyle(style))
            return t

        # ── Start building elements ─────────────────────────────────────────
        elements = []

        # ── Cover header ─────────────────────────────────────────────────
        elements.append(Spacer(1, 0.4*cm))
        elements.append(Paragraph("🛡️ CyberShield AI", s_title))
        elements.append(Paragraph("Security Assessment Report", s_subtitle))
        elements.append(Paragraph(
            f"Generated: {datetime.now().strftime('%B %d, %Y  %H:%M UTC')}",
            s_caption,
        ))
        elements.append(Spacer(1, 0.3*cm))
        elements.append(HRFlowable(
            width="100%", thickness=2, color=C_BLUE, spaceAfter=12
        ))
        elements.append(Paragraph(
            "KANAD S.H.I.E.L.D Cybersecurity Hackathon 2026  ·  Organised by Cyber Crime Branch",
            s_caption,
        ))
        elements.append(Spacer(1, 0.6*cm))

        # ── Executive Summary ─────────────────────────────────────────────
        elements.append(Paragraph("Executive Summary", s_section))

        total = sum([
            stats["ip_scans"], stats["phishing_scans"],
            stats["url_scans"], stats["log_scans"], stats["vuln_scans"],
        ])
        summary_rows = [
            ["Total Scans Performed",    str(total)],
            ["IP Address Scans",         str(stats["ip_scans"])],
            ["Phishing Analyses",        str(stats["phishing_scans"])],
            ["URL Scans",                str(stats["url_scans"])],
            ["Log Analyses",             str(stats["log_scans"])],
            ["Vulnerability Scans",      str(stats["vuln_scans"])],
            ["Critical / High Findings", str(stats["critical_total"])],
        ]
        summary_data = [["Metric", "Value"]] + summary_rows
        sum_t = Table(summary_data, colWidths=[12*cm, 5.4*cm])
        sum_style = [
            ("BACKGROUND",    (0, 0), (-1, 0),  C_HDR_BG),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_HDR_FG),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
            ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
            ("LINEBELOW",     (0, 0), (-1, 0),  1.2, C_BLUE),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            # Highlight critical/high row
            ("TEXTCOLOR",     (1, 7), (1, 7),   C_RED),
            ("FONTNAME",      (1, 7), (1, 7),   "Helvetica-Bold"),
        ]
        sum_t.setStyle(TableStyle(sum_style))
        elements.append(sum_t)
        elements.append(Spacer(1, 0.5*cm))

        # ── IP Scan Results ───────────────────────────────────────────────
        ip_rows = _filter_rows(data.get("ip_scans", []))
        if ip_rows:
            elements.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
            elements.append(Paragraph("IP Scan Results", s_section))
            headers = ["IP Address", "Location", "ISP", "Score", "Sev.", "Scanned At"]
            cw = [2.8*cm, 3.6*cm, 3.8*cm, 1.4*cm, 1.8*cm, 4.0*cm]
            rows = []
            sevs = []
            for r in ip_rows[:30]:
                rows.append([
                    _clean(r.get("ip",""), 20),
                    _clean(r.get("country",""), 26),
                    _clean(r.get("isp",""), 26),
                    str(min(r.get("threat_score", 0), 100)),
                    _clean(r.get("severity",""), 12),
                    _clean(r.get("scanned_at","")[:16], 20),
                ])
                sevs.append(r.get("severity",""))
            elements.append(build_table(headers, cw, rows, sev_col=4, sev_values=sevs))

        # ── Phishing Results ──────────────────────────────────────────────
        ph_rows = _filter_rows(data.get("phishing_scans", []))
        if ph_rows:
            elements.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
            elements.append(Paragraph("Phishing Analysis Results", s_section))
            headers = ["Score", "Sev.", "Verdict", "Scanned At"]
            cw = [1.6*cm, 1.8*cm, 10.4*cm, 3.6*cm]
            rows = []
            sevs = []
            for r in ph_rows[:30]:
                rows.append([
                    f"{r.get('score', 0):.1f}",
                    _clean(r.get("severity",""), 12),
                    _clean(r.get("verdict",""), 80),
                    _clean(r.get("scanned_at","")[:16], 20),
                ])
                sevs.append(r.get("severity",""))
            elements.append(build_table(headers, cw, rows, sev_col=1, sev_values=sevs))

        # ── URL Scan Results ──────────────────────────────────────────────
        url_rows = _filter_rows(data.get("url_scans", []))
        if url_rows:
            elements.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
            elements.append(Paragraph("URL Scan Results", s_section))
            headers = ["URL", "Domain", "Score", "Sev.", "Scanned At"]
            cw = [6.0*cm, 3.8*cm, 1.4*cm, 1.8*cm, 4.4*cm]
            rows = []
            sevs = []
            for r in url_rows[:30]:
                rows.append([
                    _clean(r.get("url",""), 50),
                    _clean(r.get("domain",""), 28),
                    f"{r.get('score', 0):.1f}",
                    _clean(r.get("severity",""), 12),
                    _clean(r.get("scanned_at","")[:16], 20),
                ])
                sevs.append(r.get("severity",""))
            elements.append(build_table(headers, cw, rows, sev_col=3, sev_values=sevs))

        # ── Log Analysis Results ──────────────────────────────────────────
        log_rows = _filter_rows(data.get("log_scans", []))
        if log_rows:
            elements.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
            elements.append(Paragraph("Log Analysis Results", s_section))
            headers = ["Log Source", "Lines", "Threats", "Sev.", "Scanned At"]
            cw = [4.6*cm, 1.6*cm, 2.0*cm, 1.8*cm, 7.4*cm]
            rows = []
            sevs = []
            for r in log_rows[:30]:
                rows.append([
                    _clean(r.get("log_source",""), 35),
                    str(r.get("total_lines", 0)),
                    str(r.get("threats_found", 0)),
                    _clean(r.get("severity",""), 12),
                    _clean(r.get("scanned_at","")[:16], 20),
                ])
                sevs.append(r.get("severity",""))
            elements.append(build_table(headers, cw, rows, sev_col=3, sev_values=sevs))

        # ── Vulnerability Scan Results ────────────────────────────────────
        vuln_rows = _filter_rows(data.get("vuln_scans", []))
        if vuln_rows:
            elements.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
            elements.append(Paragraph("Vulnerability Scan Results", s_section))
            headers = ["Target", "Scan Type", "Issues", "Sev.", "Scanned At"]
            cw = [6.4*cm, 2.0*cm, 1.6*cm, 1.8*cm, 5.6*cm]
            rows = []
            sevs = []
            for r in vuln_rows[:30]:
                rows.append([
                    _clean(r.get("target",""), 52),
                    _clean(r.get("scan_type",""), 10),
                    str(r.get("vulns_found", 0)),
                    _clean(r.get("severity",""), 12),
                    _clean(r.get("scanned_at","")[:16], 20),
                ])
                sevs.append(r.get("severity",""))
            elements.append(build_table(headers, cw, rows, sev_col=3, sev_values=sevs))

        # ── Footer ────────────────────────────────────────────────────────
        elements.append(Spacer(1, 1.2*cm))
        elements.append(HRFlowable(width="100%", thickness=1, color=C_BLUE))
        elements.append(Spacer(1, 0.2*cm))
        elements.append(Paragraph(
            "CyberShield AI — Confidential Security Assessment Report  |  "
            "For authorized use only  |  "
            "KANAD S.H.I.E.L.D Hackathon 2026",
            s_footer,
        ))

        doc.build(elements)
        return buffer.getvalue()

    except ImportError:
        return b""
    except Exception as e:
        # Re-raise so the UI can show the real error message
        raise


def render():
    st.markdown("""
    <div class='page-header'>
        <span class='page-header-icon'>📄</span>
        <div>
            <div class='page-header-title'>Security Reports</div>
            <div class='page-header-sub'>Generate professional PDF audit reports from all scan data</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    stats = get_dashboard_stats(user_id=st.session_state.get("user", {}).get("id"))
    data  = get_all_scans_for_report(user_id=st.session_state.get("user", {}).get("id"))
    total = sum([stats["ip_scans"], stats["phishing_scans"],
                 stats["url_scans"], stats["log_scans"], stats["vuln_scans"]])

    # Stats cards
    c1, c2, c3, c4, c5 = st.columns(5)
    kpis = [
        (c1, stats["ip_scans"],        "IP Scans",        "#0891b2"),
        (c2, stats["phishing_scans"],  "Phishing Checks", "#7c3aed"),
        (c3, stats["url_scans"],       "URL Scans",        "#059669"),
        (c4, stats["log_scans"],       "Log Analyses",     "#d97706"),
        (c5, stats["critical_total"],  "Critical/High",    "#dc2626"),
    ]
    for col, val, label, color in kpis:
        col.markdown(f"""
        <div class='metric-card'>
            <div class='mc-value' style='color:{color};'>{val}</div>
            <div class='mc-label'>{label}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    if total == 0:
        st.markdown("""
        <div class='alert-info'>
            ℹ️ <strong>No scan data yet.</strong>
            Run some scans first (IP Analyzer, Phishing Detector, URL Scanner, etc.)
            then come back here to generate your report.
        </div>
        """, unsafe_allow_html=True)
        return

    st.markdown("---")
    form_col, preview_col = st.columns([1, 1])

    with form_col:
        st.markdown('<div class="section-title">📋 Report Configuration</div>', unsafe_allow_html=True)

        report_title = st.text_input("Report Title", value="CyberShield AI Security Assessment")
        org_name     = st.text_input("Organization", value="KANAD S.H.I.E.L.D Hackathon 2026")

        include_sections = st.multiselect(
            "Include Sections",
            ["IP Scans", "Phishing Analysis", "URL Scans", "Log Analysis", "Vulnerability Scans"],
            default=["IP Scans", "Phishing Analysis", "URL Scans", "Log Analysis", "Vulnerability Scans"],
        )

        gen_btn = st.button("📄 Generate PDF Report", type="primary", use_container_width=True)

    with preview_col:
        st.markdown('<div class="section-title">📊 Report Will Include</div>', unsafe_allow_html=True)

        # Count only valid (non-Invalid) records
        from database.db import get_recent_scans
        valid_ip    = len(_filter_rows(data.get("ip_scans", [])))
        valid_ph    = len(_filter_rows(data.get("phishing_scans", [])))
        valid_url   = len(_filter_rows(data.get("url_scans", [])))
        valid_log   = len(_filter_rows(data.get("log_scans", [])))
        valid_vuln  = len(_filter_rows(data.get("vuln_scans", [])))

        items = [
            ("🔍", f"{valid_ip} valid IP scan records",          valid_ip > 0),
            ("📧", f"{valid_ph} valid phishing analyses",         valid_ph > 0),
            ("🔗", f"{valid_url} valid URL scan records",         valid_url > 0),
            ("📊", f"{valid_log} valid log analysis records",     valid_log > 0),
            ("🛡️", f"{valid_vuln} valid vulnerability scans",     valid_vuln > 0),
            ("🔴", f"{stats['critical_total']} critical/high findings", stats["critical_total"] > 0),
        ]
        for icon, label, has_data in items:
            status = "✅" if has_data else "⬜"
            color = "#1e293b" if has_data else "#94a3b8"
            st.markdown(f"""
            <div style='display:flex;gap:10px;align-items:center;padding:7px 0;
                        border-bottom:1px solid #f8fafc;'>
                <span>{status}</span>
                <span style='font-size:1rem;color:{color};'>{icon} {label}</span>
            </div>
            """, unsafe_allow_html=True)

        # Note about filtered records
        skipped = (stats["ip_scans"] - valid_ip + stats["phishing_scans"] - valid_ph +
                   stats["url_scans"] - valid_url + stats["log_scans"] - valid_log +
                   stats["vuln_scans"] - valid_vuln)
        if skipped > 0:
            st.caption(f"ℹ️ {skipped} invalid/error records excluded from report automatically.")

    if gen_btn:
        with st.spinner("📄 Generating PDF report…"):
            try:
                pdf_bytes = _generate_pdf(data, stats)
            except Exception as e:
                st.error(f"PDF generation error: {e}")
                import traceback
                st.code(traceback.format_exc(), language="text")
                pdf_bytes = b""

        if pdf_bytes:
            filename = f"cybershield_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            st.markdown('<div class="alert-safe">✅ PDF report generated successfully!</div>', unsafe_allow_html=True)
            st.download_button(
                label="⬇️ Download PDF Report",
                data=pdf_bytes,
                file_name=filename,
                mime="application/pdf",
                use_container_width=True,
            )
        else:
            st.error("PDF generation failed. Install reportlab: `py -3.11 -m pip install reportlab`")
            st.markdown("**CSV Export (fallback):**")
            import pandas as pd
            dl_cols = st.columns(len(data))
            for i, (key, rows) in enumerate(data.items()):
                clean_rows = _filter_rows(rows)
                if clean_rows:
                    df = pd.DataFrame(clean_rows)
                    csv = df.to_csv(index=False).encode()
                    dl_cols[i % len(data)].download_button(
                        f"⬇️ {key}.csv", data=csv,
                        file_name=f"{key}.csv", mime="text/csv", key=f"csv_{key}",
                    )

    # Data previews — only show valid records
    st.markdown("---")
    st.markdown('<div class="section-title">👁️ Data Preview (valid records only)</div>', unsafe_allow_html=True)
    preview_tabs = st.tabs(["IP Scans", "Phishing", "URLs", "Logs", "Vulns"])
    tables_keys = ["ip_scans", "phishing_scans", "url_scans", "log_scans", "vuln_scans"]
    for tab, key in zip(preview_tabs, tables_keys):
        with tab:
            rows = _filter_rows(data.get(key, []))
            if rows:
                import pandas as pd
                df = pd.DataFrame(rows).drop(columns=["id"], errors="ignore")
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.info(f"No valid {key.replace('_',' ')} data yet.")
