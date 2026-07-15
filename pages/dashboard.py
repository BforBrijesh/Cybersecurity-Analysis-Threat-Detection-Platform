"""
Dashboard — Command center overview
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from database.db import get_dashboard_stats, get_recent_scans
from datetime import datetime

SEV_COLORS = {
    "Critical": "#ef4444",
    "High":     "#f97316",
    "Medium":   "#eab308",
    "Low":      "#22c55e",
    "Info":     "#3b82f6",
}


def _gauge(value, title, color="#2563eb"):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        title={"text": title, "font": {"color": "#64748b", "size": 13}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#94a3b8", "tickfont": {"size": 10}},
            "bar":  {"color": color, "thickness": 0.25},
            "bgcolor": "#f8fafc",
            "bordercolor": "#e2e8f0",
            "steps": [
                {"range": [0, 30],   "color": "#f0fdf4"},
                {"range": [30, 60],  "color": "#fefce8"},
                {"range": [60, 100], "color": "#fff1f2"},
            ],
            "threshold": {
                "line": {"color": "#ef4444", "width": 3},
                "thickness": 0.8, "value": 70,
            },
        },
        number={"font": {"color": color, "size": 28}, "suffix": "%"},
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        height=200, margin=dict(t=50, b=10, l=20, r=20),
    )
    return fig


def render():
    user = st.session_state.get("user", {})
    now  = datetime.now()
    hour = now.hour

    # Accurate time-based greeting
    if hour < 12:
        greeting = "Good Morning"
        greeting_emoji = "🌅"
    elif hour < 17:
        greeting = "Good Afternoon"
        greeting_emoji = "☀️"
    elif hour < 20:
        greeting = "Good Evening"
        greeting_emoji = "🌇"
    else:
        greeting = "Good Night"
        greeting_emoji = "🌙"

    # Full date and time display
    date_str = now.strftime("%A, %B %d %Y")
    time_str = now.strftime("%I:%M %p")   # e.g. 02:35 PM

    display_name = user.get('full_name') or user.get('username', 'Analyst')

    st.markdown(f"""
    <div class='page-header'>
        <span class='page-header-icon'>{greeting_emoji}</span>
        <div>
            <div class='page-header-title'>{greeting}, {display_name}! 👋</div>
            <div class='page-header-sub'>
                Security Operations Dashboard &nbsp;·&nbsp;
                📅 {date_str} &nbsp;·&nbsp;
                🕐 {time_str}
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    stats = get_dashboard_stats(user_id=st.session_state.get("user", {}).get("id"))
    total = sum([stats["ip_scans"], stats["phishing_scans"],
                 stats["url_scans"], stats["log_scans"], stats["vuln_scans"]])

    # ── KPI Row ───────────────────────────────────────────────────────────────
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    kpis = [
        (c1, total,                    "Total Scans",    "#2563eb"),
        (c2, stats["ip_scans"],        "IP Scans",       "#0891b2"),
        (c3, stats["phishing_scans"],  "Phishing Checks","#7c3aed"),
        (c4, stats["url_scans"],       "URL Scans",      "#059669"),
        (c5, stats["vuln_scans"],      "Vuln Scans",     "#d97706"),
        (c6, stats["critical_total"],  "Critical/High",  "#dc2626"),
    ]
    for col, val, label, color in kpis:
        col.markdown(f"""
        <div class='metric-card'>
            <div class='mc-value' style='color:{color};'>{val}</div>
            <div class='mc-label'>{label}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Gauges + Bar chart ────────────────────────────────────────────────────
    g1, g2, g3, chart_col = st.columns([1, 1, 1, 3])

    threat_pct = min(100, (stats["critical_total"] / max(total, 1)) * 300)
    phish_pct  = min(100, (stats["phishing_scans"]  / max(total, 1)) * 100)
    vuln_pct   = min(100, (stats["vuln_scans"]       / max(total, 1)) * 100)

    g1.plotly_chart(_gauge(threat_pct, "Threat Level",  "#ef4444"), use_container_width=True)
    g2.plotly_chart(_gauge(phish_pct,  "Phishing Load", "#7c3aed"), use_container_width=True)
    g3.plotly_chart(_gauge(vuln_pct,   "Vuln Coverage", "#f97316"), use_container_width=True)

    with chart_col:
        st.markdown('<div class="section-title">Scan Volume by Module</div>', unsafe_allow_html=True)
        bar_data = {
            "Module": ["IP Scans", "Phishing", "URLs", "Logs", "Vulns"],
            "Count":  [stats["ip_scans"], stats["phishing_scans"],
                       stats["url_scans"], stats["log_scans"], stats["vuln_scans"]],
            "Color":  ["#0891b2", "#7c3aed", "#059669", "#d97706", "#2563eb"],
        }
        fig = go.Figure()
        for i, (mod, cnt, clr) in enumerate(zip(bar_data["Module"], bar_data["Count"], bar_data["Color"])):
            fig.add_trace(go.Bar(
                x=[mod], y=[cnt], name=mod,
                marker_color=clr, showlegend=False,
                text=[cnt], textposition="outside",
                textfont={"size": 13, "color": "#1e293b"},
            ))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(248,250,252,0.8)",
            height=190, margin=dict(t=10, b=10, l=10, r=10),
            xaxis=dict(showgrid=False, color="#64748b"),
            yaxis=dict(showgrid=True, gridcolor="#e2e8f0", color="#64748b"),
            bargap=0.3,
        )
        st.plotly_chart(fig, use_container_width=True)

    # ── Recent tables ─────────────────────────────────────────────────────────
    st.markdown("---")
    left, right = st.columns(2)

    with left:
        st.markdown('<div class="section-title">🔍 Recent IP Scans</div>', unsafe_allow_html=True)
        rows = get_recent_scans("ip_scans", limit=8, user_id=st.session_state.get("user", {}).get("id"))
        if rows:
            df = pd.DataFrame(rows)[["ip", "country", "threat_score", "severity", "scanned_at"]]
            df.columns = ["IP Address", "Location", "Score", "Severity", "Time"]
            df["Time"] = df["Time"].str[:16]
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.markdown('<div class="alert-info">ℹ️ No IP scans yet. Go to <b>IP Analyzer</b> to start.</div>', unsafe_allow_html=True)

    with right:
        st.markdown('<div class="section-title">📧 Recent Phishing Checks</div>', unsafe_allow_html=True)
        rows2 = get_recent_scans("phishing_scans", limit=8, user_id=st.session_state.get("user", {}).get("id"))
        if rows2:
            df2 = pd.DataFrame(rows2)[["input_text", "score", "severity", "scanned_at"]]
            df2["input_text"] = df2["input_text"].str[:55] + "…"
            df2.columns = ["Message Preview", "Score", "Severity", "Time"]
            df2["Time"] = df2["Time"].str[:16]
            st.dataframe(df2, use_container_width=True, hide_index=True)
        else:
            st.markdown('<div class="alert-info">ℹ️ No phishing checks yet. Go to <b>Phishing Detector</b>.</div>', unsafe_allow_html=True)

    # ── Severity pie + URL table ───────────────────────────────────────────────
    st.markdown("---")
    pie_col, url_col = st.columns([1, 1])

    with pie_col:
        st.markdown('<div class="section-title">📊 Severity Distribution</div>', unsafe_allow_html=True)
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for table in ["ip_scans", "phishing_scans", "url_scans", "vuln_scans"]:
            for row in get_recent_scans(table, limit=200, user_id=st.session_state.get("user", {}).get("id")):
                s = row.get("severity", "Low")
                if s in sev_counts:
                    sev_counts[s] += 1

        if sum(sev_counts.values()) > 0:
            fig2 = go.Figure(go.Pie(
                labels=list(sev_counts.keys()),
                values=list(sev_counts.values()),
                marker_colors=[SEV_COLORS[s] for s in sev_counts],
                hole=0.55,
                textinfo="label+percent",
                textfont={"size": 13, "family": "Inter"},
                pull=[0.05 if s == "Critical" else 0 for s in sev_counts],
            ))
            fig2.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                height=300, margin=dict(t=10, b=10, l=10, r=10),
                legend={"font": {"size": 13, "family": "Inter"}, "orientation": "h",
                        "x": 0.5, "xanchor": "center", "y": -0.1},
            )
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.markdown('<div class="alert-info">ℹ️ Run some scans to see severity distribution.</div>', unsafe_allow_html=True)

    with url_col:
        st.markdown('<div class="section-title">🔗 Recent URL Scans</div>', unsafe_allow_html=True)
        urows = get_recent_scans("url_scans", limit=8, user_id=st.session_state.get("user", {}).get("id"))
        if urows:
            df3 = pd.DataFrame(urows)[["url", "domain", "score", "severity", "scanned_at"]]
            df3["url"] = df3["url"].str[:45] + "…"
            df3.columns = ["URL", "Domain", "Score", "Severity", "Time"]
            df3["Time"] = df3["Time"].str[:16]
            st.dataframe(df3, use_container_width=True, hide_index=True)
        else:
            st.markdown('<div class="alert-info">ℹ️ No URL scans yet. Go to <b>URL Scanner</b>.</div>', unsafe_allow_html=True)

    # ── Quick action guide ────────────────────────────────────────────────────
    if total == 0:
        st.markdown("---")
        st.markdown('<div class="section-title">🚀 Quick Start Guide</div>', unsafe_allow_html=True)
        qa1, qa2, qa3, qa4 = st.columns(4)
        steps = [
            (qa1, "1️⃣", "IP Analyzer", "Enter an IP like 185.220.101.1 to detect Tor, VPN, threat score"),
            (qa2, "2️⃣", "Phishing Detector", "Load the phishing sample and analyze it to see risk scoring"),
            (qa3, "3️⃣", "URL Scanner", "Scan a suspicious URL like paypa1-secure.tk/verify"),
            (qa4, "4️⃣", "Log Analyzer", "Load the sample log to detect SQL injection, brute force etc."),
        ]
        for col, num, title, desc in steps:
            col.markdown(f"""
            <div class='feature-card'>
                <div style='font-size:1.8rem;margin-bottom:6px;'>{num}</div>
                <h4>{title}</h4>
                <p>{desc}</p>
            </div>
            """, unsafe_allow_html=True)
