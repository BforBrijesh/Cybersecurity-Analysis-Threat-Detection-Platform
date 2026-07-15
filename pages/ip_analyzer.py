"""
IP Address Analyzer — Full threat intelligence page
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from engine.ip_engine import analyze_ip
from database.db import save_ip_scan, get_recent_scans

SEV_COLORS = {"Critical":"#ef4444","High":"#f97316","Medium":"#eab308","Low":"#22c55e","Info":"#3b82f6"}
SEV_BG     = {"Critical":"alert-critical","High":"alert-high","Medium":"alert-medium","Low":"alert-safe","Info":"alert-info"}

SAMPLE_IPS = [
    ("8.8.8.8",        "Google DNS",        "🟢 Safe"),
    ("1.1.1.1",        "Cloudflare DNS",    "🟢 Safe"),
    ("185.220.101.1",  "Tor Exit Node",     "🔴 Critical"),
    ("45.142.212.100", "Malicious Hosting", "🟠 High"),
    ("192.168.1.1",    "Private LAN IP",    "🔵 Info"),
    ("94.102.49.190",  "Suspicious Host",   "🟠 High"),
]

# Known dangerous port info
PORT_REFERENCE = {
    21:    ("FTP",         "Transmits credentials in plaintext. Easily sniffed."),
    22:    ("SSH",         "Secure if key-based. Brute-force target if password auth."),
    23:    ("Telnet",      "Completely insecure. Disable immediately."),
    25:    ("SMTP",        "Email server. Check for open relay abuse."),
    80:    ("HTTP",        "Unencrypted web. Redirect to HTTPS."),
    443:   ("HTTPS",       "Encrypted web traffic. Ensure TLS 1.2+."),
    445:   ("SMB",         "EternalBlue exploit target. Ransomware vector."),
    1433:  ("MSSQL",       "Database exposed publicly. Critical risk."),
    3306:  ("MySQL",       "Database exposed publicly. Should be localhost only."),
    3389:  ("RDP",         "Remote Desktop. Top ransomware attack vector."),
    5432:  ("PostgreSQL",  "Database exposed publicly."),
    5900:  ("VNC",         "Remote access. Often no auth. Critical."),
    6379:  ("Redis",       "Usually no auth by default. Data theft risk."),
    8080:  ("HTTP-Alt",    "Proxy / dev server. May expose sensitive services."),
    27017: ("MongoDB",     "Common exposed NoSQL DB. Data breach source."),
}


def render():
    st.markdown("""
    <div class='page-header'>
        <span class='page-header-icon'>🔍</span>
        <div>
            <div class='page-header-title'>IP Address Analyzer</div>
            <div class='page-header-sub'>Threat Intelligence · Geo-location · Tor/VPN/Proxy Detection · Port Scanner · Reputation Scoring</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── What this tool does ───────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    for col, icon, title, desc in [
        (c1, "🌍", "Geo-location",   "Maps IP to country, city, region and ISP/ASN using live geo-lookup API."),
        (c2, "🧅", "Tor Detection",  "Checks against known Tor exit node fingerprints. Tor hides attacker identity."),
        (c3, "🔒", "VPN/Proxy",      "Identifies datacenter IPs, hosting providers, VPN ranges, and open proxies."),
        (c4, "🔌", "Port Scanner",   "TCP connect scan on 15 known dangerous ports to detect attack surface."),
    ]:
        col.markdown(f"""
        <div class='feature-card'>
            <div style='font-size:1.8rem;'>{icon}</div>
            <h4>{title}</h4>
            <p>{desc}</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    tab_scan, tab_ref, tab_history = st.tabs([
        "🔍  Analyze IP", "📚  IP Threat Reference", "📋  Scan History"
    ])

    # ══════════════════════════════════════════════════════════════════════════
    #  TAB 1 — SCAN
    # ══════════════════════════════════════════════════════════════════════════
    with tab_scan:
        st.markdown("<br>", unsafe_allow_html=True)
        form_col, guide_col = st.columns([3, 2])

        with form_col:
            st.markdown('<div class="section-title">Enter an IP Address</div>', unsafe_allow_html=True)

            with st.form("ip_scan_form", clear_on_submit=False):
                ip_input = st.text_input(
                    "IP Address",
                    placeholder="e.g.  185.220.101.1   or   45.142.212.100",
                    label_visibility="collapsed",
                )
                do_ports = st.checkbox(
                    "🔌 Enable port scan  (checks 15 dangerous ports — adds ~15–30 seconds)",
                    value=False,
                )
                analyze_btn = st.form_submit_button(
                    "🔍  Analyze IP Address", type="primary", use_container_width=True
                )

            # Sample IPs grid
            st.markdown("**Or try a sample IP:**")
            row1 = st.columns(3)
            row2 = st.columns(3)
            for i, (ip, label, badge) in enumerate(SAMPLE_IPS):
                col = row1[i] if i < 3 else row2[i - 3]
                if col.button(f"{badge}  {ip}", key=f"ip_sample_{i}", use_container_width=True):
                    st.session_state["_ip_prefill"] = ip
                col.caption(label)

            # Prefill from sample button
            if st.session_state.get("_ip_prefill") and not ip_input:
                ip_input = st.session_state["_ip_prefill"]

        with guide_col:
            st.markdown('<div class="section-title">Threat Score Guide</div>', unsafe_allow_html=True)
            for icon, sev, rng, desc, clr in [
                ("🔴","Critical","70–100","Block immediately. Known malicious actor.","#ef4444"),
                ("🟠","High",    "40–69", "Strong threat indicators. Investigate now.","#f97316"),
                ("🟡","Medium",  "20–39", "Suspicious. Monitor this IP closely.","#eab308"),
                ("🟢","Low",     "0–19",  "No significant threat indicators.","#22c55e"),
                ("🔵","Info",    "—",     "Private/RFC1918 address. Internal only.","#3b82f6"),
            ]:
                st.markdown(f"""
                <div style='display:flex;align-items:center;gap:12px;padding:10px 0;
                            border-bottom:1px solid #f1f5f9;'>
                    <span style='font-size:1.2rem;'>{icon}</span>
                    <div style='flex:1;'>
                        <span style='font-size:1rem;font-weight:700;color:{clr};'>{sev}</span>
                        <span style='font-size:0.85rem;color:#94a3b8;margin-left:8px;'>{rng}</span>
                    </div>
                    <span style='font-size:0.88rem;color:#64748b;text-align:right;max-width:150px;'>{desc}</span>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown('<div class="section-title">What Affects Score</div>', unsafe_allow_html=True)
            factors = [
                ("🧅 Tor exit node",       "+50 pts"),
                ("🔀 Proxy/VPN detected",  "+20–30 pts"),
                ("📡 Suspicious IP range", "+25 pts"),
                ("🔌 Dangerous open port", "+15 pts each"),
                ("🏢 Datacenter ISP",      "+10–15 pts"),
                ("🏠 Private address",     "N/A (Info)"),
            ]
            for factor, pts in factors:
                st.markdown(f"""
                <div style='display:flex;justify-content:space-between;padding:7px 0;
                            border-bottom:1px solid #f8fafc;font-size:0.92rem;'>
                    <span style='color:#374151;'>{factor}</span>
                    <span style='font-weight:700;color:#2563eb;'>{pts}</span>
                </div>
                """, unsafe_allow_html=True)

        # ── RESULTS ───────────────────────────────────────────────────────────
        if analyze_btn and ip_input.strip():
            with st.spinner(f"Analyzing {ip_input.strip()} — geo lookup · threat intel · reverse DNS…"):
                result = analyze_ip(ip_input.strip(), do_port_scan=do_ports)

            # Do NOT save invalid results to DB, do NOT show result UI
            if result.get("severity") == "Invalid":
                st.error(result.get("indicators", "❌ Invalid input. Please enter a valid IP address."))
            else:
                save_ip_scan({
                    "ip": result["ip"], "country": result["country"],
                    "isp": result["isp"], "threat_score": result["threat_score"],
                    "is_tor": int(result["is_tor"]), "is_vpn": int(result["is_vpn"]),
                    "is_proxy": int(result["is_proxy"]), "open_ports": str(result["open_ports"]),
                    "severity": result["severity"], "details": result["details"],
                    "user_id": st.session_state.get("user", {}).get("id"),
                })

                st.divider()
                sev = result["severity"]
                color = SEV_COLORS.get(sev, "#64748b")
                css_cls = SEV_BG.get(sev, "alert-info")

                verdict_msgs = {
                    "Critical": "🔴 CRITICAL THREAT — This IP is highly malicious. Block all traffic immediately and investigate the source.",
                    "High":     "🟠 HIGH RISK — Strong threat indicators detected. Investigate and consider blocking.",
                    "Medium":   "🟡 SUSPICIOUS — Some threat indicators found. Monitor this IP closely.",
                    "Low":      "🟢 LOW RISK — No significant threat indicators. Appears to be a normal IP.",
                    "Info":     "🔵 PRIVATE IP — This is an internal/RFC1918 address (not routable on public internet).",
                }
                st.markdown(f'<div class="{css_cls}">{verdict_msgs.get(sev, "")}</div>',
                            unsafe_allow_html=True)

                st.markdown("<br>", unsafe_allow_html=True)

                # Metric row
                m1, m2, m3, m4, m5 = st.columns(5)
                m1.metric("IP Address",   result["ip"])
                m2.metric("Threat Score", f"{min(result['threat_score'],100)} / 100")
                m3.metric("Severity",     sev)
                m4.metric("Location",     (result["country"] or "Unknown")[:22])
                m5.metric("ISP",          (result["isp"] or "Unknown")[:22])

                st.markdown("<br>", unsafe_allow_html=True)

                gauge_col, ind_col, flag_col = st.columns([1, 2, 1])

                with gauge_col:
                    fig = go.Figure(go.Indicator(
                        mode="gauge+number",
                        value=min(result["threat_score"], 100),
                        title={"text": "Threat Score", "font": {"color": "#64748b", "size": 14}},
                        gauge={
                            "axis": {"range": [0, 100], "tickfont": {"size": 10}},
                            "bar":  {"color": color, "thickness": 0.28},
                            "steps": [
                                {"range": [0, 30],   "color": "#f0fdf4"},
                                {"range": [30, 60],  "color": "#fefce8"},
                                {"range": [60, 100], "color": "#fff1f2"},
                            ],
                            "threshold": {"line": {"color": "#ef4444", "width": 3},
                                          "thickness": 0.8, "value": 70},
                        },
                        number={"font": {"color": color, "size": 34}},
                    ))
                    fig.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)", height=240,
                        margin=dict(t=50, b=10, l=10, r=10),
                    )
                    st.plotly_chart(fig, use_container_width=True)

                with ind_col:
                    st.markdown('<div class="section-title">Threat Indicators</div>', unsafe_allow_html=True)
                    inds = result.get("indicators_list") or []
                    if not inds:
                        raw = result.get("indicators", "")
                        if isinstance(raw, list):
                            inds = raw
                        else:
                            inds = str(raw).split(" | ")
                    for ind in inds:
                        if ind.strip():
                            bg  = "#fff1f2" if "🔴" in ind else ("#fff7ed" if "⚠️" in ind else "#f0fdf4")
                            brd = "#fca5a5" if "🔴" in ind else ("#fdba74" if "⚠️" in ind else "#86efac")
                            st.markdown(f"""
                            <div style='background:{bg};border:1px solid {brd};border-radius:8px;
                                        padding:9px 14px;margin:5px 0;font-size:0.95rem;color:#1e293b;'>
                                {ind}
                            </div>
                            """, unsafe_allow_html=True)
                    if result.get("reverse_dns"):
                        st.markdown(f"**Reverse DNS:** `{result['reverse_dns']}`")
                    if result.get("open_ports") and result["open_ports"] != "[]":
                        st.markdown(f"**Open Ports:** `{result['open_ports']}`")

                with flag_col:
                    st.markdown('<div class="section-title">Network Flags</div>', unsafe_allow_html=True)
                    flag_items = []
                    if result.get("is_tor"):   flag_items.append(("🧅","Tor Node",   "#ef4444"))
                    if result.get("is_vpn"):   flag_items.append(("🔒","VPN/Host",   "#f97316"))
                    if result.get("is_proxy"): flag_items.append(("🔀","Proxy",      "#eab308"))
                    if result.get("private"):  flag_items.append(("🏠","Private IP", "#3b82f6"))
                    if flag_items:
                        for icon, label, clr in flag_items:
                            st.markdown(f"""
                            <div style='background:{clr}12;border:1px solid {clr}44;border-radius:10px;
                                        padding:12px;text-align:center;margin-bottom:8px;'>
                                <div style='font-size:1.6rem;'>{icon}</div>
                                <div style='font-size:0.9rem;font-weight:700;color:{clr};margin-top:4px;'>{label}</div>
                            </div>
                            """, unsafe_allow_html=True)
                    else:
                        st.markdown("""
                        <div style='background:#f0fdf4;border:1px solid #86efac;border-radius:10px;
                                    padding:12px;text-align:center;'>
                            <div style='font-size:1.6rem;'>✅</div>
                            <div style='font-size:0.9rem;font-weight:700;color:#15803d;margin-top:4px;'>No flags</div>
                        </div>
                        """, unsafe_allow_html=True)

        elif analyze_btn:
            st.warning("⚠️ Please enter an IP address.")

    # ══════════════════════════════════════════════════════════════════════════
    #  TAB 2 — REFERENCE
    # ══════════════════════════════════════════════════════════════════════════
    with tab_ref:
        st.markdown("<br>", unsafe_allow_html=True)

        ref1, ref2 = st.columns(2)

        with ref1:
            st.markdown('<div class="section-title">🔌 Dangerous Port Reference</div>', unsafe_allow_html=True)
            for port, (service, risk) in PORT_REFERENCE.items():
                sev_color = "#ef4444" if port in (23,445,3389,6379,27017) else \
                            "#f97316" if port in (21,1433,3306,5432,5900) else "#eab308"
                st.markdown(f"""
                <div style='display:flex;align-items:flex-start;gap:12px;padding:10px 0;
                            border-bottom:1px solid #f1f5f9;'>
                    <div style='background:{sev_color}18;border:1px solid {sev_color}44;
                                border-radius:8px;padding:4px 10px;min-width:52px;text-align:center;'>
                        <div style='font-size:1rem;font-weight:800;color:{sev_color};'>{port}</div>
                        <div style='font-size:0.7rem;font-weight:600;color:{sev_color};'>{service}</div>
                    </div>
                    <div style='font-size:0.9rem;color:#475569;line-height:1.5;padding-top:2px;'>{risk}</div>
                </div>
                """, unsafe_allow_html=True)

        with ref2:
            st.markdown('<div class="section-title">🌐 IP Address Types Explained</div>', unsafe_allow_html=True)
            ip_types = [
                ("Public IP",     "#2563eb", "Routable on the internet. Any device connecting from outside uses a public IP."),
                ("Private IP",    "#7c3aed", "RFC1918 ranges: 10.x, 172.16–31.x, 192.168.x. Not routable on public internet."),
                ("Tor Exit Node", "#ef4444", "Last hop in Tor network. Real user is anonymized behind multiple hops."),
                ("VPN IP",        "#f97316", "Traffic routed through a VPN provider. Hides true user location."),
                ("Proxy IP",      "#eab308", "Intermediary server. Common in attacks to hide true origin."),
                ("Datacenter IP", "#0891b2", "Hosted in AWS/Azure/DO/Vultr etc. Not residential. Often abused for attacks."),
                ("Residential IP","#22c55e", "Assigned to home/mobile users by ISPs. Harder to block without false positives."),
                ("Bogon IP",      "#94a3b8", "Unallocated/reserved IPs that should never appear in real traffic."),
            ]
            for name, clr, desc in ip_types:
                st.markdown(f"""
                <div style='padding:10px 0;border-bottom:1px solid #f1f5f9;'>
                    <span style='background:{clr}18;color:{clr};padding:3px 10px;border-radius:20px;
                                 font-size:0.82rem;font-weight:700;'>{name}</span>
                    <div style='font-size:0.9rem;color:#475569;margin-top:6px;line-height:1.5;'>{desc}</div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown('<div class="section-title">🛡️ What To Do With a Threat IP</div>', unsafe_allow_html=True)
            actions = [
                ("🔴 Critical", "Block at firewall immediately. File incident report. Check logs for past activity from this IP."),
                ("🟠 High",     "Add to watchlist. Block if not expected traffic. Alert security team."),
                ("🟡 Medium",   "Monitor access logs. Verify if IP is expected. Consider geo-blocking."),
                ("🟢 Low",      "No immediate action. Keep monitoring for pattern changes."),
            ]
            for badge, action in actions:
                st.markdown(f"""
                <div style='display:flex;gap:10px;align-items:flex-start;padding:9px 0;border-bottom:1px solid #f1f5f9;'>
                    <span style='font-size:0.9rem;font-weight:700;min-width:90px;'>{badge}</span>
                    <span style='font-size:0.9rem;color:#475569;'>{action}</span>
                </div>
                """, unsafe_allow_html=True)

    # ══════════════════════════════════════════════════════════════════════════
    #  TAB 3 — HISTORY
    # ══════════════════════════════════════════════════════════════════════════
    with tab_history:
        st.markdown("<br>", unsafe_allow_html=True)
        rows = get_recent_scans("ip_scans", limit=30, user_id=st.session_state.get("user", {}).get("id"))

        if rows:
            df = pd.DataFrame(rows)[[
                "ip","country","isp","threat_score","is_tor","is_vpn","is_proxy","severity","scanned_at"
            ]]
            df.columns = ["IP","Location","ISP","Score","Tor","VPN","Proxy","Severity","Scanned At"]
            df["Scanned At"] = df["Scanned At"].str[:16]
            st.dataframe(df, use_container_width=True, hide_index=True)

            # Score trend
            if len(df) >= 2:
                st.markdown('<div class="section-title">📈 Threat Score Trend</div>', unsafe_allow_html=True)
                fig2 = px.line(
                    df.iloc[::-1].reset_index(drop=True),
                    x="Scanned At", y="Score",
                    markers=True,
                    color_discrete_sequence=["#2563eb"],
                )
                fig2.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(248,250,252,0.8)",
                    height=220, margin=dict(t=10, b=10, l=10, r=10),
                    xaxis=dict(showgrid=False, color="#64748b"),
                    yaxis=dict(showgrid=True, gridcolor="#e2e8f0", range=[0,105]),
                )
                fig2.update_traces(line_width=2.5, marker_size=7)
                st.plotly_chart(fig2, use_container_width=True)

            # Severity pie
            st.markdown('<div class="section-title">📊 Severity Breakdown</div>', unsafe_allow_html=True)
            sev_counts = df["Severity"].value_counts().to_dict()
            if sev_counts:
                colors = [SEV_COLORS.get(s,"#94a3b8") for s in sev_counts.keys()]
                fig3 = go.Figure(go.Pie(
                    labels=list(sev_counts.keys()),
                    values=list(sev_counts.values()),
                    marker_colors=colors,
                    hole=0.55,
                    textinfo="label+percent+value",
                ))
                fig3.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", height=300,
                    margin=dict(t=10,b=10,l=10,r=10),
                    legend={"orientation":"h","y":-0.1},
                )
                st.plotly_chart(fig3, use_container_width=True)
        else:
            st.markdown('<div class="alert-info">ℹ️ No IP scans yet. Go to the Analyze IP tab to get started.</div>', unsafe_allow_html=True)
