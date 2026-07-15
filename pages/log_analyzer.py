"""
Log Analyzer — Full attack pattern detection + reference tools
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from engine.log_engine import analyze_logs
from database.db import save_log_scan, get_recent_scans

SAMPLE_LOG = """\
192.168.1.1 - - [24/Jun/2026:10:00:01 +0000] "GET /index.php HTTP/1.1" 200 1234
10.0.0.5 - - [24/Jun/2026:10:00:02 +0000] "GET /login HTTP/1.1" 200 456
185.220.101.1 - - [24/Jun/2026:10:00:03 +0000] "POST /login HTTP/1.1" 401 200
185.220.101.1 - - [24/Jun/2026:10:00:04 +0000] "POST /login HTTP/1.1" 401 200
185.220.101.1 - - [24/Jun/2026:10:00:05 +0000] "POST /login HTTP/1.1" 401 200
185.220.101.1 - - [24/Jun/2026:10:00:06 +0000] "POST /login HTTP/1.1" 401 200
185.220.101.1 - - [24/Jun/2026:10:00:07 +0000] "POST /login HTTP/1.1" 401 200
45.142.212.100 - - [24/Jun/2026:10:00:08 +0000] "GET /admin?cmd=ls HTTP/1.1" 403 150
45.142.212.100 - - [24/Jun/2026:10:00:09 +0000] "GET /../../etc/passwd HTTP/1.1" 404 120
45.142.212.100 - - [24/Jun/2026:10:00:10 +0000] "GET /?id=1' UNION SELECT username,password FROM users-- HTTP/1.1" 500 0
1.2.3.4 - - [24/Jun/2026:10:00:11 +0000] "GET /shell.php?exec=whoami HTTP/1.1" 200 32
6.6.6.6 - - [24/Jun/2026:10:00:12 +0000] "GET / HTTP/1.1" 200 5000 "sqlmap/1.7"
8.8.8.8 - - [24/Jun/2026:10:00:13 +0000] "GET /robots.txt HTTP/1.1" 200 90
192.168.1.1 - - [24/Jun/2026:10:00:14 +0000] "GET /about.html HTTP/1.1" 200 2345
45.142.212.100 - - [24/Jun/2026:10:00:15 +0000] "POST /wp-login.php HTTP/1.1" 403 120
77.88.55.66 - - [24/Jun/2026:10:00:16 +0000] "GET /page?search=<script>alert(1)</script> HTTP/1.1" 200 500
99.11.22.33 - - [24/Jun/2026:10:00:17 +0000] "GET /download?file=../../etc/shadow HTTP/1.1" 403 0
5.5.5.5 - - [24/Jun/2026:10:00:18 +0000] "GET / HTTP/1.1" 200 1000 "Nikto/2.1.6"
10.0.0.1 - - [24/Jun/2026:10:00:19 +0000] "GET /checkout HTTP/1.1" 200 3456
45.142.212.100 - - [24/Jun/2026:10:00:20 +0000] "GET /b374k.php HTTP/1.1" 200 12000
"""

ATTACK_COLORS = {
    "SQL Injection":      "#ef4444",
    "XSS Attempt":        "#f97316",
    "Path Traversal":     "#eab308",
    "Brute Force":        "#a855f7",
    "Web Shell":          "#dc2626",
    "Scanner/Bot":        "#0891b2",
    "Unauthorized Access":"#f59e0b",
    "Command Injection":  "#ec4899",
}

# Attack pattern reference data
ATTACK_REFERENCE = [
    ("💉", "SQL Injection", "#ef4444",
     "Injecting malicious SQL into input fields to read/modify database.",
     ["' OR 1=1--", "UNION SELECT", "DROP TABLE", "' AND SLEEP(5)"],
     "Use parameterized queries. Never concatenate user input into SQL."),
    ("📜", "Cross-Site Scripting (XSS)", "#f97316",
     "Injecting JavaScript into pages viewed by other users.",
     ["<script>alert(1)</script>", "onerror=alert(1)", "javascript:void(0)", "%3cscript%3e"],
     "Sanitize and encode all output. Use Content-Security-Policy headers."),
    ("📁", "Path Traversal", "#eab308",
     "Accessing files outside the web root by manipulating file paths.",
     ["../../etc/passwd", "%2e%2e%2f", "../etc/shadow", "....//"],
     "Validate and sanitize all file paths. Use allowlists, not blocklists."),
    ("🔑", "Brute Force", "#a855f7",
     "Repeated login attempts to guess passwords or API keys.",
     ["401 repeated from same IP", "POST /login x100+", "authentication failure"],
     "Rate limiting, CAPTCHA, account lockout, MFA."),
    ("🐚", "Web Shell Upload", "#dc2626",
     "Uploading malicious PHP/ASP scripts to execute OS commands.",
     ["c99.php", "r57.php", "b374k.php", "eval(base64_decode("],
     "Restrict upload file types. Disable script execution in upload dirs."),
    ("🤖", "Scanner / Bot", "#0891b2",
     "Automated tools probing for vulnerabilities across your endpoints.",
     ["sqlmap", "nikto", "nmap", "masscan", "nuclei", "dirbuster"],
     "WAF rules, rate limiting, bot detection, IP reputation blocking."),
    ("💻", "Command Injection", "#ec4899",
     "Injecting OS commands through vulnerable input fields.",
     ["; cat /etc/passwd", "| whoami", "`id`", "$(ls -la)"],
     "Never pass user input to shell commands. Use subprocess with args list."),
    ("🚫", "Unauthorized Access", "#f59e0b",
     "Attempts to access admin panels, APIs, or protected resources.",
     ["403 on /admin", "401 on /api/users", "Access denied errors in bulk"],
     "Proper authentication, authorization checks on every endpoint."),
]

HTTP_STATUS_GUIDE = [
    ("200", "OK",                   "#22c55e",  "Normal response. Check if response contains unexpected data."),
    ("301", "Moved Permanently",    "#3b82f6",  "Redirect. Verify redirect target is not controlled by attacker."),
    ("400", "Bad Request",          "#eab308",  "Malformed request. Could indicate injection or fuzzing attempts."),
    ("401", "Unauthorized",         "#f97316",  "Authentication required. Repeated = brute force attempt."),
    ("403", "Forbidden",            "#f97316",  "Access denied. Probe for sensitive resources."),
    ("404", "Not Found",            "#94a3b8",  "Resource missing. Many 404s = directory scanning / enumeration."),
    ("429", "Too Many Requests",    "#a855f7",  "Rate limit hit. Could be bot or DoS attempt."),
    ("500", "Internal Server Error","#ef4444",  "Server error. Could reveal stack traces. Common in SQLi attacks."),
    ("502", "Bad Gateway",          "#ef4444",  "Upstream failure. Could indicate DoS or misconfiguration."),
]


def render():
    st.markdown("""
    <div class='page-header'>
        <span class='page-header-icon'>📊</span>
        <div>
            <div class='page-header-title'>Log Analyzer</div>
            <div class='page-header-sub'>Detect SQL Injection · XSS · Brute Force · Web Shells · Scanners · Command Injection</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Feature cards
    c1, c2, c3, c4 = st.columns(4)
    for col, icon, title, desc in [
        (c1, "💉", "Injection Attacks",  "Detects SQL injection, XSS, command injection patterns in log entries."),
        (c2, "🤖", "Bots & Scanners",   "Identifies sqlmap, nikto, nmap, dirbuster, nuclei and other attack tools."),
        (c3, "🔑", "Brute Force",        "Spots repeated auth failures and credential stuffing attempts."),
        (c4, "🐚", "Web Shells",         "Finds known malicious shell filenames (c99, r57, b374k, eval(base64)."),
    ]:
        col.markdown(f"""
        <div class='feature-card'>
            <div style='font-size:1.8rem;'>{icon}</div>
            <h4>{title}</h4>
            <p>{desc}</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    tab_analyze, tab_attacks, tab_http, tab_history = st.tabs([
        "🔍  Analyze Logs", "📚  Attack Reference", "🚦  HTTP Status Guide", "📋  History"
    ])

    # ══════════════════════════════════════════════════════════════════════════
    #  TAB 1 — ANALYZE
    # ══════════════════════════════════════════════════════════════════════════
    with tab_analyze:
        st.markdown("<br>", unsafe_allow_html=True)

        input_tab1, input_tab2 = st.tabs(["📝 Paste Log Text", "📁 Upload Log File"])
        log_text = ""
        source_name = "pasted log"

        with input_tab1:
            col_load, col_info = st.columns([2, 3])
            with col_load:
                if st.button("📋 Load Sample Log (20 lines with 8 attack types)", use_container_width=True):
                    st.session_state["log_text_val"] = SAMPLE_LOG
                st.caption("Sample includes: SQL injection, XSS, path traversal, brute force, web shell, scanner")

            log_paste = st.text_area(
                "Log content",
                value=st.session_state.get("log_text_val", ""),
                height=260,
                placeholder="Paste Apache / Nginx access.log, auth.log, syslog, IIS log content here…\n\nFormat example:\n192.168.1.1 - - [date] \"GET /path HTTP/1.1\" 200 1234",
                label_visibility="collapsed",
            )
            if log_paste.strip():
                log_text = log_paste
                if log_paste != st.session_state.get("log_text_val", ""):
                    st.session_state["log_text_val"] = log_paste

        with input_tab2:
            uploaded = st.file_uploader(
                "Upload log file",
                type=["log", "txt", "csv"],
                help="Apache access.log, Nginx, auth.log, syslog, IIS W3C format",
            )
            if uploaded:
                log_text = uploaded.read().decode("utf-8", errors="replace")
                source_name = uploaded.name
                st.markdown(f'<div class="alert-safe">✅ Loaded: <b>{uploaded.name}</b> · {len(log_text.splitlines())} lines</div>',
                            unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        analyze_btn = st.button("🔍  Analyze Log File", type="primary", use_container_width=True)

        if analyze_btn:
            if not log_text.strip():
                st.warning("⚠️ Please paste or upload log content first.")
            else:
                line_count = len(log_text.splitlines())
                with st.spinner(f"Analyzing {line_count} log lines for attack patterns…"):
                    result = analyze_logs(log_text, source_name)

                # If invalid input — show error only, don't save, don't show scan UI
                if result.get("severity") == "Invalid":
                    st.error(result.get("summary", "❌ Invalid log content."))
                else:
                    save_log_scan({
                        "log_source":    result["log_source"],
                        "total_lines":   result["total_lines"],
                        "threats_found": result["threats_found"],
                        "severity":      result["severity"],
                        "summary":       result["summary"],
                        "user_id": st.session_state.get("user", {}).get("id"),
                    })

                    st.divider()
                    sev = result["severity"]
                    sev_msgs = {
                        "Critical": ("alert-critical", "🔴 CRITICAL — Active exploitation detected. Web shell or severe attack in progress. Investigate immediately."),
                        "High":     ("alert-high",     "🟠 HIGH RISK — Multiple attack types detected. Immediate investigation required. Consider blocking top attacker IPs."),
                        "Medium":   ("alert-medium",   "🟡 MEDIUM — Suspicious activity detected. Review findings and investigate suspicious IPs."),
                        "Low":      ("alert-safe",     "🟢 LOW RISK — Minimal threats found. Patterns look mostly normal."),
                    }
                    css, msg = sev_msgs.get(sev, ("alert-info", result.get("summary", "")))
                    st.markdown(f'<div class="{css}">{msg}</div>', unsafe_allow_html=True)

                    st.markdown("<br>", unsafe_allow_html=True)
                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("Lines Analyzed",  result["total_lines"])
                    m2.metric("Threats Found",   result["threats_found"])
                    m3.metric("Severity",        sev)
                    m4.metric("Attack Types",    len(result["attack_breakdown"]))

                    if result["attack_breakdown"]:
                        chart_col, detail_col = st.columns([2, 1])

                        with chart_col:
                            st.markdown('<div class="section-title">⚔️ Attack Type Breakdown</div>', unsafe_allow_html=True)
                            atk_df = pd.DataFrame(
                                list(result["attack_breakdown"].items()),
                                columns=["Attack Type", "Count"],
                            ).sort_values("Count", ascending=True)

                            fig = px.bar(atk_df, x="Count", y="Attack Type", orientation="h",
                                         color="Attack Type", color_discrete_map=ATTACK_COLORS, text="Count")
                            fig.update_layout(
                                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(248,250,252,0.8)",
                                showlegend=False, height=max(200, len(atk_df) * 52 + 60),
                                xaxis=dict(gridcolor="#e2e8f0", color="#64748b"),
                                yaxis=dict(color="#64748b"),
                                margin=dict(t=10, b=10, l=10, r=50),
                            )
                            fig.update_traces(textposition="outside", textfont_size=13)
                            st.plotly_chart(fig, use_container_width=True)

                        with detail_col:
                            if result["top_ips"]:
                                st.markdown('<div class="section-title">🌐 Top Attacker IPs</div>', unsafe_allow_html=True)
                                for ip, cnt in result["top_ips"][:8]:
                                    pct = min(100, int(cnt / max(result["total_lines"], 1) * 100))
                                    st.markdown(f"""
                                    <div style='margin:8px 0;'>
                                        <div style='display:flex;justify-content:space-between;
                                                    font-size:0.88rem;margin-bottom:3px;'>
                                            <code>{ip}</code>
                                            <span style='font-weight:700;color:#ef4444;'>{cnt}</span>
                                        </div>
                                        <div style='height:7px;background:#fee2e2;border-radius:4px;'>
                                            <div style='height:100%;width:{pct}%;background:#ef4444;border-radius:4px;'></div>
                                        </div>
                                    </div>
                                    """, unsafe_allow_html=True)

                    if result["status_alerts"]:
                        st.markdown('<div class="section-title">🚦 HTTP Status Code Alerts</div>', unsafe_allow_html=True)
                        sc_cols = st.columns(min(len(result["status_alerts"]), 5))
                        for i, (code, (cnt, desc)) in enumerate(result["status_alerts"].items()):
                            clr = "#ef4444" if code in ("401","403","500") else "#f97316"
                            sc_cols[i % 5].markdown(f"""
                            <div style='background:{clr}10;border:1px solid {clr}44;border-radius:12px;
                                        padding:14px;text-align:center;'>
                                <div style='font-size:1.8rem;font-weight:900;color:{clr};'>{code}</div>
                                <div style='font-size:0.82rem;color:#475569;margin-top:2px;'>{desc}</div>
                                <div style='font-size:1.2rem;font-weight:800;color:{clr};margin-top:6px;'>{cnt}×</div>
                            </div>
                            """, unsafe_allow_html=True)

                    if result["findings"]:
                        st.markdown("---")
                        st.markdown('<div class="section-title">📋 Detailed Threat Findings</div>', unsafe_allow_html=True)
                        st.caption(f"Showing first {min(len(result['findings']), 100)} findings")
                        findings_df = pd.DataFrame(result["findings"][:100])[["line_no","type","ip","snippet"]]
                        findings_df.columns = ["Line #","Attack Type","Source IP","Log Entry"]
                        st.dataframe(findings_df, use_container_width=True, hide_index=True)

    # ══════════════════════════════════════════════════════════════════════════
    #  TAB 2 — ATTACK REFERENCE
    # ══════════════════════════════════════════════════════════════════════════
    with tab_attacks:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="section-title">📚 Web Attack Patterns Reference</div>', unsafe_allow_html=True)
        st.caption("Learn to recognize each attack type in your log files.")

        for icon, name, clr, desc, examples, defense in ATTACK_REFERENCE:
            with st.expander(f"{icon}  {name}", expanded=False):
                ex_col, def_col = st.columns([1, 1])

                with ex_col:
                    st.markdown(f"""
                    <div style='background:{clr}0d;border:1px solid {clr}33;border-left:4px solid {clr};
                                border-radius:10px;padding:14px 16px;margin-bottom:10px;'>
                        <div style='font-size:1rem;font-weight:700;color:{clr};margin-bottom:6px;'>What it is</div>
                        <div style='font-size:0.95rem;color:#374151;line-height:1.6;'>{desc}</div>
                    </div>
                    """, unsafe_allow_html=True)
                    st.markdown("**Log signatures to look for:**")
                    for ex in examples:
                        st.markdown(f"""
                        <div style='background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;
                                    padding:6px 12px;margin:4px 0;font-family:monospace;
                                    font-size:0.88rem;color:#0f172a;'>{ex}</div>
                        """, unsafe_allow_html=True)

                with def_col:
                    st.markdown(f"""
                    <div style='background:#f0fdf4;border:1px solid #86efac;border-left:4px solid #22c55e;
                                border-radius:10px;padding:14px 16px;'>
                        <div style='font-size:1rem;font-weight:700;color:#15803d;margin-bottom:6px;'>🛡️ Defense</div>
                        <div style='font-size:0.95rem;color:#374151;line-height:1.6;'>{defense}</div>
                    </div>
                    """, unsafe_allow_html=True)

    # ══════════════════════════════════════════════════════════════════════════
    #  TAB 3 — HTTP STATUS GUIDE
    # ══════════════════════════════════════════════════════════════════════════
    with tab_http:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="section-title">🚦 HTTP Status Code Security Guide</div>', unsafe_allow_html=True)
        st.caption("What each HTTP status code means from a security perspective when seen in bulk.")

        for code, name, clr, meaning in HTTP_STATUS_GUIDE:
            st.markdown(f"""
            <div style='display:flex;align-items:flex-start;gap:16px;padding:12px 0;
                        border-bottom:1px solid #f1f5f9;'>
                <div style='background:{clr}18;border:1px solid {clr}44;border-radius:10px;
                            padding:6px 14px;text-align:center;min-width:60px;'>
                    <div style='font-size:1.3rem;font-weight:900;color:{clr};'>{code}</div>
                    <div style='font-size:0.72rem;font-weight:700;color:{clr};'>{name}</div>
                </div>
                <div style='font-size:0.95rem;color:#374151;line-height:1.6;padding-top:4px;'>{meaning}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="section-title">📖 Log Format Reference</div>', unsafe_allow_html=True)
        st.markdown("**Apache / Nginx Combined Log Format:**")
        st.code('127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/5.0"', language="text")
        st.markdown("""
        | Field | Description |
        |---|---|
        | `127.0.0.1` | Client IP address (attacker's IP) |
        | `frank` | Authenticated username (or `-` if anonymous) |
        | `[date/time]` | Timestamp of request |
        | `"GET /path HTTP/1.0"` | HTTP method, path, and protocol |
        | `200` | HTTP response status code |
        | `2326` | Response size in bytes |
        """)

        st.markdown("**Auth.log Format (Linux SSH):**")
        st.code("Jun 24 10:00:01 server sshd[1234]: Failed password for root from 185.220.101.1 port 22 ssh2", language="text")
        st.markdown("Look for: `Failed password`, `Invalid user`, `authentication failure` repeated from same IP = brute force.")

    # ══════════════════════════════════════════════════════════════════════════
    #  TAB 4 — HISTORY
    # ══════════════════════════════════════════════════════════════════════════
    with tab_history:
        st.markdown("<br>", unsafe_allow_html=True)
        rows = get_recent_scans("log_scans", limit=20, user_id=st.session_state.get("user", {}).get("id"))
        if rows:
            df2 = pd.DataFrame(rows)[["log_source","total_lines","threats_found","severity","scanned_at"]]
            df2.columns = ["Source","Lines Analyzed","Threats Found","Severity","Time"]
            df2["Time"] = df2["Time"].str[:16]
            st.dataframe(df2, use_container_width=True, hide_index=True)

            if len(df2) >= 2:
                st.markdown('<div class="section-title">📈 Threats Found Over Time</div>', unsafe_allow_html=True)
                fig_h = px.bar(df2.iloc[::-1], x="Time", y="Threats Found",
                               color="Severity",
                               color_discrete_map={"Critical":"#ef4444","High":"#f97316",
                                                   "Medium":"#eab308","Low":"#22c55e"})
                fig_h.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(248,250,252,0.8)",
                    height=240, margin=dict(t=10,b=10,l=10,r=10),
                    xaxis=dict(color="#64748b"), yaxis=dict(gridcolor="#e2e8f0"),
                )
                st.plotly_chart(fig_h, use_container_width=True)
        else:
            st.markdown('<div class="alert-info">ℹ️ No log analyses yet. Go to Analyze Logs tab to get started.</div>', unsafe_allow_html=True)
