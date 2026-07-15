"""
Vulnerability Scanner Page
"""

import streamlit as st
import plotly.express as px
import pandas as pd
from engine.vuln_engine import scan_target
from database.db import save_vuln_scan, get_recent_scans

SEV_COLORS = {"Critical":"#ef4444","High":"#f97316","Medium":"#eab308","Low":"#22c55e","Info":"#3b82f6"}
SEV_BG     = {"Critical":"alert-critical","High":"alert-high","Medium":"alert-medium","Low":"alert-safe"}


def render():
    st.markdown("""
    <div class='page-header'>
        <span class='page-header-icon'>🛡️</span>
        <div>
            <div class='page-header-title'>Vulnerability Scanner</div>
            <div class='page-header-sub'>Security headers · Exposed files · Port scanning · Misconfigurations</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Ethics notice
    st.markdown("""
    <div class='alert-medium'>
        ⚖️ <strong>Ethical Use Notice:</strong> Only scan systems you own or have explicit written
        permission to test. Unauthorized scanning may violate the IT Act 2000 and other applicable laws.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Feature cards
    c1, c2, c3, c4 = st.columns(4)
    for col, icon, title, desc in [
        (c1, "🔒", "Security Headers",  "HSTS, CSP, X-Frame, CORS checks"),
        (c2, "📂", "Sensitive Files",   ".env, .git, wp-config exposure"),
        (c3, "🔌", "Port Scanner",      "Detects dangerous open ports"),
        (c4, "ℹ️", "Info Disclosure",   "Server version leakage"),
    ]:
        col.markdown(f"""
        <div class='feature-card' style='padding:14px;'>
            <div style='font-size:1.5rem;'>{icon}</div>
            <h4 style='font-size:0.9rem;margin:4px 0;'>{title}</h4>
            <p style='font-size:0.9rem;'>{desc}</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    tab_scan, tab_history, tab_guide = st.tabs(["🚀 Run Scan", "📋 History", "📚 Security Guide"])

    with tab_scan:
        st.markdown("<br>", unsafe_allow_html=True)
        form_col, explain_col = st.columns([1, 1])

        with form_col:
            st.markdown('<div class="section-title">Target Configuration</div>', unsafe_allow_html=True)

            target = st.text_input(
                "Target",
                placeholder="https://example.com  or  192.168.1.100",
                label_visibility="collapsed",
            )

            scan_type = st.radio(
                "Scan Type",
                ["headers", "files", "ports", "full"],
                format_func=lambda x: {
                    "headers": "🔒 Security Headers (fast, ~5s)",
                    "files":   "📂 Sensitive Files (~15s)",
                    "ports":   "🔌 Port Scan (~30s)",
                    "full":    "🔍 Full Scan — All Checks (~60s)",
                }[x],
                horizontal=False,
            )

            scan_btn = st.button("🚀 Start Vulnerability Scan", type="primary", use_container_width=True)

        with explain_col:
            st.markdown('<div class="section-title">What Each Check Does</div>', unsafe_allow_html=True)
            checks = [
                ("🔒", "Security Headers",
                 "Checks for HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy. Missing headers leave sites vulnerable to XSS, clickjacking, and SSL stripping."),
                ("📂", "Sensitive Files",
                 "Probes for exposed .env (credentials), .git/HEAD (source code), wp-config.php (database passwords), phpMyAdmin, /actuator/env (Spring Boot secrets)."),
                ("🔌", "Port Scan",
                 "Checks 15 common dangerous ports: RDP (3389), SSH (22), Telnet (23), SMB (445), Redis (6379), MongoDB (27017), MySQL (3306) and more."),
                ("🔍", "Full Scan",
                 "Runs all three checks above for a comprehensive security assessment."),
            ]
            for icon, title, desc in checks:
                st.markdown(f"""
                <div style='padding:10px 0;border-bottom:1px solid #f1f5f9;'>
                    <div style='font-size:1rem;font-weight:700;color:#1e293b;
                                margin-bottom:4px;'>{icon} {title}</div>
                    <div style='font-size:0.9rem;color:#64748b;line-height:1.6;'>{desc}</div>
                </div>
                """, unsafe_allow_html=True)

        # ── Scan execution ─────────────────────────────────────────────────────
        if scan_btn:
            if not target.strip():
                st.warning("⚠️ Enter a target URL or IP address.")
            else:
                time_hints = {"headers":"~5s","files":"~15s","ports":"~30s","full":"~60s"}
                with st.spinner(f"Scanning {target.strip()} — {scan_type} check ({time_hints.get(scan_type,'')})…"):
                    result = scan_target(target.strip(), scan_type)

                # If invalid input — show error only, don't save, don't show scan UI
                if result.get("severity") == "Invalid":
                    st.error(result.get("findings", "❌ Invalid target. Please enter a valid URL, domain, or IP address."))
                else:
                    save_vuln_scan({
                        "target":      result["target"],
                        "scan_type":   result["scan_type"],
                        "vulns_found": result["vulns_found"],
                        "severity":    result["severity"],
                        "findings":    result["findings"],
                        "user_id": st.session_state.get("user", {}).get("id"),
                    })

                    st.markdown("---")
                    sev = result["severity"]
                    sev_msgs = {
                        "Critical": "🔴 CRITICAL VULNERABILITIES FOUND — Immediate action required.",
                        "High":     "🟠 HIGH RISK — Serious security issues need urgent attention.",
                        "Medium":   "🟡 MEDIUM RISK — Issues found. Schedule fixes soon.",
                        "Low":      "🟢 LOW RISK — Minor improvements possible.",
                    }
                    if result["vulns_found"] == 0:
                        st.markdown('<div class="alert-safe">🟢 NO ISSUES FOUND — Target appears well-hardened!</div>', unsafe_allow_html=True)
                    else:
                        css = SEV_BG.get(sev, "alert-info")
                        st.markdown(f'<div class="{css}">{sev_msgs.get(sev,"")}</div>', unsafe_allow_html=True)

                    st.markdown("<br>", unsafe_allow_html=True)
                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("Issues Found",    result["vulns_found"])
                    m2.metric("Overall Risk",    result["severity"])
                    m3.metric("Scan Type",       scan_type.title())
                    m4.metric("Target",          result["target"][:30])

                    if result["findings_list"]:
                        st.markdown('<div class="section-title">🔍 Findings</div>', unsafe_allow_html=True)

                        for sev_level in ["Critical", "High", "Medium", "Low", "Info"]:
                            level_findings = [f for f in result["findings_list"]
                                              if f.get("severity") == sev_level]
                            if not level_findings:
                                continue

                            clr = SEV_COLORS.get(sev_level, "#64748b")
                            st.markdown(f"""
                            <div style='font-size:1rem;font-weight:700;color:{clr};
                                        margin:14px 0 8px 0;padding:6px 0;border-bottom:2px solid {clr}44;'>
                                {sev_level} ({len(level_findings)} findings)
                            </div>
                            """, unsafe_allow_html=True)

                            for finding in level_findings:
                                cat = finding.get("category","")
                                msg = finding.get("message","")
                                hdr = finding.get("header","")
                                st.markdown(f"""
                                <div style='background:{clr}0d;border:1px solid {clr}33;border-left:3px solid {clr};
                                            border-radius:8px;padding:10px 14px;margin:5px 0;'>
                                    <div style='font-size:0.9rem;font-weight:700;color:{clr};'>{cat}</div>
                                    <div style='font-size:1rem;color:#1e293b;margin-top:3px;'>{msg}</div>
                                    {f'<div style="font-size:0.9rem;color:#64748b;margin-top:2px;">Header: <code>{hdr}</code></div>' if hdr else ''}
                                </div>
                                """, unsafe_allow_html=True)

                        with st.expander("📋 Remediation Guide — Click to expand fix instructions"):
                            for finding in result["findings_list"]:
                                msg = finding.get("message","").lower()
                                clr = SEV_COLORS.get(finding.get("severity","Low"),"#64748b")
                                st.markdown(f"**[{finding.get('severity','')}]** {finding.get('message','')}")
                                if "hsts" in msg:
                                    st.code("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload", language="http")
                                elif "csp" in msg:
                                    st.code("Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'", language="http")
                                elif "x-frame" in msg:
                                    st.code("X-Frame-Options: DENY", language="http")
                                elif "x-content-type" in msg:
                                    st.code("X-Content-Type-Options: nosniff", language="http")
                                elif "referrer" in msg:
                                    st.code("Referrer-Policy: strict-origin-when-cross-origin", language="http")
                                elif "permissions" in msg:
                                    st.code("Permissions-Policy: geolocation=(), microphone=(), camera=()", language="http")
                                elif "server header" in msg or "x-powered-by" in msg:
                                    st.markdown("*Remove this header in your web server config to avoid fingerprinting.*")
                                elif "telnet" in msg:
                                    st.markdown("*Disable Telnet immediately: `sudo systemctl disable telnet`*")
                                elif "rdp" in msg:
                                    st.markdown("*Restrict RDP to VPN only. Use Windows Firewall to block port 3389 from public.*")
                                elif "smb" in msg:
                                    st.markdown("*Block SMB (port 445) at firewall. Disable if not needed.*")
                                elif "redis" in msg:
                                    st.markdown("*Add `requirepass yourpassword` to redis.conf. Bind to 127.0.0.1 only.*")
                                elif "mongodb" in msg:
                                    st.markdown("*Enable MongoDB authentication: `mongod --auth`. Bind to localhost.*")
                                st.markdown("---")

    with tab_history:
        st.markdown("<br>", unsafe_allow_html=True)
        rows = get_recent_scans("vuln_scans", limit=15, user_id=st.session_state.get("user", {}).get("id"))
        if rows:
            df2 = pd.DataFrame(rows)[["target","scan_type","vulns_found","severity","scanned_at"]]
            df2.columns = ["Target","Scan Type","Issues Found","Severity","Time"]
            df2["Time"] = df2["Time"].str[:16]
            st.dataframe(df2, use_container_width=True, hide_index=True)
        else:
            st.markdown('<div class="alert-info">ℹ️ No vulnerability scans yet.</div>', unsafe_allow_html=True)

    with tab_guide:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="section-title">🛡️ OWASP Top 10 Quick Reference</div>', unsafe_allow_html=True)
        owasp = [
            ("A01", "Broken Access Control",       "Ensure proper authorization checks on all endpoints."),
            ("A02", "Cryptographic Failures",       "Use TLS 1.2+, encrypt sensitive data at rest and in transit."),
            ("A03", "Injection (SQL, XSS, etc.)",  "Use parameterized queries, validate and sanitize all input."),
            ("A04", "Insecure Design",              "Apply threat modeling during design phase."),
            ("A05", "Security Misconfiguration",   "Remove defaults, disable unnecessary features, set security headers."),
            ("A06", "Vulnerable Components",        "Keep all dependencies updated, use SCA tools."),
            ("A07", "Auth & Session Management",   "Use strong session IDs, MFA, and secure password storage."),
            ("A08", "Software & Data Integrity",   "Verify integrity of software updates and CI/CD pipelines."),
            ("A09", "Logging & Monitoring Failures","Implement centralized logging, alerting, and audit trails."),
            ("A10", "Server-Side Request Forgery",  "Validate and sanitize all server-side URL fetching."),
        ]
        for code, title, rec in owasp:
            st.markdown(f"""
            <div style='display:flex;gap:14px;align-items:flex-start;padding:10px 0;
                        border-bottom:1px solid #f1f5f9;'>
                <span style='background:#dbeafe;color:#1d4ed8;padding:4px 10px;border-radius:6px;
                             font-size:0.9rem;font-weight:700;min-width:40px;text-align:center;'>{code}</span>
                <div>
                    <div style='font-size:1rem;font-weight:700;color:#1e293b;'>{title}</div>
                    <div style='font-size:0.9rem;color:#64748b;margin-top:2px;'>{rec}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
