"""
About Page
"""

import streamlit as st


def render():
    st.markdown("""
    <div class='page-header'>
        <span class='page-header-icon'>ℹ️</span>
        <div>
            <div class='page-header-title'>About CyberShield AI</div>
            <div class='page-header-sub'>KANAD S.H.I.E.L.D Cybersecurity Hackathon 2026 · Organised by Cyber Crime Branch</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns([3, 2])

    with col1:
        st.markdown("""
        ## What is CyberShield AI?

        **CyberShield AI** is a unified cybersecurity analysis platform designed for rapid
        threat detection and security assessment. It gives security teams a single interface
        for IP intelligence, phishing analysis, URL scanning, log forensics, and vulnerability
        assessment — without needing expensive commercial subscriptions.

        Built for the **KANAD S.H.I.E.L.D Hackathon 2026**, organised by the **Cyber Crime Branch**.
        """)

        st.markdown("---")
        st.markdown("## 🔍 Modules")

        modules = [
            ("🔍", "IP Analyzer",          "Geo-location, Tor/VPN/proxy detection, threat scoring, port scanning"),
            ("📧", "Phishing Detector",     "Rule-based NLP analysis: urgency, impersonation, credential harvesting, suspicious URLs"),
            ("🔗", "URL Scanner",           "Typosquatting, malicious TLD, open redirect, punycode homograph detection"),
            ("📊", "Log Analyzer",          "SQLi, XSS, path traversal, brute force, web shell, scanner detection in log files"),
            ("🛡️", "Vulnerability Scanner", "Security headers, exposed sensitive files, dangerous open ports, info disclosure"),
            ("📄", "PDF Reports",           "Professional audit-grade PDF reports with all scan results"),
            ("🔐", "Authentication",        "Secure login with SHA-256 + salt, role-based access (Admin/Analyst)"),
        ]
        for icon, title, desc in modules:
            st.markdown(f"""
            <div class='cs-card' style='padding:14px 18px;margin-bottom:10px;'>
                <div style='display:flex;gap:12px;align-items:flex-start;'>
                    <span style='font-size:1.4rem;'>{icon}</span>
                    <div>
                        <div style='font-size:15px !important;font-weight:700;color:#1e293b;'>{title}</div>
                        <div style='font-size:0.9rem;color:#64748b;margin-top:3px;'>{desc}</div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("## ⚠️ Ethical Use Policy")
        st.markdown("""
        This tool is provided **for educational and authorized security testing only.**

        ✅ Scan your own infrastructure  
        ✅ Authorized penetration testing with written permission  
        ✅ Security research and learning  
        ❌ Do NOT scan systems without explicit permission  
        ❌ Do NOT use for unauthorized access or surveillance  

        Unauthorized scanning may violate the **IT Act 2000 (India)**, Computer Fraud and Abuse Act,
        GDPR, and other applicable laws.
        """)

    with col2:
        st.markdown("## 🏗️ Tech Stack")
        stack = [
            ("🐍", "Python 3.11",    "Core language"),
            ("🎨", "Streamlit",      "Web UI framework"),
            ("🗄️", "SQLite",        "Local data storage"),
            ("📈", "Plotly",         "Interactive charts"),
            ("📄", "ReportLab",      "PDF generation"),
            ("🌐", "Requests",       "HTTP/API calls"),
            ("🔐", "SHA-256 + Salt", "Password hashing"),
        ]
        for icon, name, desc in stack:
            st.markdown(f"""
            <div style='display:flex;gap:10px;align-items:center;padding:8px 0;
                        border-bottom:1px solid #f1f5f9;'>
                <span style='font-size:1.1rem;'>{icon}</span>
                <div>
                    <span style='font-size:1rem;font-weight:700;color:#1e293b;'>{name}</span>
                    <span style='font-size:0.9rem;color:#94a3b8;margin-left:8px;'>{desc}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("## 📊 Severity Scale")
        levels = [
            ("🔴", "Critical", "70–100", "#ef4444", "Immediate action"),
            ("🟠", "High",     "40–69",  "#f97316", "Urgent attention"),
            ("🟡", "Medium",   "20–39",  "#eab308", "Scheduled fix"),
            ("🟢", "Low",      "0–19",   "#22c55e", "Monitor"),
        ]
        for icon, sev, rng, clr, action in levels:
            st.markdown(f"""
            <div style='display:flex;gap:12px;align-items:center;padding:8px 0;
                        border-bottom:1px solid #f1f5f9;'>
                <span style='font-size:1.2rem;'>{icon}</span>
                <div style='flex:1;'>
                    <span style='font-size:1rem;font-weight:700;color:{clr};'>{sev}</span>
                    <span style='font-size:0.9rem;color:#94a3b8;margin-left:8px;'>{rng}</span>
                </div>
                <span style='font-size:0.9rem;color:#64748b;'>{action}</span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("""
        ## 🚀 Quick Start
        ```bash
        py -3.11 -m pip install -r requirements.txt
        py -3.11 -m streamlit run app.py
        ```

        ## 🏆 Hackathon
        **KANAD S.H.I.E.L.D 2026**  
        Organised by Cyber Crime Branch  
        Version 2.0 · MIT License
        """)
