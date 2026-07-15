"""
Phishing Detector Page
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from engine.phishing_engine import analyze_phishing
from database.db import save_phishing_scan, get_recent_scans

SAMPLE_PHISHING = """From: security-alert@paypa1-secure.com
Subject: ⚠️ URGENT: Your PayPal account has been SUSPENDED!

Dear Valued Customer,

We have detected UNAUTHORIZED ACCESS to your PayPal account from an unknown device in Russia.

You MUST verify your identity IMMEDIATELY or your account will be permanently terminated within 24 hours.

👉 Click here NOW to verify: http://paypal-secure-verify.tk/account?redirect=credentials

To unlock your account, please provide:
- Full name and date of birth
- Credit card number and CVV
- Social Security Number
- Current password

FAILURE TO COMPLY WILL RESULT IN IMMEDIATE LEGAL ACTION AND ACCOUNT CLOSURE!!!

This is your FINAL NOTICE.

PayPal Security Team
© PayPal 2026"""

SAMPLE_SAFE = """Hi Sarah,

Hope you're doing well! Just following up on our meeting from yesterday.

I've attached the Q3 marketing report you requested. 
Please review sections 2 and 4 as they contain the budget projections we discussed.

Let me know if you have any questions or need any changes.

Looking forward to your feedback.

Best regards,
Michael Thompson
Marketing Director
michael.thompson@company.com"""

SAMPLE_SMS_SCAM = """FedEx: Your package #FX2847291 is on hold due to an unpaid customs fee of $2.99.
Pay now to avoid return: http://fedex-customs-fee.xyz/pay?id=2847291
This link expires in 24 hours."""


def render():
    st.markdown("""
    <div class='page-header'>
        <span class='page-header-icon'>📧</span>
        <div>
            <div class='page-header-title'>Phishing Detector</div>
            <div class='page-header-sub'>AI-powered analysis of emails, SMS, and messages for phishing indicators</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── How it works cards ────────────────────────────────────────────────────
    c1, c2, c3, c4, c5 = st.columns(5)
    for col, icon, title, desc in [
        (c1, "⚡", "Urgency Detection", "Finds time-pressure language"),
        (c2, "🎯", "Impersonation", "Detects brand spoofing"),
        (c3, "💳", "Credential Harvesting", "Spots password/card requests"),
        (c4, "🔗", "URL Analysis", "Flags suspicious links"),
        (c5, "📎", "Attachment Risk", "Detects malicious file types"),
    ]:
        col.markdown(f"""
        <div class='feature-card' style='padding:14px;'>
            <div style='font-size:1.5rem;'>{icon}</div>
            <h4 style='font-size:1rem;margin:6px 0;'>{title}</h4>
            <p style='font-size:0.9rem;'>{desc}</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Sample buttons ────────────────────────────────────────────────────────
    st.markdown('<div class="section-title">Load a Sample or Paste Your Own</div>', unsafe_allow_html=True)
    sb1, sb2, sb3, _ = st.columns([1, 1, 1, 3])
    load_phish = sb1.button("🔴 Load Phishing Email", use_container_width=True)
    load_safe  = sb2.button("🟢 Load Safe Email",     use_container_width=True)
    load_sms   = sb3.button("📱 Load SMS Scam",       use_container_width=True)

    default_text = st.session_state.get("phish_text", "")
    if load_phish: default_text = SAMPLE_PHISHING; st.session_state["phish_text"] = SAMPLE_PHISHING
    if load_safe:  default_text = SAMPLE_SAFE;     st.session_state["phish_text"] = SAMPLE_SAFE
    if load_sms:   default_text = SAMPLE_SMS_SCAM; st.session_state["phish_text"] = SAMPLE_SMS_SCAM

    text_input = st.text_area(
        "Message",
        value=default_text,
        height=260,
        placeholder="Paste email body, SMS text, or any suspicious message here…",
        label_visibility="collapsed",
    )

    if text_input != st.session_state.get("phish_text", ""):
        st.session_state["phish_text"] = text_input

    col_btn, col_info = st.columns([1, 3])
    analyze_btn = col_btn.button("🔍 Analyze Message", type="primary", use_container_width=True)
    col_info.caption("Analysis runs locally. Your text is stored only in the local database.")

    # ── Result ────────────────────────────────────────────────────────────────
    if analyze_btn:
        if not text_input.strip():
            st.warning("⚠️ Please paste a message to analyze.")
        else:
            with st.spinner("Analyzing message for phishing indicators…"):
                result = analyze_phishing(text_input)

            # If invalid input — show error only, don't save, don't show scan UI
            if result.get("severity") == "Invalid":
                st.error(result.get("verdict", "❌ Invalid input."))
            else:
                save_phishing_scan({
                    "input_text": result["input_text"],
                    "score": result["score"],
                    "severity": result["severity"],
                    "indicators": result["indicators"],
                    "verdict": result["verdict"],
                    "user_id": st.session_state.get("user", {}).get("id"),
                })

                st.markdown("---")

                sev = result["severity"]
                sev_msgs = {
                    "Critical": ("alert-critical", "🔴 PHISHING CONFIRMED — DO NOT interact with this message. Report and delete immediately."),
                    "High":     ("alert-high",     "🟠 VERY LIKELY PHISHING — Treat with extreme caution. Verify sender through official channels."),
                    "Medium":   ("alert-medium",   "🟡 SUSPICIOUS MESSAGE — Some phishing indicators found. Verify before taking any action."),
                    "Low":      ("alert-safe",     "🟢 LIKELY SAFE — No strong phishing indicators detected. Always stay vigilant."),
                }
                css_cls, msg = sev_msgs.get(sev, ("alert-info", result["verdict"]))
                st.markdown(f'<div class="{css_cls}">{msg}</div>', unsafe_allow_html=True)

                st.markdown("<br>", unsafe_allow_html=True)
                m1, m2, m3 = st.columns(3)
                m1.metric("Phishing Score", f"{result['score']:.0f} / 100")
                m2.metric("Risk Level",     sev)
                m3.metric("Indicators Found", len(result.get("indicators_list", [])))

                # Score bar
                bar_colors = {"Critical":"#ef4444","High":"#f97316","Medium":"#eab308","Low":"#22c55e"}
                bar_color = bar_colors.get(sev, "#3b82f6")
                fig = go.Figure(go.Bar(
                    x=[result["score"]], y=["Risk Score"],
                    orientation="h", marker_color=bar_color,
                    text=[f"{result['score']:.0f}%"], textposition="outside",
                    textfont={"size": 14, "color": bar_color},
                    width=0.35,
                ))
                fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(248,250,252,0.8)",
                    xaxis=dict(range=[0, 100], showgrid=True, gridcolor="#e2e8f0", color="#64748b"),
                    yaxis=dict(color="#64748b"),
                    height=100, margin=dict(t=10, b=10, l=10, r=60),
                )
                st.plotly_chart(fig, use_container_width=True)

                # Indicators
                st.markdown('<div class="section-title">🎯 Detected Indicators</div>', unsafe_allow_html=True)
                inds = result.get("indicators_list", [])
                if inds:
                    ind_col1, ind_col2 = st.columns(2)
                    for i, ind in enumerate(inds):
                        col = ind_col1 if i % 2 == 0 else ind_col2
                        bg = "#fff1f2" if "🔴" in ind else ("#fff7ed" if "⚠️" in ind else "#f0fdf4")
                        col.markdown(f"""
                        <div style='background:{bg};border-radius:8px;padding:10px 14px;
                                    margin:5px 0;font-size:1rem;color:#1e293b;'>
                            {ind}
                        </div>
                        """, unsafe_allow_html=True)

    # ── Phishing stats + History ───────────────────────────────────────────────
    st.markdown("---")
    rows = get_recent_scans("phishing_scans", limit=20, user_id=st.session_state.get("user", {}).get("id"))

    if rows:
        hist_col, stats_col = st.columns([2, 1])

        with hist_col:
            st.markdown('<div class="section-title">📋 Scan History</div>', unsafe_allow_html=True)
            df = pd.DataFrame(rows)[["input_text","score","severity","verdict","scanned_at"]]
            df["input_text"] = df["input_text"].str[:70] + "…"
            df.columns = ["Message Preview","Score","Severity","Verdict","Time"]
            df["Time"] = df["Time"].str[:16]
            st.dataframe(df, use_container_width=True, hide_index=True)

        with stats_col:
            st.markdown('<div class="section-title">📊 Risk Breakdown</div>', unsafe_allow_html=True)
            sev_counts = {"Critical":0,"High":0,"Medium":0,"Low":0}
            for r in rows:
                s = r.get("severity","Low")
                if s in sev_counts: sev_counts[s] += 1
            fig2 = go.Figure(go.Pie(
                labels=list(sev_counts.keys()), values=list(sev_counts.values()),
                marker_colors=["#ef4444","#f97316","#eab308","#22c55e"],
                hole=0.5, textinfo="label+value",
                textfont={"size":13,"family":"Inter"},
            ))
            fig2.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", height=280,
                margin=dict(t=10,b=10,l=10,r=10),
                legend={"font":{"size":12},"orientation":"h","y":-0.15},
            )
            st.plotly_chart(fig2, use_container_width=True)
    else:
        st.markdown('<div class="alert-info">ℹ️ No phishing checks yet. Load a sample above to get started.</div>', unsafe_allow_html=True)
