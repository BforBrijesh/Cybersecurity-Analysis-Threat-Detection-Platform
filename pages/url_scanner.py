"""
URL Scanner Page
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from engine.url_engine import analyze_url
from database.db import save_url_scan, get_recent_scans

SEV_COLORS = {"Critical":"#ef4444","High":"#f97316","Medium":"#eab308","Low":"#22c55e"}
SEV_BG     = {"Critical":"alert-critical","High":"alert-high","Medium":"alert-medium","Low":"alert-safe"}

SAMPLE_URLS = [
    ("🔴", "paypa1-secure-login.tk/verify",          "Typosquat + malicious TLD"),
    ("🔴", "http://185.220.101.1/phishing/steal",    "Raw IP URL"),
    ("🔴", "https://amazon-account-verify-now.com",  "Brand impersonation"),
    ("🟠", "http://bit.ly/3xAbC12",                  "URL shortener"),
    ("🟡", "https://xn--pypl-p0a.com",               "Punycode homograph"),
    ("🟢", "https://www.google.com",                 "Known safe domain"),
]


def _display_result(result: dict):
    sev = result["severity"]
    msgs = {
        "Critical": "🔴 MALICIOUS URL — Do NOT visit. Report and block this domain immediately.",
        "High":     "🟠 HIGH RISK URL — Strong indicators of malicious intent. Avoid this URL.",
        "Medium":   "🟡 SUSPICIOUS URL — Verify legitimacy before visiting.",
        "Low":      "🟢 LIKELY SAFE — No significant threats detected.",
    }
    css = SEV_BG.get(sev, "alert-info")
    # Only display if we have a known severity message — never show generic fallback
    if sev not in msgs:
        return
    st.markdown(f'<div class="{css}">{msgs[sev]}</div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Threat Score", f"{result['score']} / 100")
    m2.metric("Severity",     sev)
    m3.metric("Domain",       result["domain"][:30] if result["domain"] else "—")
    m4.metric("Protocol",     "HTTPS ✅" if result["url"].startswith("https") else "HTTP ⚠️")

    # Indicators
    st.markdown('<div class="section-title">🎯 Indicators</div>', unsafe_allow_html=True)
    inds = result["indicators"].split(" | ")
    ic1, ic2 = st.columns(2)
    for i, ind in enumerate(inds):
        if ind.strip():
            bg = "#fff1f2" if "🔴" in ind else ("#fff7ed" if "⚠️" in ind else "#f0fdf4")
            col = ic1 if i % 2 == 0 else ic2
            col.markdown(f"""
            <div style='background:{bg};border-radius:8px;padding:9px 13px;
                        margin:5px 0;font-size:1rem;color:#1e293b;'>
                {ind.strip()}
            </div>
            """, unsafe_allow_html=True)


def render():
    st.markdown("""
    <div class='page-header'>
        <span class='page-header-icon'>🔗</span>
        <div>
            <div class='page-header-title'>URL Scanner</div>
            <div class='page-header-sub'>Typosquat · Malicious TLD · Open Redirect · Homograph Attack Detection</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Info cards
    i1, i2, i3, i4 = st.columns(4)
    for col, icon, title, desc in [
        (i1, "🔤", "Typosquatting",   "Detects imitation of trusted brands"),
        (i2, "🌐", "TLD Analysis",    "Flags suspicious top-level domains"),
        (i3, "↩️", "Open Redirects", "Catches redirect parameter abuse"),
        (i4, "🔡", "Homograph",       "Detects punycode/IDN attacks"),
    ]:
        col.markdown(f"""
        <div class='feature-card' style='padding:14px;'>
            <div style='font-size:1.5rem;'>{icon}</div>
            <h4 style='font-size:0.9rem;margin:4px 0;'>{title}</h4>
            <p style='font-size:0.9rem;'>{desc}</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    tab_single, tab_bulk, tab_history = st.tabs(["🔍 Single URL", "📋 Bulk Scan", "📊 History"])

    # ── Single URL ────────────────────────────────────────────────────────────
    with tab_single:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="section-title">Enter a URL to Scan</div>', unsafe_allow_html=True)

        url_input = st.text_input("URL", placeholder="https://example.com or paste any suspicious link",
                                   label_visibility="collapsed")

        st.markdown("**Try a sample URL:**")
        rows_a = SAMPLE_URLS[:3]
        rows_b = SAMPLE_URLS[3:]
        r1cols = st.columns(3)
        r2cols = st.columns(3)
        for i, (badge, url, desc) in enumerate(rows_a):
            if r1cols[i].button(f"{badge} {url[:35]}", key=f"url_s_{i}", use_container_width=True):
                st.session_state["url_input_val"] = url
        for i, (badge, url, desc) in enumerate(rows_b):
            if r2cols[i].button(f"{badge} {url[:35]}", key=f"url_s_{i+3}", use_container_width=True):
                st.session_state["url_input_val"] = url
            r2cols[i].caption(desc)

        if st.session_state.get("url_input_val") and not url_input:
            url_input = st.session_state["url_input_val"]

        scan_btn = st.button("🔍 Scan URL", type="primary", use_container_width=True, key="scan_single")

        if scan_btn:
            if not url_input.strip():
                st.error("⚠️ Please enter a URL to scan.")
            else:
                with st.spinner(f"Scanning {url_input.strip()[:60]}…"):
                    result = analyze_url(url_input.strip())

                # Bug 7: show error immediately if invalid, don't save to DB
                if result.get("severity") == "Invalid":
                    st.error(result["indicators"])
                else:
                    save_url_scan({
                        "url": result["url"], "domain": result["domain"],
                        "score": result["score"], "severity": result["severity"],
                        "indicators": result["indicators"], "redirect_chain": result["redirect_chain"],
                        "user_id": st.session_state.get("user", {}).get("id"),
                    })
                    st.markdown("---")
                    _display_result(result)

    # ── Bulk Scan ─────────────────────────────────────────────────────────────
    with tab_bulk:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="section-title">Bulk URL Scan</div>', unsafe_allow_html=True)
        st.caption("Enter one URL per line. Up to 50 URLs at once.")

        bulk_text = st.text_area(
            "URLs",
            height=200,
            label_visibility="collapsed",
            placeholder="\n".join(url for _, url, _ in SAMPLE_URLS),
        )

        load_samples = st.button("Load all sample URLs", key="load_bulk_samples")
        if load_samples:
            bulk_text = "\n".join(url for _, url, _ in SAMPLE_URLS)

        if st.button("🔍 Scan All URLs", type="primary", key="scan_bulk"):
            urls = [u.strip() for u in bulk_text.strip().splitlines() if u.strip()][:50]
            if not urls:
                st.warning("Enter at least one URL.")
            else:
                results = []
                invalid_count = 0
                prog = st.progress(0, text="Scanning…")
                for i, url in enumerate(urls):
                    r = analyze_url(url)
                    if r.get("severity") == "Invalid":
                        invalid_count += 1
                    else:
                        save_url_scan({
                            "url":r["url"],"domain":r["domain"],"score":r["score"],
                            "severity":r["severity"],"indicators":r["indicators"],
                            "redirect_chain":r["redirect_chain"],
                            "user_id": st.session_state.get("user", {}).get("id"),
                        })
                    results.append(r)
                    prog.progress((i+1)/len(urls), text=f"Scanned {i+1}/{len(urls)}")
                prog.empty()

                # Filter out invalid for chart/table
                valid_results = [r for r in results if r.get("severity") != "Invalid"]
                if invalid_count:
                    st.warning(f"⚠️ {invalid_count} invalid URL(s) skipped — not valid URLs.")

                if not valid_results:
                    st.error("No valid URLs to display.")
                else:
                    df = pd.DataFrame([{
                        "URL":      r["url"][:65],
                        "Domain":   r["domain"],
                        "Score":    r["score"],
                        "Severity": r["severity"],
                    } for r in valid_results])

                    st.dataframe(df, use_container_width=True, hide_index=True)

                    fig = px.bar(df, x="URL", y="Score", color="Severity",
                                 color_discrete_map=SEV_COLORS, text="Score")
                    fig.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(248,250,252,0.8)",
                        xaxis_tickangle=-35, height=350,
                        xaxis=dict(color="#64748b"), yaxis=dict(range=[0,105]),
                        margin=dict(t=10,b=80,l=10,r=10),
                    )
                    fig.update_traces(textposition="outside")
                    st.plotly_chart(fig, use_container_width=True)

                    total = len(valid_results)
                    critical = sum(1 for r in valid_results if r["severity"] in ("Critical","High"))
                    st.markdown(f"""
                    <div class='{"alert-critical" if critical > 0 else "alert-safe"}'>
                        {'🔴' if critical > 0 else '🟢'} Bulk scan complete:
                        <b>{total}</b> URLs scanned,
                        <b>{critical}</b> high-risk URLs detected.
                    </div>
                    """, unsafe_allow_html=True)

    # ── History ───────────────────────────────────────────────────────────────
    with tab_history:
        st.markdown("<br>", unsafe_allow_html=True)
        rows = get_recent_scans("url_scans", limit=30, user_id=st.session_state.get("user", {}).get("id"))
        if rows:
            df2 = pd.DataFrame(rows)[["url","domain","score","severity","scanned_at"]]
            df2.columns = ["URL","Domain","Score","Severity","Scanned At"]
            df2["Scanned At"] = df2["Scanned At"].str[:16]
            st.dataframe(df2, use_container_width=True, hide_index=True)

            # Scatter plot: score over time
            if len(df2) >= 3:
                df2_plot = df2.iloc[::-1].reset_index(drop=True)
                fig3 = px.scatter(df2_plot, x="Scanned At", y="Score", color="Severity",
                                  color_discrete_map=SEV_COLORS, size_max=12,
                                  hover_data=["Domain"])
                fig3.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(248,250,252,0.8)",
                    height=250, margin=dict(t=10,b=10,l=10,r=10),
                    xaxis=dict(showgrid=False, color="#64748b"),
                    yaxis=dict(gridcolor="#e2e8f0", range=[0,105]),
                )
                st.caption("Threat score history for scanned URLs")
                st.plotly_chart(fig3, use_container_width=True)
        else:
            st.markdown('<div class="alert-info">ℹ️ No URL scans yet. Go to the Single URL tab.</div>', unsafe_allow_html=True)
