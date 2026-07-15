"""
My Account Page — Profile, security settings, and activity
"""

import streamlit as st
from database.db import get_connection, _hash_password, get_dashboard_stats, get_recent_scans, verify_user
import pandas as pd


def render():
    user = st.session_state.get("user", {})

    # Compute role info once at the top — used in multiple tabs
    role_bg  = "#fee2e2" if user.get("role") == "admin" else "#dbeafe"
    role_clr = "#dc2626" if user.get("role") == "admin" else "#1d4ed8"
    role_lbl = "Administrator" if user.get("role") == "admin" else "Security Analyst"

    st.markdown("""
    <div class='page-header'>
        <span class='page-header-icon'>👤</span>
        <div>
            <div class='page-header-title'>My Account</div>
            <div class='page-header-sub'>Profile · Password · Security Settings · Scan Activity</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    tab_profile, tab_security, tab_activity = st.tabs([
        "👤  Profile", "🔒  Change Password", "📊  My Activity"
    ])

    # ══════════════════════════════════════════════════════════════════════════
    #  PROFILE TAB
    # ══════════════════════════════════════════════════════════════════════════
    with tab_profile:
        st.markdown("<br>", unsafe_allow_html=True)

        avatar_col, form_col = st.columns([1, 3])

        with avatar_col:
            initials = "".join(
                w[0].upper()
                for w in (user.get("full_name") or user.get("username","U")).split()[:2]
            )

            st.markdown(f"""
            <div style='text-align:center;'>
                <div style='width:100px;height:100px;background:linear-gradient(135deg,#2563eb,#7c3aed);
                            border-radius:50%;display:flex;align-items:center;justify-content:center;
                            font-size:2.2rem;font-weight:900;color:white;margin:0 auto 12px auto;
                            box-shadow:0 4px 20px rgba(37,99,235,0.35);'>
                    {initials}
                </div>
                <div style='font-size:1.05rem;font-weight:700;color:#0f172a;'>
                    {user.get("full_name") or user.get("username","User")}
                </div>
                <div style='font-size:0.85rem;color:#64748b;margin:4px 0 10px 0;'>
                    @{user.get("username","")}
                </div>
                <span style='background:{role_bg};color:{role_clr};padding:4px 14px;
                             border-radius:20px;font-size:0.82rem;font-weight:700;'>
                    {role_lbl}
                </span>
            </div>
            """, unsafe_allow_html=True)

        with form_col:
            st.markdown('<div class="section-title">Profile Information</div>', unsafe_allow_html=True)

            with st.form("profile_form", clear_on_submit=False):
                new_name = st.text_input("Full Name", value=user.get("full_name", ""),
                                         placeholder="Your display name")
                st.text_input("Username", value=user.get("username", ""), disabled=True,
                              help="Username cannot be changed after registration.")
                st.text_input("Email", value=user.get("email", ""), disabled=True,
                              help="Contact an administrator to change your email.")
                st.text_input("Account Type", value=role_lbl, disabled=True)

                save_btn = st.form_submit_button("💾  Save Changes", type="primary")
                if save_btn:
                    if new_name.strip():
                        conn = get_connection()
                        conn.execute("UPDATE users SET full_name=? WHERE id=?",
                                     (new_name.strip(), user["id"]))
                        conn.commit()
                        conn.close()
                        st.session_state.user["full_name"] = new_name.strip()
                        st.success("✅ Profile updated.")
                        st.rerun()
                    else:
                        st.error("Full name cannot be empty.")

        st.divider()
        st.markdown('<div class="section-title">Account Summary</div>', unsafe_allow_html=True)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Username",     user.get("username","—"))
        c2.metric("Role",         role_lbl)
        c3.metric("Member Since", str(user.get("created_at","—"))[:10])
        c4.metric("Last Login",   str(user.get("last_login","—"))[:16]
                                   if user.get("last_login") else "Current session")

    # ══════════════════════════════════════════════════════════════════════════
    #  SECURITY TAB
    # ══════════════════════════════════════════════════════════════════════════
    with tab_security:
        st.markdown("<br>", unsafe_allow_html=True)

        sec_left, sec_right = st.columns([1, 1])

        with sec_left:
            st.markdown('<div class="section-title">🔒 Change Password</div>', unsafe_allow_html=True)

            with st.form("password_form", clear_on_submit=True):
                cur_pwd  = st.text_input("Current Password", type="password",
                                          placeholder="Enter your current password")
                new_pwd  = st.text_input("New Password", type="password",
                                          placeholder="Minimum 8 characters")
                conf_pwd = st.text_input("Confirm New Password", type="password",
                                          placeholder="Repeat your new password")

                change_btn = st.form_submit_button("🔒  Update Password", type="primary",
                                                    use_container_width=True)

            if change_btn:
                ok, _ = verify_user(user.get("username",""), cur_pwd)
                if not ok:
                    st.error("❌ Current password is incorrect.")
                elif len(new_pwd) < 8:
                    st.error("❌ Password must be at least 8 characters.")
                elif new_pwd != conf_pwd:
                    st.error("❌ New passwords do not match.")
                elif new_pwd == cur_pwd:
                    st.error("❌ New password must be different from current.")
                else:
                    hashed, salt = _hash_password(new_pwd)
                    conn = get_connection()
                    conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                                 (f"{salt}:{hashed}", user["id"]))
                    conn.commit()
                    conn.close()
                    st.success("✅ Password updated successfully!")

        with sec_right:
            st.markdown('<div class="section-title">🛡️ Security Best Practices</div>', unsafe_allow_html=True)
            tips = [
                ("🔑", "Strong passwords", "Use 12+ characters with uppercase, numbers, and symbols."),
                ("🔄", "Rotate regularly",  "Change your password every 90 days minimum."),
                ("🚪", "Log out always",    "Always sign out when done, especially on shared devices."),
                ("👁️", "Never share",       "Never share your credentials with anyone, ever."),
                ("📧", "Unique email",      "Use a dedicated email for security platform accounts."),
                ("🔔", "Stay alert",        "Report any suspicious activity to your security team."),
            ]
            for icon, title, desc in tips:
                st.markdown(f"""
                <div style='display:flex;gap:12px;align-items:flex-start;
                            padding:10px 0;border-bottom:1px solid #f1f5f9;'>
                    <span style='font-size:1.3rem;flex-shrink:0;'>{icon}</span>
                    <div>
                        <div style='font-size:0.97rem;font-weight:700;color:#1e293b;'>{title}</div>
                        <div style='font-size:0.88rem;color:#64748b;margin-top:2px;'>{desc}</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

    # ══════════════════════════════════════════════════════════════════════════
    #  ACTIVITY TAB
    # ══════════════════════════════════════════════════════════════════════════
    with tab_activity:
        st.markdown("<br>", unsafe_allow_html=True)

        stats = get_dashboard_stats()
        total = sum([stats["ip_scans"], stats["phishing_scans"],
                     stats["url_scans"], stats["log_scans"], stats["vuln_scans"]])

        c1, c2, c3, c4, c5 = st.columns(5)
        for col, val, label, clr in [
            (c1, total,                   "Total Scans",    "#2563eb"),
            (c2, stats["ip_scans"],       "IP Scans",       "#0891b2"),
            (c3, stats["phishing_scans"], "Phishing Checks","#7c3aed"),
            (c4, stats["url_scans"],      "URL Scans",      "#059669"),
            (c5, stats["critical_total"], "Critical Finds", "#dc2626"),
        ]:
            col.markdown(f"""
            <div class='metric-card'>
                <div class='mc-value' style='color:{clr};'>{val}</div>
                <div class='mc-label'>{label}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="section-title">📋 Recent Scan Activity</div>', unsafe_allow_html=True)

        all_activity = []
        for table, label in [
            ("ip_scans",       "🔍 IP Scan"),
            ("phishing_scans", "📧 Phishing Check"),
            ("url_scans",      "🔗 URL Scan"),
            ("log_scans",      "📊 Log Analysis"),
            ("vuln_scans",     "🛡️ Vuln Scan"),
        ]:
            for r in get_recent_scans(table, limit=5):
                target = r.get("ip") or r.get("url") or r.get("target") or r.get("log_source") or "—"
                all_activity.append({
                    "Time":     r.get("scanned_at","")[:16],
                    "Type":     label,
                    "Target":   str(target)[:50],
                    "Severity": r.get("severity","—"),
                })

        if all_activity:
            df = pd.DataFrame(all_activity).sort_values("Time", ascending=False).head(25)
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.markdown('<div class="alert-info">ℹ️ No activity yet. Start using the tools from the sidebar.</div>',
                        unsafe_allow_html=True)
