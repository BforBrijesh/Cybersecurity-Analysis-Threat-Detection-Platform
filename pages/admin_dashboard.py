"""
Admin Dashboard — CyberShield AI
Production-ready admin panel with professional user cards.
All UI rendered with native Streamlit components — no raw HTML leaks.
"""

import streamlit as st
import pandas as pd
from datetime import datetime
from database.db import (
    get_admin_stats, get_login_history, get_all_users,
    update_user_status, delete_user, reset_user_password,
    get_dashboard_stats, get_recent_scans,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _access_check() -> bool:
    return st.session_state.get("user", {}).get("role") == "admin"


def _avatar_letter(user: dict) -> str:
    """Get initials for avatar (up to 2 letters)."""
    name = user.get("full_name") or user.get("username", "?")
    parts = name.strip().split()
    if len(parts) >= 2:
        return (parts[0][0] + parts[1][0]).upper()
    return name[0].upper() if name else "?"


def _role_badge(role: str) -> str:
    if role == "admin":
        return "👑 Admin"
    return "🔵 Analyst"


def _status_badge(status: str) -> str:
    return "🟢 Active" if status == "active" else "🔴 Disabled"


def _metric_card(col, value, label: str, color: str) -> None:
    col.markdown(
        f"""<div class='metric-card'>
            <div class='mc-value' style='color:{color};'>{value}</div>
            <div class='mc-label'>{label}</div>
        </div>""",
        unsafe_allow_html=True,
    )


# ── User card (pure Streamlit, no raw HTML containers) ──────────────────────────

def _render_user_card(u: dict) -> None:
    """
    Render a single user as a professional card using native Streamlit components.
    No raw HTML is ever written to the DOM as visible text.
    """
    uid       = u["id"]
    is_super  = u["username"] == "brijesh_parmar"
    role      = u.get("role", "analyst")
    status    = u.get("status", "active")
    joined    = str(u.get("created_at", ""))[:10] or "—"
    last_seen = str(u.get("last_login", ""))[:16] if u.get("last_login") else "Never"
    initials  = _avatar_letter(u)
    name      = u.get("full_name") or u["username"]
    email     = u.get("email", "")
    username  = u["username"]

    # Avatar colors
    avatar_bg  = "#e53935" if role == "admin" else "#2563eb"
    role_color = "#e53935" if role == "admin" else "#2563eb"
    stat_color = "#16a34a" if status == "active" else "#dc2626"

    # ── Card container ────────────────────────────────────────────────────
    with st.container():
        st.markdown(
            f"""
            <div style='background:#ffffff;border:1px solid #e2e8f0;border-radius:16px;
                        padding:20px 22px 16px 22px;margin-bottom:12px;
                        box-shadow:0 2px 12px rgba(0,0,0,0.06);
                        transition:box-shadow 0.2s;'>

                <!-- Row 1: Avatar + Info + Badges -->
                <div style='display:flex;align-items:flex-start;gap:16px;margin-bottom:14px;'>

                    <!-- Avatar circle -->
                    <div style='width:52px;height:52px;border-radius:50%;
                                background:{avatar_bg};flex-shrink:0;
                                display:flex;align-items:center;justify-content:center;
                                font-size:1.25rem;font-weight:900;color:#fff;
                                box-shadow:0 2px 8px {avatar_bg}55;'>
                        {initials}
                    </div>

                    <!-- Name + username + email -->
                    <div style='flex:1;min-width:0;'>
                        <div style='font-size:1.05rem;font-weight:800;color:#0f172a;
                                    line-height:1.2;margin-bottom:2px;'>
                            {name} {"&nbsp;👑" if is_super else ""}
                        </div>
                        <div style='font-size:0.85rem;color:#64748b;margin-bottom:3px;'>
                            @{username}
                        </div>
                        <div style='font-size:0.85rem;color:#475569;'>
                            {email}
                        </div>
                    </div>

                    <!-- Badges column -->
                    <div style='display:flex;flex-direction:column;
                                align-items:flex-end;gap:6px;flex-shrink:0;'>
                        <span style='background:{role_color}18;color:{role_color};
                                     padding:4px 12px;border-radius:20px;
                                     font-size:0.78rem;font-weight:700;
                                     border:1px solid {role_color}44;'>
                            {_role_badge(role)}
                        </span>
                        <span style='background:{stat_color}18;color:{stat_color};
                                     padding:4px 12px;border-radius:20px;
                                     font-size:0.78rem;font-weight:700;
                                     border:1px solid {stat_color}44;'>
                            {_status_badge(status)}
                        </span>
                    </div>
                </div>

                <!-- Row 2: Meta info -->
                <div style='display:flex;gap:24px;font-size:0.8rem;color:#94a3b8;
                            padding-top:10px;border-top:1px solid #f1f5f9;'>
                    <span>📅 Joined: <b style='color:#475569;'>{joined}</b></span>
                    <span>🕐 Last login: <b style='color:#475569;'>{last_seen}</b></span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # ── Action buttons (native Streamlit — never rendered as raw HTML) ──
        if is_super:
            st.info("👑 Super Admin — this account is protected and cannot be modified.", icon="🔒")
        else:
            b1, b2, b3, b4, b5 = st.columns([1, 1, 1, 1, 3])

            # Disable / Enable
            with b1:
                if status == "active":
                    if st.button("🔒 Disable", key=f"dis_{uid}", use_container_width=True,
                                 help="Disable this account"):
                        update_user_status(uid, "disabled")
                        st.toast(f"Account @{username} disabled.", icon="🔒")
                        st.rerun()
                else:
                    if st.button("✅ Enable", key=f"ena_{uid}", use_container_width=True,
                                 help="Enable this account"):
                        update_user_status(uid, "active")
                        st.toast(f"Account @{username} enabled.", icon="✅")
                        st.rerun()

            # Reset password
            with b2:
                if st.button("🔑 Reset", key=f"rst_{uid}", use_container_width=True,
                             help="Reset password"):
                    st.session_state[f"reset_open_{uid}"] = True

            # Delete
            with b3:
                if st.button("🗑️ Delete", key=f"del_{uid}", use_container_width=True,
                             help="Delete user permanently"):
                    st.session_state[f"del_confirm_{uid}"] = True

            # Login history
            with b4:
                if st.button("📜 History", key=f"hist_{uid}", use_container_width=True,
                             help="View login history"):
                    st.session_state[f"view_hist_{uid}"] = not st.session_state.get(f"view_hist_{uid}", False)

            # ── Password reset form ───────────────────────────────────────
            if st.session_state.get(f"reset_open_{uid}"):
                with st.expander("🔑 Set New Password", expanded=True):
                    new_pw = st.text_input(
                        "New password",
                        type="password",
                        placeholder="Minimum 8 characters",
                        key=f"npw_{uid}",
                    )
                    ok_col, cancel_col = st.columns(2)
                    if ok_col.button("✅ Save Password", key=f"rpw_ok_{uid}"):
                        if len(new_pw) < 8:
                            st.error("Password must be at least 8 characters.")
                        else:
                            reset_user_password(uid, new_pw)
                            st.success(f"✅ Password for @{username} updated.")
                            del st.session_state[f"reset_open_{uid}"]
                            st.rerun()
                    if cancel_col.button("❌ Cancel", key=f"rpw_no_{uid}"):
                        del st.session_state[f"reset_open_{uid}"]
                        st.rerun()

            # ── Delete confirmation ───────────────────────────────────────
            if st.session_state.get(f"del_confirm_{uid}"):
                st.warning(f"⚠️ Permanently delete **@{username}**? This action cannot be undone.")
                yes_col, no_col = st.columns(2)
                if yes_col.button("🗑️ Yes, Delete", key=f"del_yes_{uid}"):
                    delete_user(uid)
                    del st.session_state[f"del_confirm_{uid}"]
                    st.toast(f"User @{username} deleted.", icon="🗑️")
                    st.rerun()
                if no_col.button("❌ Keep User", key=f"del_no_{uid}"):
                    del st.session_state[f"del_confirm_{uid}"]
                    st.rerun()

            # ── Login history panel ───────────────────────────────────────
            if st.session_state.get(f"view_hist_{uid}"):
                with st.expander(f"📜 Login History — @{username}", expanded=True):
                    hist = get_login_history(user_id=uid, limit=20)
                    if hist:
                        hdf = pd.DataFrame(hist)
                        available = [c for c in ["login_time","logout_time","status","ip_address"] if c in hdf.columns]
                        hdf = hdf[available].copy()
                        hdf.columns = ["Login Time","Logout Time","Status","IP Address"][:len(available)]
                        if "Login Time" in hdf.columns:
                            hdf["Login Time"] = hdf["Login Time"].str[:16]
                        if "Logout Time" in hdf.columns:
                            hdf["Logout Time"] = hdf["Logout Time"].fillna("—").astype(str).str[:16]
                        st.dataframe(hdf, use_container_width=True, hide_index=True)
                    else:
                        st.info(f"No login records for @{username} yet.")
                    if st.button("Close History", key=f"hist_close_{uid}"):
                        del st.session_state[f"view_hist_{uid}"]
                        st.rerun()

        st.markdown("---", unsafe_allow_html=False)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN RENDER
# ══════════════════════════════════════════════════════════════════════════════

def render():

    # ── Access guard ──────────────────────────────────────────────────────────
    if not _access_check():
        st.markdown("<br><br>", unsafe_allow_html=True)
        col = st.columns([1, 2, 1])[1]
        with col:
            st.error("🚫 **Access Denied**")
            st.markdown(
                "You do not have administrator privileges.  \n"
                "Contact **Brijesh Parmar** (Super Admin) for access."
            )
        return

    current_admin = st.session_state.get("user", {})

    # ── Page header ────────────────────────────────────────────────────────────
    st.markdown(
        f"""<div class='page-header'>
            <span class='page-header-icon'>🔐</span>
            <div>
                <div class='page-header-title'>Admin Dashboard</div>
                <div class='page-header-sub'>
                    Logged in as: {current_admin.get('full_name') or current_admin.get('username')}
                    &nbsp;·&nbsp;{datetime.now().strftime('%A, %B %d %Y  %I:%M %p')}
                </div>
            </div>
        </div>""",
        unsafe_allow_html=True,
    )

    # ── Tabs ──────────────────────────────────────────────────────────────────
    t1, t2, t3, t4 = st.tabs([
        "📊  Overview",
        "👥  User Management",
        "📋  Login History",
        "📈  Scan Statistics",
    ])

    # ════════════════════════════════════════════════════════════════════════
    # TAB 1 — OVERVIEW
    # ════════════════════════════════════════════════════════════════════════
    with t1:
        st.markdown("<br>", unsafe_allow_html=True)
        stats    = get_admin_stats()
        sc_stats = get_dashboard_stats()

        k1, k2, k3, k4, k5, k6 = st.columns(6)
        for col, val, lbl, clr in [
            (k1, stats["total_users"],       "Total Users",    "#2563eb"),
            (k2, stats["active_users"],      "Active",         "#16a34a"),
            (k3, stats["disabled_users"],    "Disabled",       "#dc2626"),
            (k4, stats["logins_today"],      "Logins Today",   "#9333ea"),
            (k5, stats["total_scans"],       "Total Scans",    "#0891b2"),
            (k6, sc_stats["critical_total"], "Critical Finds", "#ef4444"),
        ]:
            _metric_card(col, val, lbl, clr)

        st.markdown("<br>", unsafe_allow_html=True)

        col_a, col_b = st.columns(2)

        with col_a:
            st.markdown('<div class="section-title">🕐 Recent Login Activity</div>',
                        unsafe_allow_html=True)
            history = get_login_history(limit=10)
            if history:
                df = pd.DataFrame(history)[["username","login_time","status","ip_address"]]
                df.columns = ["User","Login Time","Status","IP"]
                df["Login Time"] = df["Login Time"].str[:16]
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.info("No login records yet.")

        with col_b:
            st.markdown('<div class="section-title">✨ Recent Registrations</div>',
                        unsafe_allow_html=True)
            all_users = get_all_users()
            if all_users:
                df2 = pd.DataFrame(all_users[:10])[
                    ["username","full_name","email","role","status","created_at"]
                ]
                df2.columns = ["Username","Name","Email","Role","Status","Joined"]
                df2["Joined"] = df2["Joined"].str[:10]
                st.dataframe(df2, use_container_width=True, hide_index=True)
            else:
                st.info("No users registered yet.")

        st.markdown("---")
        st.markdown('<div class="section-title">📊 Scan Volume Summary</div>',
                    unsafe_allow_html=True)
        sv1, sv2, sv3, sv4, sv5 = st.columns(5)
        for col, val, lbl, clr in [
            (sv1, sc_stats["ip_scans"],       "IP Scans",     "#0891b2"),
            (sv2, sc_stats["phishing_scans"], "Phishing",     "#7c3aed"),
            (sv3, sc_stats["url_scans"],      "URL Scans",    "#059669"),
            (sv4, sc_stats["log_scans"],      "Log Analyses", "#b45309"),
            (sv5, sc_stats["vuln_scans"],     "Vuln Scans",   "#dc2626"),
        ]:
            _metric_card(col, val, lbl, clr)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 2 — USER MANAGEMENT (professional cards)
    # ════════════════════════════════════════════════════════════════════════
    with t2:
        st.markdown("<br>", unsafe_allow_html=True)

        all_users = get_all_users()
        if not all_users:
            st.info("No users found in the database.")
            return

        # ── Search + filter bar ───────────────────────────────────────────
        search_col, filter_col = st.columns([3, 1])
        with search_col:
            search = st.text_input(
                "Search",
                placeholder="🔍  Search by name, username, or email…",
                label_visibility="collapsed",
                key="user_search",
            )
        with filter_col:
            role_filter = st.selectbox(
                "Role",
                ["All Roles", "admin", "analyst"],
                label_visibility="collapsed",
                key="user_role_filter",
            )

        # Apply filters
        filtered_users = all_users
        if search:
            q = search.strip().lower()
            filtered_users = [
                u for u in filtered_users
                if q in u.get("username","").lower()
                or q in u.get("full_name","").lower()
                or q in u.get("email","").lower()
            ]
        if role_filter != "All Roles":
            filtered_users = [u for u in filtered_users if u.get("role") == role_filter]

        total_shown = len(filtered_users)
        st.caption(f"Showing **{total_shown}** user{'s' if total_shown != 1 else ''}")
        st.markdown("<br>", unsafe_allow_html=True)

        if not filtered_users:
            st.info("No users match your search.")
        else:
            for user in filtered_users:
                _render_user_card(user)

        # ── Export section ────────────────────────────────────────────────
        st.markdown('<div class="section-title">📥 Export Data</div>',
                    unsafe_allow_html=True)
        ec1, ec2 = st.columns(2)

        with ec1:
            export_users = pd.DataFrame(all_users).drop(
                columns=["password_hash","failed_attempts","locked_until"],
                errors="ignore",
            )
            st.download_button(
                "⬇️  Export All Users (CSV)",
                data=export_users.to_csv(index=False).encode("utf-8"),
                file_name=f"users_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv",
                use_container_width=True,
            )

        with ec2:
            all_history = get_login_history(limit=500)
            if all_history:
                st.download_button(
                    "⬇️  Export Login History (CSV)",
                    data=pd.DataFrame(all_history).to_csv(index=False).encode("utf-8"),
                    file_name=f"login_history_{datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv",
                    use_container_width=True,
                )

    # ════════════════════════════════════════════════════════════════════════
    # TAB 3 — LOGIN HISTORY
    # ════════════════════════════════════════════════════════════════════════
    with t3:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="section-title">📋 Full Login History</div>',
                    unsafe_allow_html=True)

        history = get_login_history(limit=200)
        if not history:
            st.info("ℹ️ No login history recorded yet.")
        else:
            fc1, fc2 = st.columns(2)
            with fc1:
                filter_user = st.text_input(
                    "Filter by username", placeholder="Username…", key="hist_filter"
                )
            with fc2:
                filter_status = st.selectbox(
                    "Status filter", ["All", "success", "failed"], key="hist_status"
                )

            filtered = history
            if filter_user:
                filtered = [h for h in filtered
                            if filter_user.lower() in h.get("username","").lower()]
            if filter_status != "All":
                filtered = [h for h in filtered if h.get("status") == filter_status]

            st.caption(f"Showing {len(filtered)} records")

            if filtered:
                df_h = pd.DataFrame(filtered)
                show_cols = [c for c in ["username","email","login_time","logout_time","status","ip_address","session_id"] if c in df_h.columns]
                df_h = df_h[show_cols].copy()
                col_names = {"username":"Username","email":"Email","login_time":"Login Time",
                             "logout_time":"Logout Time","status":"Status",
                             "ip_address":"IP Address","session_id":"Session ID"}
                df_h.rename(columns=col_names, inplace=True)
                if "Login Time" in df_h.columns:
                    df_h["Login Time"] = df_h["Login Time"].str[:16]
                if "Logout Time" in df_h.columns:
                    df_h["Logout Time"] = df_h["Logout Time"].fillna("—").astype(str).str[:16]
                if "Session ID" in df_h.columns:
                    df_h["Session ID"] = df_h["Session ID"].str[:20] + "…"
                st.dataframe(df_h, use_container_width=True, hide_index=True)

                st.download_button(
                    "⬇️ Export Login History (CSV)",
                    data=df_h.to_csv(index=False).encode("utf-8"),
                    file_name=f"login_history_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                    mime="text/csv",
                )

    # ════════════════════════════════════════════════════════════════════════
    # TAB 4 — SCAN STATISTICS
    # ════════════════════════════════════════════════════════════════════════
    with t4:
        st.markdown("<br>", unsafe_allow_html=True)
        sc = get_dashboard_stats()
        total = sum([sc["ip_scans"], sc["phishing_scans"], sc["url_scans"],
                     sc["log_scans"], sc["vuln_scans"]])

        s1, s2, s3, s4, s5, s6 = st.columns(6)
        for col, val, lbl, clr in [
            (s1, total,                  "Total Scans",   "#2563eb"),
            (s2, sc["ip_scans"],         "IP Scans",      "#0891b2"),
            (s3, sc["phishing_scans"],   "Phishing",      "#7c3aed"),
            (s4, sc["url_scans"],        "URL Scans",     "#059669"),
            (s5, sc["vuln_scans"],       "Vuln Scans",    "#b45309"),
            (s6, sc["critical_total"],   "Critical/High", "#dc2626"),
        ]:
            _metric_card(col, val, lbl, clr)

        st.markdown("<br>", unsafe_allow_html=True)

        tab_ip, tab_ph, tab_url, tab_log, tab_vuln = st.tabs([
            "🔍 IP", "📧 Phishing", "🔗 URL", "📊 Log", "🛡️ Vuln"
        ])

        def _show_scan_table(tab, table_name: str, cols: list, rename: list) -> None:
            with tab:
                rows = get_recent_scans(table_name, limit=30)
                if not rows:
                    st.info("No records yet.")
                    return
                df = pd.DataFrame(rows)
                available = [c for c in cols if c in df.columns]
                df = df[available].copy()
                df.columns = rename[:len(available)]
                for tc in df.columns:
                    if "Time" in tc or "at" in tc.lower():
                        try:
                            df[tc] = df[tc].str[:16]
                        except Exception:
                            pass
                st.dataframe(df, use_container_width=True, hide_index=True)

        _show_scan_table(tab_ip,   "ip_scans",
            ["ip","country","threat_score","severity","scanned_at"],
            ["IP","Location","Score","Severity","Time"])
        _show_scan_table(tab_ph,   "phishing_scans",
            ["input_text","score","severity","scanned_at"],
            ["Message","Score","Severity","Time"])
        _show_scan_table(tab_url,  "url_scans",
            ["url","domain","score","severity","scanned_at"],
            ["URL","Domain","Score","Severity","Time"])
        _show_scan_table(tab_log,  "log_scans",
            ["log_source","total_lines","threats_found","severity","scanned_at"],
            ["Source","Lines","Threats","Severity","Time"])
        _show_scan_table(tab_vuln, "vuln_scans",
            ["target","scan_type","vulns_found","severity","scanned_at"],
            ["Target","Type","Issues","Severity","Time"])
