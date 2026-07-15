"""
Auth Page — Login & Registration with session persistence,
rate limiting, login history recording.
"""

import re
import streamlit as st
from database.db import (
    verify_user, create_user,
    record_login,
    check_account_locked,
)
from utils.session_manager import set_session_cookie
from utils.mailer import send_welcome_email, send_login_notification


def _valid_email(email: str) -> bool:
    return bool(re.match(r"^[\w\.\+\-]+@[\w\-]+\.[a-z]{2,}$", email.lower()))


def _strength(pwd: str) -> tuple[int, str, str]:
    s = 0
    if len(pwd) >= 8:                    s += 1
    if len(pwd) >= 12:                   s += 1
    if re.search(r"[A-Z]", pwd):         s += 1
    if re.search(r"[0-9]", pwd):         s += 1
    if re.search(r"[^a-zA-Z0-9]", pwd): s += 1
    s = min(s, 4)
    return (
        s,
        ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"][s],
        ["#ef4444", "#f97316", "#eab308", "#22c55e", "#16a34a"][s],
    )


def render():
    # ── Auth page styling ─────────────────────────────────────────────────────
    st.markdown("""
    <style>
    [data-testid="stSidebar"] { display:none !important; }
    .stApp {
        background: linear-gradient(145deg,#fff1f2 0%,#fff5f5 50%,#fef2f2 100%) !important;
    }
    .stTabs [data-baseweb="tab-list"] { background:#fee2e2 !important; }
    .stTabs [data-baseweb="tab"]      { color:#7f1d1d !important; }
    .stTabs [aria-selected="true"]    {
        background:#fff !important; color:#e53935 !important;
        font-weight:700 !important;
    }
    </style>
    """, unsafe_allow_html=True)

    # ── Hero ──────────────────────────────────────────────────────────────────
    st.markdown("""
    <div style='text-align:center;padding:44px 0 24px 0;'>
        <div style='font-size:4.5rem;line-height:1;
                    filter:drop-shadow(0 4px 8px rgba(229,57,53,0.25));'>🛡️</div>
        <h1 style='font-size:2.6rem !important;font-weight:900 !important;
                   color:#0f172a !important;letter-spacing:-1px;margin:14px 0 6px 0;'>
            CyberShield AI
        </h1>
        <p style='font-size:1.1rem !important;color:#475569;font-weight:500;margin:0 0 3px 0;'>
            KANAD S.H.I.E.L.D Cybersecurity Hackathon 2026
        </p>
        <p style='font-size:0.9rem !important;color:#94a3b8;margin:0;'>
            Organised by Cyber Crime Branch · Open to all security researchers
        </p>
    </div>
    """, unsafe_allow_html=True)

    # ── Feature pills ─────────────────────────────────────────────────────────
    st.markdown("""
    <div style='display:flex;justify-content:center;gap:10px;flex-wrap:wrap;margin-bottom:28px;'>
        <span style='background:#fff1f2;color:#e53935;padding:6px 14px;border-radius:20px;
                     font-size:0.88rem;font-weight:600;border:1px solid #fecaca;'>🔍 IP Analysis</span>
        <span style='background:#fff1f2;color:#e53935;padding:6px 14px;border-radius:20px;
                     font-size:0.88rem;font-weight:600;border:1px solid #fecaca;'>📧 Phishing Detection</span>
        <span style='background:#fff1f2;color:#e53935;padding:6px 14px;border-radius:20px;
                     font-size:0.88rem;font-weight:600;border:1px solid #fecaca;'>🔗 URL Scanner</span>
        <span style='background:#fff1f2;color:#e53935;padding:6px 14px;border-radius:20px;
                     font-size:0.88rem;font-weight:600;border:1px solid #fecaca;'>📊 Log Analyzer</span>
        <span style='background:#fff1f2;color:#e53935;padding:6px 14px;border-radius:20px;
                     font-size:0.88rem;font-weight:600;border:1px solid #fecaca;'>🛡️ Vuln Scanner</span>
        <span style='background:#fff1f2;color:#e53935;padding:6px 14px;border-radius:20px;
                     font-size:0.88rem;font-weight:600;border:1px solid #fecaca;'>📄 PDF Reports</span>
    </div>
    """, unsafe_allow_html=True)

    # ── Centered card ─────────────────────────────────────────────────────────
    _, mid, _ = st.columns([1, 1.6, 1])

    with mid:
        st.markdown("""
        <div style='background:#ffffff;border:1px solid #fecaca;border-radius:24px;
                    padding:36px 32px 28px 32px;
                    box-shadow:0 4px 40px rgba(229,57,53,0.10);'>
        """, unsafe_allow_html=True)

        tab_signin, tab_register = st.tabs(["🔐  Sign In", "✨  Create Account"])

        # ════════════════════════════════════════════════════
        # SIGN IN
        # ════════════════════════════════════════════════════
        with tab_signin:
            st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)

            with st.form("signin_form", clear_on_submit=False):
                username_in = st.text_input(
                    "Username", placeholder="Enter your username"
                )
                password_in = st.text_input(
                    "Password", type="password", placeholder="Enter your password"
                )
                st.markdown("<div style='height:4px;'></div>", unsafe_allow_html=True)
                signin_btn = st.form_submit_button(
                    "🔐  Sign In to CyberShield",
                    type="primary", use_container_width=True,
                )

            if signin_btn:
                uname = username_in.strip()
                pwd   = password_in.strip()

                if not uname or not pwd:
                    st.error("Please enter both username and password.")
                else:
                    # Check account lock first (fast path)
                    is_locked, remaining = check_account_locked(uname)
                    if is_locked:
                        mins = remaining // 60
                        secs = remaining % 60
                        st.error(
                            f"🔒 Account locked due to too many failed attempts. "
                            f"Try again in **{mins}m {secs}s**."
                        )
                    else:
                        ok, udata = verify_user(uname, pwd)
                        if ok:
                            # Create persistent session + write browser cookie
                            session_id = set_session_cookie(udata["id"])

                            # Record login history
                            record_login(
                                user_id=udata["id"],
                                username=udata["username"],
                                email=udata.get("email", ""),
                                session_id=session_id,
                                status="success",
                            )

                            # Store in Streamlit session state
                            st.session_state.authenticated = True
                            st.session_state.user       = udata
                            st.session_state.session_id = session_id
                            st.session_state.page       = "Dashboard"

                            # Set page in URL so refresh returns to Dashboard
                            try:
                                st.query_params["page"] = "Dashboard"
                                st.query_params["sid"]  = session_id
                            except Exception:
                                pass

                            # Send login notification email (non-blocking)
                            try:
                                send_login_notification(
                                    to_email=udata.get("email", ""),
                                    full_name=udata.get("full_name") or udata.get("username", ""),
                                    username=udata.get("username", ""),
                                )
                            except Exception:
                                pass

                            display = udata.get("full_name") or udata.get("username")
                            st.success(f"✅ Welcome back, {display}!")
                            st.rerun()
                        else:
                            # Show specific error if present
                            err = udata.get("error", "") if isinstance(udata, dict) else ""
                            if err:
                                st.error(f"❌ {err}")
                            else:
                                st.error("❌ Incorrect username or password. Please try again.")

            # Just a helpful hint for new users
            st.markdown("""
            <div style='background:#fff1f2;border:1px solid #fecaca;border-radius:12px;
                        padding:14px 18px;margin-top:16px;'>
                <div style='font-size:0.9rem;color:#64748b;'>
                    New users — create a free account using the
                    <b>Create Account</b> tab →
                </div>
            </div>
            """, unsafe_allow_html=True)

        # ════════════════════════════════════════════════════
        # CREATE ACCOUNT
        # ════════════════════════════════════════════════════
        with tab_register:
            st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)
            st.markdown("""
            <div style='background:#f0fdf4;border:1px solid #86efac;
                        border-left:4px solid #22c55e;border-radius:10px;
                        padding:12px 16px;margin-bottom:16px;'>
                <span style='font-size:0.93rem;font-weight:600;color:#14532d;'>
                    ✅ Free to join — All security tools available to everyone.
                </span>
            </div>
            """, unsafe_allow_html=True)

            with st.form("register_form", clear_on_submit=False):
                r_name  = st.text_input("Full Name *",       placeholder="Your full name")
                r_email = st.text_input("Email Address *",   placeholder="you@example.com")
                r_user  = st.text_input("Username *",        placeholder="Min 3 characters")
                r_pass1 = st.text_input("Password *",        type="password",
                                        placeholder="Minimum 8 characters")
                r_pass2 = st.text_input("Confirm Password *",type="password",
                                        placeholder="Repeat your password")
                st.markdown("<div style='height:4px;'></div>", unsafe_allow_html=True)
                reg_btn = st.form_submit_button(
                    "✨  Create My Free Account",
                    type="primary", use_container_width=True,
                )

            if reg_btn:
                errors = []
                if not r_name.strip():        errors.append("Full name is required.")
                if not _valid_email(r_email): errors.append("Enter a valid email (e.g. you@example.com).")
                if len(r_user.strip()) < 3:   errors.append("Username must be at least 3 characters.")
                if len(r_pass1) < 8:          errors.append("Password must be at least 8 characters.")
                if r_pass1 != r_pass2:        errors.append("Passwords do not match.")

                if errors:
                    for e in errors:
                        st.error(e)
                else:
                    # Show password strength
                    sc, lbl, clr = _strength(r_pass1)
                    pct = int((sc / 4) * 100)
                    st.markdown(f"""
                    <div style='margin:8px 0 12px 0;'>
                        <div style='height:6px;background:#fee2e2;border-radius:4px;overflow:hidden;'>
                            <div style='height:100%;width:{pct}%;background:{clr};border-radius:4px;'></div>
                        </div>
                        <span style='font-size:0.83rem;color:{clr};font-weight:700;'>
                            Password strength: {lbl}
                        </span>
                    </div>
                    """, unsafe_allow_html=True)

                    # All new users are analysts — only super admin can promote to admin
                    ok, msg = create_user(
                        r_user.strip(), r_email.strip(), r_pass1,
                        full_name=r_name.strip(), role="analyst",
                    )
                    if ok:
                        # Send welcome email
                        try:
                            send_welcome_email(
                                to_email=r_email.strip(),
                                full_name=r_name.strip(),
                                username=r_user.strip(),
                            )
                        except Exception:
                            pass
                        st.success(
                            f"✅ Account created! Sign in as **{r_user.strip()}** now."
                        )
                        st.balloons()
                    else:
                        st.error(f"❌ {msg}")

        st.markdown("</div>", unsafe_allow_html=True)

    # ── Footer ────────────────────────────────────────────────────────────────
    st.markdown("""
    <div style='text-align:center;padding:32px 0 20px 0;'>
        <p style='font-size:0.83rem !important;color:#94a3b8;line-height:1.9;'>
            🔒 Passwords hashed · Session-based auth · Rate limiting enabled<br>
            CyberShield AI v2.0 · KANAD S.H.I.E.L.D Hackathon 2026
        </p>
    </div>
    """, unsafe_allow_html=True)
