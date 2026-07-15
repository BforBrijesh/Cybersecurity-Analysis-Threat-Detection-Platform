"""
CyberShield AI — KANAD S.H.I.E.L.D Hackathon 2026
Session persistence: cookie + URL query param — survives refresh, new tab, browser restart.
HOW TO RUN: py -3.11 -m streamlit run app.py   OR   double-click run.bat
"""
import streamlit as st

# ─── Page config MUST be the very first Streamlit call ────────────────────────
st.set_page_config(
    page_title="CyberShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─── 1. Init session state defaults ──────────────────────────────────────────
from utils.session_manager import init_session, restore_session_from_cookie
init_session()

# ─── 2. Restore page from URL query param (survives F5) ──────────────────────
# If user was on "Log Analyzer" and refreshes, ?page=Log+Analyzer brings them back
_PAGE_PARAM = "page"
try:
    _qp_page = st.query_params.get(_PAGE_PARAM)
    if _qp_page and st.session_state.page == "Dashboard":
        # Only restore from URL if we haven't already set a page this run
        st.session_state.page = _qp_page
except Exception:
    pass

# ─── 3. Restore session from cookie / query param ─────────────────────────────
# This is the core of "stay logged in after refresh"
restore_session_from_cookie()

# ─── 4. DB init ───────────────────────────────────────────────────────────────
from utils.session_manager import clear_session_cookie
from database.db import init_db, seed_accounts
init_db()
seed_accounts()

R = "#e53935"   # Brand red

def _go(k: str) -> None:
    """Navigate to a page and persist it in the URL so refresh stays there."""
    st.session_state.page = k
    try:
        st.query_params[_PAGE_PARAM] = k
        # Preserve the session ID in URL too
        sid = st.session_state.get("session_id")
        if sid:
            st.query_params["sid"] = sid
    except Exception:
        pass
    st.rerun()


# ─── Nav definition — Admin tab only visible to admins ────────────────────────
NAV = [
    ("🏠", "Home",     "Dashboard"),
    ("🔍", "IP",       "IP Analyzer"),
    ("📧", "Phishing", "Phishing Detector"),
    ("🔗", "URL",      "URL Scanner"),
    ("📊", "Logs",     "Log Analyzer"),
    ("🛡️", "Vuln",    "Vulnerability Scanner"),
    ("📄", "Reports",  "Reports"),
    ("ℹ️", "About",    "About"),
    ("👤", "Account",  "My Account"),
]

# Admin tab is ONLY added if the logged-in user is admin
# Non-admin users never see it — it does not appear in the navbar at all
_is_admin = st.session_state.get("user", {}).get("role") == "admin"
if _is_admin:
    NAV.append(("🔐", "Admin", "Admin Dashboard"))

NAV.append(("🚪", "Logout", "__logout__"))

cur = st.session_state.page

# ─── Global CSS ────────────────────────────────────────────────────────────────
CSS = ("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');
html{font-size:16px;}
body,.stApp,[class*="css"]{font-family:'Inter',system-ui,sans-serif !important;}
.stApp{background:#f0f2f8 !important;}
[data-testid="stSidebar"],[data-testid="collapsedControl"]{display:none !important;}
#MainMenu,footer,header{visibility:hidden !important;}
[data-testid="stToolbar"],[data-testid="stDecoration"],
.stDeployButton,[data-testid="stStatusWidget"]{display:none !important;}
.main .block-container{
    padding-top:0 !important;
    padding-left:2rem !important;
    padding-right:2rem !important;
    max-width:1600px !important;
}
.stButton>button{
    background:RED !important;color:#fff !important;border:none !important;
    border-radius:10px !important;font-family:'Inter',sans-serif !important;
    font-size:0.95rem !important;font-weight:700 !important;
    padding:0.55rem 1.4rem !important;
    box-shadow:0 2px 8px rgba(229,57,53,0.30) !important;
    transition:all 0.18s !important;white-space:nowrap !important;
}
.stButton>button:hover{
    background:#c62828 !important;transform:translateY(-1px) !important;
    box-shadow:0 4px 14px rgba(229,57,53,0.40) !important;
}
.nav-link-box{
    display:flex;flex-direction:column;align-items:center;justify-content:center;
    gap:3px;padding:8px 6px 6px 6px;border-radius:10px;
    border:1.5px solid #e5e7eb;background:#ffffff;cursor:pointer;
    transition:all 0.12s;min-height:58px;
}
.nav-link-box:hover{background:#fff5f5;border-color:#ffcdd2;}
.nav-link-box.active{background:#fff5f5;border-color:#ffcdd2;border-bottom:3px solid RED;}
.nav-link-box .nav-icon{font-size:1.3rem;line-height:1;}
.nav-link-box .nav-label{font-size:0.78rem;font-weight:600;color:#374151;white-space:nowrap;line-height:1;}
.nav-link-box.active .nav-label{color:RED;font-weight:700;}
.nav-link-logout{
    display:flex;flex-direction:column;align-items:center;justify-content:center;
    gap:3px;padding:8px 6px 6px 6px;border-radius:10px;
    border:1.5px solid #fecaca;background:#fff5f5;cursor:pointer;min-height:58px;
}
.nav-link-logout .nav-label{font-size:0.78rem;font-weight:700;color:RED;white-space:nowrap;line-height:1;}
.nav-over .stButton>button{
    position:absolute !important;top:0 !important;left:0 !important;
    width:100% !important;height:100% !important;opacity:0 !important;
    cursor:pointer !important;font-size:0 !important;border:none !important;
    background:transparent !important;box-shadow:none !important;
    padding:0 !important;min-height:0 !important;margin:0 !important;
}
.nav-over{position:absolute;top:0;left:0;width:100%;height:100%;}
h1{font-size:2rem !important;font-weight:900 !important;color:#0f172a !important;letter-spacing:-.5px;}
h2{font-size:1.55rem !important;font-weight:800 !important;color:#1e293b !important;}
h3{font-size:1.25rem !important;font-weight:700 !important;color:#1e293b !important;}
h4{font-size:1.05rem !important;font-weight:700 !important;color:#334155 !important;}
p,li{font-size:1rem !important;color:#334155;line-height:1.75;}
.stTextInput input,.stTextArea textarea{
    background:#fff !important;border:2px solid #e2e8f0 !important;
    border-radius:10px !important;font-size:1rem !important;
    color:#111827 !important;padding:10px 14px !important;
}
.stTextInput input:focus,.stTextArea textarea:focus{
    border-color:RED !important;box-shadow:0 0 0 3px rgba(229,57,53,0.12) !important;
}
.stTextInput label,.stTextArea label,.stSelectbox label,
.stRadio>label,.stCheckbox span,.stMultiSelect label{
    font-size:1rem !important;font-weight:600 !important;color:#374151 !important;
}
.stTabs [data-baseweb="tab-list"]{background:#f8fafc !important;border-radius:12px !important;padding:4px !important;gap:3px !important;}
.stTabs [data-baseweb="tab"]{background:transparent !important;border-radius:9px !important;font-size:.95rem !important;font-weight:600 !important;color:#64748b !important;padding:9px 18px !important;border:none !important;}
.stTabs [aria-selected="true"]{background:#fff !important;color:RED !important;font-weight:700 !important;box-shadow:0 1px 6px rgba(0,0,0,.10) !important;}
[data-testid="stMetricValue"]{font-size:2.2rem !important;font-weight:900 !important;color:RED !important;}
[data-testid="stMetricLabel"]{font-size:.78rem !important;font-weight:700 !important;color:#64748b !important;text-transform:uppercase !important;letter-spacing:.6px !important;}
.page-header{
    background:linear-gradient(135deg,RED 0%,#ef5350 55%,#ff7043 100%);
    border-radius:18px;padding:26px 30px;margin-bottom:24px;
    display:flex;align-items:center;gap:18px;box-shadow:0 4px 24px rgba(229,57,53,0.28);
}
.page-header-icon{font-size:2.6rem;}
.page-header-title{font-size:1.8rem !important;font-weight:800 !important;color:#fff !important;margin:0 !important;line-height:1.2;}
.page-header-sub{font-size:.95rem !important;color:rgba(255,255,255,.88) !important;margin:5px 0 0 0 !important;}
.section-title{font-size:1.1rem !important;font-weight:700 !important;color:#1e293b !important;border-left:4px solid RED;padding-left:13px;margin:22px 0 13px 0 !important;line-height:1.4;}
.metric-card{background:#fff;border:1px solid #f1f5f9;border-top:3px solid RED;border-radius:16px;padding:22px 14px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,.06);transition:transform .18s,box-shadow .18s;}
.metric-card:hover{transform:translateY(-3px);box-shadow:0 8px 24px rgba(229,57,53,0.15);}
.mc-value{font-size:2.4rem;font-weight:900;line-height:1.1;margin:0;letter-spacing:-1px;color:RED;}
.mc-label{font-size:.75rem;color:#64748b;margin-top:6px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;}
.feature-card{background:#fff;border:1px solid #f1f5f9;border-top:3px solid RED;border-radius:14px;padding:18px;margin-bottom:10px;transition:box-shadow .2s,transform .2s;}
.feature-card:hover{box-shadow:0 6px 20px rgba(229,57,53,0.12);transform:translateY(-2px);}
.feature-card h4{color:RED;font-size:.97rem !important;font-weight:700 !important;margin:8px 0 4px 0 !important;}
.feature-card p{color:#475569;font-size:.93rem !important;margin:0 !important;line-height:1.5;}
.cs-card{background:#fff;border:1px solid #f1f5f9;border-radius:14px;padding:22px;box-shadow:0 1px 4px rgba(0,0,0,.05);margin-bottom:14px;}
.alert-critical{background:#fff1f2;border:1px solid #fca5a5;border-left:5px solid #ef4444;border-radius:12px;padding:15px 18px;margin:10px 0;color:#7f1d1d !important;font-weight:600;font-size:1rem !important;}
.alert-high{background:#fff7ed;border:1px solid #fdba74;border-left:5px solid #f97316;border-radius:12px;padding:15px 18px;margin:10px 0;color:#7c2d12 !important;font-weight:600;font-size:1rem !important;}
.alert-medium{background:#fefce8;border:1px solid #fde047;border-left:5px solid #eab308;border-radius:12px;padding:15px 18px;margin:10px 0;color:#713f12 !important;font-weight:600;font-size:1rem !important;}
.alert-safe{background:#f0fdf4;border:1px solid #86efac;border-left:5px solid #22c55e;border-radius:12px;padding:15px 18px;margin:10px 0;color:#14532d !important;font-weight:600;font-size:1rem !important;}
.alert-info{background:#eff6ff;border:1px solid #93c5fd;border-left:5px solid #3b82f6;border-radius:12px;padding:15px 18px;margin:10px 0;color:#1e40af !important;font-size:1rem !important;}
[data-testid="stDataFrame"]{border-radius:12px !important;border:1px solid #f1f5f9 !important;}
hr{border-color:#e2e8f0 !important;margin:18px 0 !important;}
code,pre{font-family:'JetBrains Mono',monospace !important;font-size:.88rem !important;background:#f8fafc !important;border-radius:6px;color:#0f172a !important;}
::-webkit-scrollbar{width:6px;height:6px;}
::-webkit-scrollbar-track{background:#f1f5f9;}
::-webkit-scrollbar-thumb{background:#e2e8f0;border-radius:4px;}
</style>
""").replace("RED", R)

st.markdown(CSS, unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# AUTH GATE
# Only redirect to login if session could not be restored from cookie
# ══════════════════════════════════════════════════════════════════════════════
if not st.session_state.authenticated:
    from pages import auth
    auth.render()
    st.stop()

# ══════════════════════════════════════════════════════════════════════════════
# NAVBAR
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div style='background:#fff;border-bottom:2px solid #f1f5f9;
            box-shadow:0 2px 12px rgba(0,0,0,0.06);
            margin:0 -2rem;padding:10px 2rem 8px 2rem;'>
""", unsafe_allow_html=True)

col_sizes = [1.8] + [0.78] * len(NAV)
all_cols  = st.columns(col_sizes, gap="small")

with all_cols[0]:
    st.markdown(f"""
    <div style='display:flex;align-items:center;gap:9px;height:58px;'>
        <div style='width:38px;height:38px;flex-shrink:0;
                    background:linear-gradient(135deg,{R},{R}cc);
                    border-radius:10px;display:flex;align-items:center;
                    justify-content:center;font-size:1.3rem;
                    box-shadow:0 2px 8px {R}55;'>🛡️</div>
        <div>
            <div style='font-size:0.92rem;font-weight:900;color:#0f172a;
                        letter-spacing:-0.3px;white-space:nowrap;line-height:1.25;'>
                CyberShield AI</div>
            <div style='font-size:0.55rem;font-weight:600;color:#9ca3af;
                        letter-spacing:0.4px;white-space:nowrap;'>
                PREVENT · DETECT · RESPOND</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

for col, (emoji, label, key) in zip(all_cols[1:], NAV):
    with col:
        is_active = cur == key
        is_out    = key == "__logout__"

        box_class = "nav-link-logout" if is_out else (
            "nav-link-box active" if is_active else "nav-link-box"
        )
        st.markdown(f"""
        <div style='position:relative;'>
          <div class='{box_class}'>
            <span class='nav-icon'>{emoji}</span>
            <span class='nav-label'>{label}</span>
          </div>
        <div class='nav-over'>
        """, unsafe_allow_html=True)

        if is_out:
            if st.button(".", key=f"nb_{key}", use_container_width=True):
                clear_session_cookie()
                # Clear all query params
                try:
                    st.query_params.clear()
                except Exception:
                    pass
                st.session_state.page = "Dashboard"
                st.rerun()
        else:
            if st.button(".", key=f"nb_{key}", use_container_width=True):
                _go(key)

        st.markdown("</div></div>", unsafe_allow_html=True)

st.markdown("</div>", unsafe_allow_html=True)

st.markdown(f"""
<div style='height:3px;background:linear-gradient(90deg,{R},{R}66,transparent);
            margin:0 -2rem 1.2rem -2rem;'></div>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# PAGE ROUTER
# ══════════════════════════════════════════════════════════════════════════════
p = st.session_state.page

# ── Security: if a non-admin somehow reaches Admin Dashboard, redirect away ──
if p == "Admin Dashboard" and not _is_admin:
    st.session_state.page = "Dashboard"
    try:
        st.query_params["page"] = "Dashboard"
    except Exception:
        pass
    st.rerun()

if   p == "Dashboard":             from pages import dashboard;         dashboard.render()
elif p == "IP Analyzer":           from pages import ip_analyzer;       ip_analyzer.render()
elif p == "Phishing Detector":     from pages import phishing_detector; phishing_detector.render()
elif p == "URL Scanner":           from pages import url_scanner;       url_scanner.render()
elif p == "Log Analyzer":          from pages import log_analyzer;      log_analyzer.render()
elif p == "Vulnerability Scanner": from pages import vuln_scanner;      vuln_scanner.render()
elif p == "Reports":               from pages import reports;           reports.render()
elif p == "My Account":            from pages import account;           account.render()
elif p == "About":                 from pages import about;             about.render()
elif p == "Admin Dashboard":
    # Double-check — _is_admin guard above already redirected non-admins
    from pages import admin_dashboard
    admin_dashboard.render()
