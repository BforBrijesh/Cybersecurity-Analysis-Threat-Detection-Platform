"""
Session Manager — Robust persistent authentication for CyberShield AI.

HOW SESSION PERSISTENCE WORKS:
  Streamlit session_state resets on page refresh (F5). To survive this we use
  TWO layers of persistence:

  Layer 1 — Browser Cookie (via extra-streamlit-components):
    Stores the session_id in the browser. Survives F5, new tab, browser restart.
    Limitation: CookieManager needs one rerun before the cookie value is readable.

  Layer 2 — URL query param (?sid=...):
    On first login we also put the session_id into st.query_params.
    On refresh Streamlit preserves query params in the URL, so we can read it
    immediately without waiting for a rerun.

  Combined approach:
    Read cookie first. If None (first run of CookieManager), fall back to
    ?sid= query param. Either way we get the session_id and validate it
    server-side. One valid hit → user stays logged in.

ON LOGOUT:
  - Invalidate server-side session
  - Delete cookie
  - Clear ?sid= query param
  - Wipe all tool-specific session_state keys so next user starts clean

ON LOGIN:
  - Also wipe old tool state so previous user's data doesn't leak
"""

from __future__ import annotations
import streamlit as st
from database.db import validate_session, invalidate_session, create_session

COOKIE_NAME    = "cs_sid"
QUERY_PARAM    = "sid"
COOKIE_MAX_AGE = 8 * 3600   # 8 hours




def _clear_tool_state() -> None:
    """
    Wipe ALL per-tool session_state keys.
    Called on login (clean slate for new user) AND logout (don't leak data to next user).

    Complete list of tool keys across all pages:
      ip_analyzer  → _ip_prefill
      url_scanner  → url_input_val
      phishing     → phish_text
      log_analyzer → log_text_val
      admin        → user_search, user_role_filter, hist_filter, hist_status,
                     reset_open_*, del_confirm_*, view_hist_*, rpw_*, npw_*
    """
    KEEP = {
        "authenticated", "user", "session_id", "page",
        "_cookie_mgr", COOKIE_NAME, "__cs_cookies__", "_stcore",
    }

    # Exact keys to always delete
    EXACT = {
        "_ip_prefill",
        "url_input_val",
        "phish_text",
        "log_text_val",
        "user_search",
        "user_role_filter",
        "hist_filter",
        "hist_status",
        "scan_single",
        "scan_bulk",
    }

    # Prefixes — delete any key that starts with these
    PREFIXES = (
        "reset_open_", "del_confirm_", "view_hist_",
        "nb_", "ip_sample_", "url_s_",
        "npw_", "rpw_ok_", "rpw_no_",
        "del_yes_", "del_no_",
        "dis_", "ena_", "rst_", "hist_close_",
        "scan_",
    )

    to_delete = [
        k for k in list(st.session_state.keys())
        if k not in KEEP
        and (k in EXACT or any(k.startswith(p) for p in PREFIXES))
    ]

    for k in to_delete:
        try:
            del st.session_state[k]
        except Exception:
            pass


def _get_mgr():
    """Return CookieManager singleton, or None if unavailable."""
    if "_cookie_mgr" not in st.session_state:
        try:
            import extra_streamlit_components as stx
            st.session_state["_cookie_mgr"] = stx.CookieManager(key="__cs_cookies__")
        except Exception:
            st.session_state["_cookie_mgr"] = None
    return st.session_state["_cookie_mgr"]


def _read_sid() -> str | None:
    """
    Read session_id from cookie OR query param (whichever is available first).
    """
    # 1. Try cookie
    mgr = _get_mgr()
    if mgr is not None:
        try:
            sid = mgr.get(COOKIE_NAME)
            if sid:
                return str(sid)
        except Exception:
            pass

    # 2. Fall back to ?sid= URL query param
    try:
        sid = st.query_params.get(QUERY_PARAM)
        if sid:
            return str(sid)
    except Exception:
        pass

    return None


def _write_sid(sid: str) -> None:
    """Write session_id to both cookie and URL query param."""
    # Cookie
    mgr = _get_mgr()
    if mgr is not None:
        try:
            mgr.set(COOKIE_NAME, sid, max_age=COOKIE_MAX_AGE,
                    key="__cs_write__")
        except Exception:
            pass

    # URL query param — survives F5 immediately
    try:
        st.query_params[QUERY_PARAM] = sid
    except Exception:
        pass


def _erase_sid() -> None:
    """Remove session_id from cookie and URL query param."""
    mgr = _get_mgr()
    if mgr is not None:
        try:
            mgr.delete(COOKIE_NAME)
        except Exception:
            pass

    try:
        st.query_params.pop(QUERY_PARAM, None)
    except Exception:
        try:
            # Older Streamlit API
            params = dict(st.query_params)
            params.pop(QUERY_PARAM, None)
            st.query_params.update(params)
        except Exception:
            pass


# ── Public API ────────────────────────────────────────────────────────────────

def init_session() -> None:
    """Initialise session_state defaults. Call first in app.py."""
    defaults = {
        "authenticated": False,
        "user":          {},
        "session_id":    None,
        "page":          "Dashboard",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def restore_session_from_cookie() -> None:
    """
    Attempt to restore auth from cookie / query param.
    Runs on EVERY page load. If valid session found, sets:
      st.session_state.authenticated = True
      st.session_state.user          = <user dict>
    """
    # Already authenticated in this Streamlit memory
    if st.session_state.get("authenticated"):
        return

    sid = _read_sid()
    if not sid:
        return

    user_data = validate_session(sid)
    if user_data:
        st.session_state.authenticated = True
        st.session_state.user          = user_data
        st.session_state.session_id    = sid
        # Make sure query param stays set for next refresh
        try:
            if st.query_params.get(QUERY_PARAM) != sid:
                st.query_params[QUERY_PARAM] = sid
        except Exception:
            pass
    else:
        # Stale / expired session — clean up
        _erase_sid()
        st.session_state.session_id = None


def set_session_cookie(user_id: int) -> str:
    """
    Create server-side session and persist the session_id.
    Call immediately after successful login.
    Returns the new session_id.
    """
    # Clear previous user's tool data
    _clear_tool_state()

    session_id = create_session(user_id)
    st.session_state.session_id = session_id

    _write_sid(session_id)
    return session_id


def clear_session_cookie() -> None:
    """
    Logout: invalidate server session, erase cookie + query param, wipe tool state.
    """
    sid = st.session_state.get("session_id")
    if sid:
        invalidate_session(sid)

    _erase_sid()
    _clear_tool_state()

    st.session_state.authenticated = False
    st.session_state.user          = {}
    st.session_state.session_id    = None
    st.session_state.page          = "Dashboard"
