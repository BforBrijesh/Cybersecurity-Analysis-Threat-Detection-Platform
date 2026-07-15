"""
CyberShield AI — Database Layer
Production-grade SQLite with WAL, indexes, login history, sessions, rate limiting.
"""

import sqlite3
import os
import hashlib
import secrets
import json
from datetime import datetime, timedelta
from typing import Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "cybershield.db")

# ── Table allowlist (SQL injection protection) ─────────────────────────────────
_VALID_TABLES = frozenset([
    "users", "ip_scans", "phishing_scans", "url_scans",
    "log_scans", "vuln_scans", "login_history", "user_sessions",
])

# ── Session config ─────────────────────────────────────────────────────────────
SESSION_TIMEOUT_MINUTES = 30


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create all tables and indexes. Safe to call multiple times."""
    conn = get_connection()
    c = conn.cursor()
    c.executescript("""
        -- ── Users ──────────────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT    NOT NULL UNIQUE,
            email           TEXT    NOT NULL UNIQUE,
            password_hash   TEXT    NOT NULL,
            full_name       TEXT    DEFAULT '',
            role            TEXT    DEFAULT 'analyst',
            status          TEXT    DEFAULT 'active',
            created_at      TEXT    DEFAULT (datetime('now')),
            last_login      TEXT,
            failed_attempts INTEGER DEFAULT 0,
            locked_until    TEXT
        );

        -- ── Login history ───────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS login_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            username    TEXT    NOT NULL,
            email       TEXT    NOT NULL,
            login_time  TEXT    DEFAULT (datetime('now')),
            logout_time TEXT,
            ip_address  TEXT    DEFAULT 'N/A',
            user_agent  TEXT    DEFAULT 'N/A',
            status      TEXT    DEFAULT 'success',
            session_id  TEXT
        );

        -- ── User sessions ───────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS user_sessions (
            session_id  TEXT PRIMARY KEY,
            user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at  TEXT DEFAULT (datetime('now')),
            last_active TEXT DEFAULT (datetime('now')),
            expires_at  TEXT NOT NULL,
            is_active   INTEGER DEFAULT 1
        );

        -- ── Scan tables ─────────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS ip_scans (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ip           TEXT    NOT NULL,
            country      TEXT,
            isp          TEXT,
            threat_score INTEGER DEFAULT 0,
            is_tor       INTEGER DEFAULT 0,
            is_vpn       INTEGER DEFAULT 0,
            is_proxy     INTEGER DEFAULT 0,
            open_ports   TEXT,
            severity     TEXT,
            details      TEXT,
            scanned_at   TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS phishing_scans (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            input_text TEXT    NOT NULL,
            score      REAL    DEFAULT 0.0,
            severity   TEXT,
            indicators TEXT,
            verdict    TEXT,
            scanned_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS url_scans (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            url            TEXT NOT NULL,
            domain         TEXT,
            score          REAL DEFAULT 0.0,
            severity       TEXT,
            indicators     TEXT,
            redirect_chain TEXT,
            scanned_at     TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS log_scans (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            log_source    TEXT,
            total_lines   INTEGER,
            threats_found INTEGER,
            severity      TEXT,
            summary       TEXT,
            scanned_at    TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS vuln_scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target      TEXT NOT NULL,
            scan_type   TEXT,
            vulns_found INTEGER DEFAULT 0,
            severity    TEXT,
            findings    TEXT,
            scanned_at  TEXT DEFAULT (datetime('now'))
        );

        -- ── Indexes ─────────────────────────────────────────────────────────
        CREATE INDEX IF NOT EXISTS idx_ip_time      ON ip_scans(scanned_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ph_time      ON phishing_scans(scanned_at DESC);
        CREATE INDEX IF NOT EXISTS idx_url_time     ON url_scans(scanned_at DESC);
        CREATE INDEX IF NOT EXISTS idx_log_time     ON log_scans(scanned_at DESC);
        CREATE INDEX IF NOT EXISTS idx_vuln_time    ON vuln_scans(scanned_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ip_sev       ON ip_scans(severity);
        CREATE INDEX IF NOT EXISTS idx_ph_sev       ON phishing_scans(severity);
        CREATE INDEX IF NOT EXISTS idx_url_sev      ON url_scans(severity);
        CREATE INDEX IF NOT EXISTS idx_vuln_sev     ON vuln_scans(severity);
        CREATE INDEX IF NOT EXISTS idx_lh_user      ON login_history(user_id);
        CREATE INDEX IF NOT EXISTS idx_lh_time      ON login_history(login_time DESC);
        CREATE INDEX IF NOT EXISTS idx_sess_user    ON user_sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sess_active  ON user_sessions(is_active);
    """)
    conn.commit()

    # ── Migrate existing scan tables: add user_id if missing ──────────────────
    scan_tables = ["ip_scans", "phishing_scans", "url_scans", "log_scans", "vuln_scans"]
    for tbl in scan_tables:
        existing = [r[1] for r in conn.execute(f"PRAGMA table_info({tbl})").fetchall()]
        if "user_id" not in existing:
            try:
                conn.execute(f"ALTER TABLE {tbl} ADD COLUMN user_id INTEGER")
                conn.commit()
            except Exception:
                pass

    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# PASSWORD HASHING
# ══════════════════════════════════════════════════════════════════════════════

def _hash_password(password: str, salt: str = "") -> tuple[str, str]:
    """
    Hash password with SHA-256 + unique salt.
    Single round — consistent with existing database records.
    Passwords are never stored in plain text and are never decryptable.
    """
    if not salt:
        salt = secrets.token_hex(32)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return hashed, salt


# ══════════════════════════════════════════════════════════════════════════════
# SESSION MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def create_session(user_id: int) -> str:
    """Create a new session token for a user."""
    session_id = secrets.token_urlsafe(64)
    now        = datetime.now()
    expires    = now + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
    try:
        conn = get_connection()
        # Invalidate old sessions for this user
        conn.execute(
            "UPDATE user_sessions SET is_active=0 WHERE user_id=?", (user_id,)
        )
        conn.execute(
            "INSERT INTO user_sessions (session_id, user_id, created_at, last_active, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (session_id, user_id,
             now.isoformat(), now.isoformat(), expires.isoformat()),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass
    return session_id


def validate_session(session_id: str) -> Optional[dict]:
    """
    Validate a session token.
    Returns user dict if valid and not expired, else None.
    Also extends the session on activity.
    """
    if not session_id:
        return None
    try:
        conn = get_connection()
        row = conn.execute(
            "SELECT s.*, u.id as uid, u.username, u.email, u.full_name, "
            "       u.role, u.status, u.last_login "
            "FROM user_sessions s "
            "JOIN users u ON s.user_id = u.id "
            "WHERE s.session_id=? AND s.is_active=1",
            (session_id,),
        ).fetchone()

        if not row:
            conn.close()
            return None

        row = dict(row)

        # Check expiry
        expires_at = datetime.fromisoformat(row["expires_at"])
        if datetime.now() > expires_at:
            # Expired — invalidate
            conn.execute(
                "UPDATE user_sessions SET is_active=0 WHERE session_id=?",
                (session_id,),
            )
            conn.commit()
            conn.close()
            return None

        # Check user is still active
        if row.get("status") == "disabled":
            conn.close()
            return None

        # Extend session on activity
        new_expires = datetime.now() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        conn.execute(
            "UPDATE user_sessions SET last_active=?, expires_at=? WHERE session_id=?",
            (datetime.now().isoformat(), new_expires.isoformat(), session_id),
        )
        conn.commit()
        conn.close()

        return {
            "id":         row["uid"],
            "username":   row["username"],
            "email":      row["email"],
            "full_name":  row["full_name"],
            "role":       row["role"],
            "status":     row["status"],
            "last_login": row["last_login"],
        }
    except Exception:
        return None


def invalidate_session(session_id: str) -> None:
    """Invalidate (logout) a session."""
    if not session_id:
        return
    try:
        conn = get_connection()
        conn.execute(
            "UPDATE user_sessions SET is_active=0 WHERE session_id=?",
            (session_id,),
        )
        # Record logout time in login_history
        conn.execute(
            "UPDATE login_history SET logout_time=? WHERE session_id=? AND logout_time IS NULL",
            (datetime.now().isoformat(), session_id),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# LOGIN HISTORY
# ══════════════════════════════════════════════════════════════════════════════

def record_login(user_id: int, username: str, email: str,
                 session_id: str, status: str = "success",
                 ip_address: str = "N/A", user_agent: str = "N/A") -> None:
    try:
        conn = get_connection()
        conn.execute(
            "INSERT INTO login_history "
            "(user_id, username, email, login_time, ip_address, user_agent, status, session_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (user_id, username, email, datetime.now().isoformat(),
             ip_address, user_agent, status, session_id),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_login_history(user_id: Optional[int] = None, limit: int = 50) -> list:
    """Get login history. If user_id given, filter to that user."""
    try:
        conn = get_connection()
        if user_id:
            rows = conn.execute(
                "SELECT * FROM login_history WHERE user_id=? "
                "ORDER BY login_time DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM login_history ORDER BY login_time DESC LIMIT ?",
                (limit,),
            ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


# ══════════════════════════════════════════════════════════════════════════════
# RATE LIMITING / ACCOUNT LOCKING
# ══════════════════════════════════════════════════════════════════════════════

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES     = 15


def check_account_locked(username: str) -> tuple[bool, int]:
    """
    Returns (is_locked, seconds_remaining).
    """
    try:
        conn = get_connection()
        row = conn.execute(
            "SELECT failed_attempts, locked_until FROM users WHERE username=?",
            (username.lower().strip(),),
        ).fetchone()
        conn.close()
        if not row:
            return False, 0
        row = dict(row)
        if row.get("locked_until"):
            locked_until = datetime.fromisoformat(row["locked_until"])
            if datetime.now() < locked_until:
                remaining = int((locked_until - datetime.now()).total_seconds())
                return True, remaining
            else:
                # Lock expired — reset
                _reset_failed_attempts(username)
        return False, 0
    except Exception:
        return False, 0


def increment_failed_attempts(username: str) -> int:
    """Increment failed attempts. Returns new count. Locks after MAX."""
    try:
        conn = get_connection()
        conn.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username=?",
            (username.lower().strip(),),
        )
        row = conn.execute(
            "SELECT failed_attempts FROM users WHERE username=?",
            (username.lower().strip(),),
        ).fetchone()
        count = dict(row)["failed_attempts"] if row else 0

        if count >= MAX_FAILED_ATTEMPTS:
            lock_until = (datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
            conn.execute(
                "UPDATE users SET locked_until=? WHERE username=?",
                (lock_until, username.lower().strip()),
            )
        conn.commit()
        conn.close()
        return count
    except Exception:
        return 0


def _reset_failed_attempts(username: str) -> None:
    try:
        conn = get_connection()
        conn.execute(
            "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?",
            (username.lower().strip(),),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# USER MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def create_user(username: str, email: str, password: str,
                full_name: str = "", role: str = "analyst") -> tuple[bool, str]:
    """Create a new user. Returns (success, message)."""
    # Validation
    username = username.lower().strip()
    email    = email.lower().strip()
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters."
    if not email or "@" not in email:
        return False, "Invalid email address."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    try:
        hashed, salt = _hash_password(password)
        conn = get_connection()
        conn.execute(
            "INSERT INTO users (username, email, password_hash, full_name, role, status) "
            "VALUES (?, ?, ?, ?, ?, 'active')",
            (username, email, f"{salt}:{hashed}", full_name, role),
        )
        conn.commit()
        conn.close()
        return True, "Account created successfully."
    except sqlite3.IntegrityError as e:
        msg = str(e).lower()
        if "username" in msg: return False, "Username already exists."
        if "email"    in msg: return False, "Email already registered."
        return False, "Registration failed."
    except Exception as e:
        return False, f"Database error: {e}"


def verify_user(username: str, password: str) -> tuple[bool, dict]:
    """
    Verify login credentials.
    Returns (success, user_dict).
    Handles rate limiting and account locking.
    """
    username = username.lower().strip()

    # Check if locked
    is_locked, remaining = check_account_locked(username)
    if is_locked:
        mins = remaining // 60
        secs = remaining % 60
        return False, {"error": f"Account locked. Try again in {mins}m {secs}s."}

    try:
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM users WHERE username=? AND status='active'",
            (username,),
        ).fetchone()
        conn.close()

        if not row:
            increment_failed_attempts(username)
            return False, {}

        row = dict(row)
        stored = row["password_hash"]
        if ":" not in stored:
            return False, {}

        salt, hashed = stored.split(":", 1)
        check, _ = _hash_password(password, salt)

        if check == hashed:
            _reset_failed_attempts(username)
            # Update last_login
            try:
                conn2 = get_connection()
                conn2.execute(
                    "UPDATE users SET last_login=? WHERE id=?",
                    (datetime.now().isoformat(), row["id"]),
                )
                conn2.commit()
                conn2.close()
            except Exception:
                pass
            return True, row
        else:
            count = increment_failed_attempts(username)
            remaining_attempts = MAX_FAILED_ATTEMPTS - count
            if remaining_attempts > 0:
                return False, {"error": f"Wrong password. {remaining_attempts} attempt(s) remaining."}
            else:
                return False, {"error": f"Account locked for {LOCKOUT_MINUTES} minutes."}

    except Exception:
        return False, {}


def get_user_by_id(user_id: int) -> dict:
    try:
        conn = get_connection()
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        conn.close()
        return dict(row) if row else {}
    except Exception:
        return {}


def get_all_users() -> list:
    """Admin: get all users."""
    try:
        conn = get_connection()
        rows = conn.execute(
            "SELECT id, username, email, full_name, role, status, created_at, last_login "
            "FROM users ORDER BY created_at DESC"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def update_user_status(user_id: int, status: str) -> bool:
    """Admin: enable or disable a user account."""
    if status not in ("active", "disabled"):
        return False
    try:
        conn = get_connection()
        conn.execute("UPDATE users SET status=? WHERE id=?", (status, user_id))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def delete_user(user_id: int) -> bool:
    """Admin: delete a user. Super admin (brijesh_parmar) cannot be deleted."""
    try:
        conn = get_connection()
        row = conn.execute(
            "SELECT username, email FROM users WHERE id=?", (user_id,)
        ).fetchone()
        if not row:
            conn.close()
            return False
        r = dict(row)
        # Protect super admin by both username and email
        if r["username"] == "brijesh_parmar" or r["email"] == "brijeshparmar1412@gmail.com":
            conn.close()
            return False
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def reset_user_password(user_id: int, new_password: str) -> bool:
    """Admin: reset a user's password."""
    try:
        hashed, salt = _hash_password(new_password)
        conn = get_connection()
        conn.execute(
            "UPDATE users SET password_hash=?, failed_attempts=0, locked_until=NULL WHERE id=?",
            (f"{salt}:{hashed}", user_id),
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# SCAN HELPERS (unchanged from original)
# ══════════════════════════════════════════════════════════════════════════════

def save_ip_scan(data: dict) -> bool:
    try:
        conn = get_connection()
        conn.execute("""
            INSERT INTO ip_scans (ip, country, isp, threat_score, is_tor, is_vpn,
                                  is_proxy, open_ports, severity, details, user_id)
            VALUES (:ip, :country, :isp, :threat_score, :is_tor, :is_vpn,
                    :is_proxy, :open_ports, :severity, :details, :user_id)
        """, data)
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def save_phishing_scan(data: dict) -> bool:
    try:
        conn = get_connection()
        conn.execute("""
            INSERT INTO phishing_scans (input_text, score, severity, indicators, verdict, user_id)
            VALUES (:input_text, :score, :severity, :indicators, :verdict, :user_id)
        """, data)
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def save_url_scan(data: dict) -> bool:
    try:
        conn = get_connection()
        conn.execute("""
            INSERT INTO url_scans (url, domain, score, severity, indicators, redirect_chain, user_id)
            VALUES (:url, :domain, :score, :severity, :indicators, :redirect_chain, :user_id)
        """, data)
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def save_log_scan(data: dict) -> bool:
    try:
        conn = get_connection()
        conn.execute("""
            INSERT INTO log_scans (log_source, total_lines, threats_found, severity, summary, user_id)
            VALUES (:log_source, :total_lines, :threats_found, :severity, :summary, :user_id)
        """, data)
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def save_vuln_scan(data: dict) -> bool:
    try:
        conn = get_connection()
        conn.execute("""
            INSERT INTO vuln_scans (target, scan_type, vulns_found, severity, findings, user_id)
            VALUES (:target, :scan_type, :vulns_found, :severity, :findings, :user_id)
        """, data)
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def get_recent_scans(table: str, limit: int = 20, user_id: int = None) -> list:
    """
    Fetch recent scan records.
    If user_id is provided, returns ONLY that user's scans.
    Admins can pass user_id=None to get all scans (used in admin dashboard).
    """
    if table not in _VALID_TABLES:
        return []
    try:
        conn = get_connection()
        if user_id is not None:
            rows = conn.execute(
                f"SELECT * FROM {table} WHERE user_id=? ORDER BY scanned_at DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                f"SELECT * FROM {table} ORDER BY scanned_at DESC LIMIT ?", (limit,)
            ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def get_dashboard_stats(user_id: int = None) -> dict:
    """
    Return scan counts for dashboard.
    If user_id is provided, counts only that user's scans.
    """
    stats = {
        "ip_scans": 0, "phishing_scans": 0, "url_scans": 0,
        "log_scans": 0, "vuln_scans": 0, "critical_total": 0,
    }
    try:
        conn = get_connection()
        for table in ["ip_scans", "phishing_scans", "url_scans", "log_scans", "vuln_scans"]:
            if table in _VALID_TABLES:
                if user_id is not None:
                    row = conn.execute(
                        f"SELECT COUNT(*) as cnt FROM {table} WHERE user_id=?", (user_id,)
                    ).fetchone()
                else:
                    row = conn.execute(f"SELECT COUNT(*) as cnt FROM {table}").fetchone()
                stats[table] = row["cnt"] if row else 0

        critical = 0
        for table in ["ip_scans", "phishing_scans", "url_scans", "vuln_scans"]:
            if table in _VALID_TABLES:
                if user_id is not None:
                    row = conn.execute(
                        f"SELECT COUNT(*) as cnt FROM {table} "
                        "WHERE severity IN ('Critical','High') AND user_id=?",
                        (user_id,),
                    ).fetchone()
                else:
                    row = conn.execute(
                        f"SELECT COUNT(*) as cnt FROM {table} "
                        "WHERE severity IN ('Critical','High')"
                    ).fetchone()
                critical += row["cnt"] if row else 0
        stats["critical_total"] = critical
        conn.close()
    except Exception:
        pass
    return stats


def get_all_scans_for_report(user_id: int = None) -> dict:
    """Return scan data for PDF report. Filtered by user_id if provided."""
    result = {}
    for table in ["ip_scans", "phishing_scans", "url_scans", "log_scans", "vuln_scans"]:
        result[table] = get_recent_scans(table, limit=100, user_id=user_id)
    return result


def get_admin_stats() -> dict:
    """Admin dashboard statistics."""
    stats = {}
    try:
        conn = get_connection()
        stats["total_users"]    = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
        stats["active_users"]   = conn.execute("SELECT COUNT(*) as c FROM users WHERE status='active'").fetchone()["c"]
        stats["disabled_users"] = conn.execute("SELECT COUNT(*) as c FROM users WHERE status='disabled'").fetchone()["c"]
        stats["admin_users"]    = conn.execute("SELECT COUNT(*) as c FROM users WHERE role='admin'").fetchone()["c"]

        today = datetime.now().strftime("%Y-%m-%d")
        stats["logins_today"]   = conn.execute(
            "SELECT COUNT(*) as c FROM login_history WHERE login_time LIKE ? AND status='success'",
            (f"{today}%",)
        ).fetchone()["c"]

        # Total scans
        total = 0
        for table in ["ip_scans", "phishing_scans", "url_scans", "log_scans", "vuln_scans"]:
            row = conn.execute(f"SELECT COUNT(*) as c FROM {table}").fetchone()
            total += row["c"] if row else 0
        stats["total_scans"] = total

        conn.close()
    except Exception:
        stats.update({"total_users":0,"active_users":0,"disabled_users":0,
                      "admin_users":0,"logins_today":0,"total_scans":0})
    return stats


# ══════════════════════════════════════════════════════════════════════════════
# SEED — Brijesh Parmar as Super Admin (cannot be deleted)
# ══════════════════════════════════════════════════════════════════════════════

def seed_accounts():
    """
    Ensure super admin (brijesh_parmar) always exists with correct credentials.
    Runs every startup — safe for both new and existing databases.
    """
    try:
        conn = get_connection()

        # ── 1. Upsert brijesh_parmar super admin ──────────────────────────
        hashed, salt = _hash_password("Admin@2026")
        pw_hash = f"{salt}:{hashed}"

        existing = conn.execute(
            "SELECT id FROM users WHERE username='brijesh_parmar'"
        ).fetchone()

        if existing:
            # Always ensure correct password, role, email, status
            conn.execute(
                "UPDATE users SET password_hash=?, role='admin', status='active', "
                "full_name='Brijesh Parmar', email='brijeshparmar1412@gmail.com' "
                "WHERE username='brijesh_parmar'",
                (pw_hash,),
            )
        else:
            # Insert fresh — handle email conflict by updating that row instead
            try:
                conn.execute(
                    "INSERT INTO users "
                    "(username, email, password_hash, full_name, role, status) "
                    "VALUES ('brijesh_parmar','brijeshparmar1412@gmail.com',?,"
                    "'Brijesh Parmar','admin','active')",
                    (pw_hash,),
                )
            except sqlite3.IntegrityError:
                # email already registered to another username — rename + update
                conn.execute(
                    "UPDATE users SET username='brijesh_parmar', "
                    "password_hash=?, full_name='Brijesh Parmar', "
                    "role='admin', status='active' "
                    "WHERE email='brijeshparmar1412@gmail.com'",
                    (pw_hash,),
                )
        conn.commit()

        # ── 2. Ensure analyst demo account ───────────────────────────────
        # Removed — only super admin account is seeded.
        # New users register themselves through the registration form.

        conn.close()
    except Exception:
        pass


# Run on import
init_db()
seed_accounts()
