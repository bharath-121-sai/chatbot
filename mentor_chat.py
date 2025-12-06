# mentor_chat.py
# MentorAssist — Mentor Chat (production-ready single-file)
#
# Save as mentor_chat.py and run:
#    streamlit run mentor_chat.py
#
# Dependencies (same as in your project):
#  - streamlit
#  - rapidfuzz (for fuzzy)
#  - shared_utils.py (must export parse_intent, fuzzy_best_candidate, load_chat_history_for, save_chat_history_for, chat_file_for_user)
#  - db_utils.py (exports used DB helpers; app gracefully falls back to sample data if DB unavailable)
#  - ai_core.py (exports call_gemini_short, AI_AVAILABLE) - optional
#
# This file intentionally includes many comments and helper functions so that you can
# modify behavior easily. It also provides both simulated and API-based login modes.
###############################################################################

import streamlit as st
import os
import json
import time
import re
import traceback
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple

# Local project imports (your repository should provide these modules)
# If any of these are missing, the app will run in offline/demo mode using sample data.
try:
    from shared_utils import (
        parse_intent,
        fuzzy_best_candidate,
        load_chat_history_for,
        save_chat_history_for,
        chat_file_for_user,
    )
except Exception as e:
    # Provide fallbacks if shared_utils missing - very small local implementations
    def parse_intent(text: str):
        t = (text or "").strip().lower()
        meta = {"roll_query": None, "name_query": None, "memory_phrase": None}
        if t in ("hi", "hello", "hey", "hii"):
            return "greeting", meta
        if t.startswith("who is "):
            meta["memory_phrase"] = t[7:].strip()
            return "memory_lookup", meta
        if "certificate" in t or "certificates" in t:
            if "how many" in t or "count" in t:
                return "count_certificates", meta
            return "certificates", meta
        if "activity" in t and "score" in t:
            return "activity_score", meta
        if "mentees" in t:
            return "mentees", meta
        if t.startswith("profile of") or t.startswith("student profile"):
            return "profile", meta
        if t.startswith("find student") or t.startswith("search student"):
            return "find_student", meta
        # detect roll-like tokens
        roll = re.search(r"\b[0-9]{1,}[A-Za-z0-9\-]{1,}\b", t)
        if roll:
            meta["roll_query"] = roll.group(0)
        return "unknown", meta

    def fuzzy_best_candidate(q, candidates, key=lambda x: x, score_cutoff=60):
        # naive fallback: return first candidate
        if not candidates:
            return None, 0
        return candidates[0], 100

    def chat_file_for_user(user):
        from pathlib import Path
        d = Path("chats")
        d.mkdir(exist_ok=True)
        return d / f"chat_{user['username']}.json"

    def load_chat_history_for(user):
        f = chat_file_for_user(user)
        if f.exists():
            try:
                return json.loads(open(f, "r", encoding="utf-8").read())
            except Exception:
                return []
        return []

    def save_chat_history_for(user, messages):
        f = chat_file_for_user(user)
        with open(f, "w", encoding="utf-8") as fw:
            json.dump(messages, fw, indent=2)

# Try importing DB utilities — if unavailable, fall back to sample functions
DB_AVAILABLE = True
try:
    from db_utils import (
        find_students_by_query,
        get_mentees,
        get_certificates_for_student,
        count_certificates,
        get_student_by_id,
        get_department_by_id,
        get_conn,
    )
except Exception:
    DB_AVAILABLE = False

# Try importing AI core (optional)
AI_AVAILABLE = False
try:
    from ai_core import call_gemini_short, AI_AVAILABLE as AI_FLAG
    AI_AVAILABLE = bool(AI_FLAG)
except Exception:
    AI_AVAILABLE = False

# -------------------------
# CONFIGURATION
# -------------------------
# Swap these to True to make the app attempt API-based login and data access.
USE_API = False  # If True, the app will try to call your Django endpoints (requires config below)
# API endpoints - if you want to enable API login, set these accordingly
API_BASE = "http://localhost:8000"  # override in-file or via environment variable
API_AUTH_JWT_CREATE = f"{API_BASE}/auth/jwt/create/"  # expects {"username","password"} -> returns token
API_ME = f"{API_BASE}/api/vmeg/auth/users/me/"  # GET with Authorization: Bearer <token>, returns {"username","mentor_id"}
API_TOKEN_HEADER = "Authorization"

# Admin simulated credentials (demo). Replace with your secure process in production.
ADMIN_SIM = {"username": "kondenagaruthvik@gmail.com", "password": "Ruthvik3234L"}

# Simulated mentor users for local demo (you asked for static as default + optional API)
SIMULATED_USERS = {
    "mentor5": {"username": "mentor5", "password": "mentor5", "mentor_id": 5, "role": "mentor"},
    "mentor1": {"username": "mentor1", "password": "mentor1", "mentor_id": 1, "role": "mentor"},
    "admin": {"username": "admin", "password": "admin", "mentor_id": None, "role": "admin"},
}

# UI constants
APP_TITLE = "MentorAssist — Mentor Chat"
CHAT_DIR = "chats"
os.makedirs(CHAT_DIR, exist_ok=True)

# Audit log (local file)
AUDIT_LOG = "mentorassist_audit.log"

# -------------------------
# SAMPLE DATA (fallback when DB unavailable)
# -------------------------
# Keep sample_students fairly rich so the app behaves as if it had DB responses
SAMPLE_STUDENTS = [
    {
        "id": 101,
        "first_name": "John",
        "last_name": "Doe",
        "roll_number": "23881A66K1",
        "batch_year": 2024,
        "current_semester": 2,
        "department_id": 2,
        "mentor_id": 5,
        "activity_score": 92,
    },
    {
        "id": 102,
        "first_name": "Jane",
        "last_name": "Smith",
        "roll_number": "23881A66J2",
        "batch_year": 2024,
        "current_semester": 2,
        "department_id": 2,
        "mentor_id": 5,
        "activity_score": 78,
    },
    {
        "id": 103,
        "first_name": "Bob",
        "last_name": "Brown",
        "roll_number": "23881A6617",
        "batch_year": 2024,
        "current_semester": 2,
        "department_id": 2,
        "mentor_id": 5,
        "activity_score": 85,
    },
    {
        "id": 104,
        "first_name": "Alice",
        "last_name": "Johnson",
        "roll_number": "23881A66F5",
        "batch_year": 2024,
        "current_semester": 2,
        "department_id": 2,
        "mentor_id": 5,
        "activity_score": 95,
    },
]

SAMPLE_CERTIFICATES = {
    104: [
        {"id": 1, "title": "DSA in Python", "issuing_organization": "Udemy", "status": "verified", "created_at": datetime(2024, 2, 10)},
        {"id": 2, "title": "Django Certificate", "issuing_organization": "Coursera", "status": "verified", "created_at": datetime(2024, 3, 12)},
        {"id": 3, "title": "NPTEL: Algorithms", "issuing_organization": "NPTEL", "status": "verified", "created_at": datetime(2023, 12, 1)},
    ],
    101: [
        {"id": 21, "title": "Python Basics", "issuing_organization": "FreeCodeCamp", "status": "verified", "created_at": datetime(2022, 5, 10)},
    ],
    102: [],
    103: [{"id": 31, "title": "Web Dev Bootcamp", "issuing_organization": "Udemy", "status": "verified", "created_at": datetime(2024, 1, 20)}],
}

SAMPLE_DEPARTMENTS = {
    1: {"id": 1, "name": "Electronics & Communication"},
    2: {"id": 2, "name": "Computer Science Engineering"},
    3: {"id": 3, "name": "Mechanical Engineering"},
    4: {"id": 4, "name": "Electrical Engineering"},
    5: {"id": 5, "name": "Information Technology"},
}

# -------------------------
# UTILITIES (DB-safe wrappers)
# -------------------------
def audit_log(action: str, user: Optional[Dict[str, Any]] = None, details: Optional[Dict[str, Any]] = None):
    """Append an audit entry to the audit log file."""
    entry = {
        "ts": datetime.utcnow().isoformat(),
        "user": user.get("username") if user else None,
        "action": action,
        "details": details or {},
    }
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        # best-effort only
        pass

def safe_get_mentees(mentor_id: int) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Return (mentees, error) using DB if available else sample data."""
    if not mentor_id:
        return [], None
    if DB_AVAILABLE:
        try:
            rows = get_mentees(mentor_id)
            return rows or [], None
        except Exception as e:
            return [], str(e)
    else:
        # filter sample
        out = [s for s in SAMPLE_STUDENTS if s.get("mentor_id") == mentor_id]
        return out, None

def safe_find_students(q: str, limit: int = 200) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    if DB_AVAILABLE:
        try:
            rows = find_students_by_query(q, limit=limit)
            return rows or [], None
        except Exception as e:
            return [], str(e)
    else:
        ql = (q or "").lower()
        rows = []
        for s in SAMPLE_STUDENTS:
            if ql in (s.get("roll_number") or "").lower() or ql in (s.get("first_name","").lower() + " " + s.get("last_name","").lower()):
                rows.append(s)
        return rows, None

def safe_get_certs(sid: int) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    if DB_AVAILABLE:
        try:
            rows = get_certificates_for_student(sid)
            return rows or [], None
        except Exception as e:
            return [], str(e)
    else:
        return SAMPLE_CERTIFICATES.get(sid, []), None

def safe_count_certs(sid: int) -> Tuple[int, Optional[str]]:
    if DB_AVAILABLE:
        try:
            cnt = count_certificates(sid)
            return cnt, None
        except Exception as e:
            return 0, str(e)
    else:
        return len(SAMPLE_CERTIFICATES.get(sid, [])), None

def safe_get_student_by_id(sid: int) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if DB_AVAILABLE:
        try:
            s = get_student_by_id(sid)
            return s, None
        except Exception as e:
            return None, str(e)
    else:
        for s in SAMPLE_STUDENTS:
            if s.get("id") == sid:
                return s, None
        return None, None

def safe_get_department(dept_id: int) -> Optional[Dict[str, Any]]:
    if DB_AVAILABLE:
        try:
            return get_department_by_id(dept_id)
        except Exception:
            return None
    else:
        return SAMPLE_DEPARTMENTS.get(dept_id)

# -------------------------
# MEMORY ENGINE (session-scoped)
# -------------------------
# Requirements from you:
# - When the mentor states "k1 is topper" it should "store" that fact in memory for session
# - The first time it stores, reply should be short "Noted: 'k1' → 'topper'."
# - Later when asked "who is k1" it should return the stored fact string
# - Memory should be session-scoped (stored in st.session_state.memory)
#
# Implementation:
# - st.session_state.memory is a dict: key -> list of values (history). Key normalized to lower case.
# - memory_store(key, value) appends and returns None (silently); the calling code will produce the user-visible confirmation message
# - memory_lookup(phrase) tries exact key match; if none, uses fuzzy matching across keys and across values
#
# NOTE: memory is not persisted beyond the login session (you asked for that behavior)
def memory_init():
    if "memory" not in st.session_state:
        st.session_state.memory = {}

def memory_store(key: str, value: str):
    key_n = (key or "").strip().lower()
    val = (value or "").strip()
    if not key_n or not val:
        return
    if key_n in st.session_state.memory:
        st.session_state.memory[key_n].append(val)
    else:
        st.session_state.memory[key_n] = [val]

def memory_lookup(phrase: str) -> Optional[str]:
    """
    Attempt to return a remembered sentence for 'phrase'.
    Behavior:
     - exact key match -> return latest value (string)
     - fuzzy key match (partial) -> return latest value if score >= threshold
     - fuzzy value search -> return latest key (so 'who is topper' returns 'k1' if value matched)
     - fallback: search recent chat messages for a text containing phrase
    """
    from rapidfuzz import fuzz

    if not phrase:
        return None
    phrase_l = phrase.strip().lower()

    # 1) exact key match
    if phrase_l in st.session_state.memory:
        vals = st.session_state.memory[phrase_l]
        return vals[-1] if vals else None

    # 2) fuzzy match on keys
    best_key = None
    best_score = 0
    for k in st.session_state.memory.keys():
        score = fuzz.partial_ratio(phrase_l, k)
        if score > best_score:
            best_score = score
            best_key = k
    if best_key and best_score >= 65:
        vals = st.session_state.memory.get(best_key)
        return vals[-1] if vals else None

    # 3) fuzzy match inside values -> return the SUBJECT (key)
    for k, vals in st.session_state.memory.items():
        for v in vals:
            score = fuzz.partial_ratio(phrase_l, v.lower())
            if score >= 65:
                # return the subject (key)
                return k

    # 4) fallback: search recent messages
    for msg in reversed(st.session_state.messages[-60:]):
        text = msg.get("content", "").lower()
        if phrase_l in text:
            return msg.get("content")

    return None

# -------------------------
# Helper: pretty profile text builder
# -------------------------
def pretty_student_profile(student: Dict[str, Any], certs: List[Dict[str, Any]], dept_name: Optional[str], mentor_name: Optional[str], cert_count: Optional[int], activity_score: Optional[Any]) -> str:
    lines = []
    lines.append("📌 STUDENT PROFILE")
    lines.append("-" * 36)
    lines.append(f"Name        : {student.get('first_name','')} {student.get('last_name','')}")
    lines.append(f"Roll Number : {student.get('roll_number','')}")
    lines.append(f"Batch       : {student.get('batch_year','')}")
    lines.append(f"Semester    : {student.get('current_semester','')}")
    lines.append(f"Department  : {dept_name or 'N/A'}")
    lines.append(f"Mentor      : {mentor_name or 'N/A'}")
    lines.append(f"Activity    : {activity_score if activity_score is not None else 'Not available'}")
    lines.append(f"Certificates: {cert_count if cert_count is not None else 'N/A'}")
    lines.append("")
    lines.append("Certificates (top 50):")
    if not certs:
        lines.append("- No certificates recorded.")
    else:
        for c in certs[:50]:
            title = c.get("title", "Untitled")
            org = c.get("issuing_organization", "")
            status = c.get("status", "")
            created = c.get("created_at")
            if isinstance(created, datetime):
                created = created.strftime("%Y-%m-%d")
            lines.append(f"- {title} [{status}] ({org}) - {created}")
    return "\n".join(lines)

# -------------------------
# UI / Main App
# -------------------------
st.set_page_config(page_title=APP_TITLE, layout="wide")
st.title(APP_TITLE)
st.write("MentorAssist — Mentor Chat. Use the sidebar to login and test features. This app supports simulated login (default) and optional API login (configure `USE_API = True`).")

# Sidebar: login
st.sidebar.header("Login / Session")
st.sidebar.info("By default the app uses simulated users (no API). To use your Django APIs set USE_API = True and configure the top API_* constants.")

# We offer two login modes:
# 1) Simulated login (default) - no password checks (local demo)
# 2) Optional API login (when USE_API True) - calls /auth/jwt/create/ and GET /api/me/
#
# The UI shows both controls but only one path executes depending on the USE_API flag.

# Initialize session defaults
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user" not in st.session_state:
    st.session_state.user = None
if "messages" not in st.session_state:
    st.session_state.messages = []
memory_init()

# Buttons to clear chat file or show audit logs
with st.sidebar.expander("Admin & Debug"):
    st.sidebar.write(f"DB available: {'Yes' if DB_AVAILABLE else 'No'}")
    st.sidebar.write(f"LLM available: {'Yes' if AI_AVAILABLE else 'No'}")
    if st.sidebar.button("Show audit log (last 50 lines)"):
        out = []
        try:
            with open(AUDIT_LOG, "r", encoding="utf-8") as f:
                lines = f.readlines()[-50:]
                for l in lines:
                    try:
                        out.append(json.loads(l))
                    except Exception:
                        out.append({"raw": l})
        except Exception as e:
            st.sidebar.error(f"Failed reading audit: {e}")
            out = []
        st.sidebar.write(out)
    if st.sidebar.button("Clear session (logout)"):
        # Delete user chat file to start fresh
        if st.session_state.user:
            try:
                fpath = chat_file_for_user(st.session_state.user)
                if os.path.exists(fpath):
                    os.remove(fpath)
            except Exception:
                pass
        st.session_state.logged_in = False
        st.session_state.user = None
        st.session_state.messages = []
        st.session_state.memory = {}
        st.sidebar.success("Session cleared. Please login again.")
        st.rerun()

# Display login options
login_mode = st.sidebar.radio("Login mode", options=["Simulated (default)", "API (use your Django endpoints)"])

# Filling the login inputs
if login_mode == "API (use your Django endpoints)":
    st.sidebar.caption("API mode: will POST to auth/jwt/create/ then GET /api/vmeg/auth/users/me/. Set USE_API=True in the file to enable behavior.")
    api_user = st.sidebar.text_input("API username", key="api_user")
    api_pass = st.sidebar.text_input("API password", type="password", key="api_pass")
    if st.sidebar.button("Login via API"):
        if not USE_API:
            st.sidebar.warning("API mode not enabled in the script (USE_API=False). Edit the file or set USE_API=True in top config to enable.")
        else:
            # Attempt API login
            try:
                import requests
                resp = requests.post(API_AUTH_JWT_CREATE, json={"username": api_user, "password": api_pass}, timeout=8)
                if resp.status_code == 200:
                    token = resp.json().get("access") or resp.json().get("token") or resp.json().get("access_token")
                    if not token:
                        st.sidebar.error("Auth response did not include token. Check your endpoint.")
                    else:
                        headers = {"Authorization": f"Bearer {token}"}
                        me = requests.get(API_ME, headers=headers, timeout=8)
                        if me.status_code == 200:
                            profile = me.json()
                            # expected response: {"username": "...", "mentor_id": 5}
                            mentor_id = profile.get("mentor_id")
                            username = profile.get("username") or api_user
                            st.sidebar.success(f"Logged in as {username} (mentor_id={mentor_id})")
                            st.session_state.logged_in = True
                            st.session_state.user = {"username": username, "mentor_id": mentor_id, "role": "mentor", "api_token": token}
                            st.session_state.messages = []
                            st.session_state.memory = {}
                            audit_log("api_login", st.session_state.user, {"via": "api"})
                            st.rerun()
                        else:
                            st.sidebar.error(f"/me failed: {me.status_code} {me.text}")
                else:
                    st.sidebar.error(f"Auth failed: {resp.status_code} {resp.text}")
            except Exception as e:
                st.sidebar.error(f"API login error: {e}")
else:
    # Simulated login UI
    st.sidebar.caption("Simulated login for demo/testing (no external API calls).")
    sim_user = st.sidebar.selectbox("Simulated user", options=list(SIMULATED_USERS.keys()), index=0)
    sim_pass = st.sidebar.text_input("Password (simulated)", type="password", key="sim_pass")
    if st.sidebar.button("Login (simulated)"):
        user = SIMULATED_USERS.get(sim_user)
        if user and sim_pass == user.get("password"):
            # Delete prior chat file to start fresh each login (as requested)
            try:
                f = chat_file_for_user(user)
                if os.path.exists(f):
                    os.remove(f)
            except Exception:
                pass
            st.session_state.logged_in = True
            st.session_state.user = user.copy()
            st.session_state.messages = []
            st.session_state.memory = {}
            st.sidebar.success(f"Simulated login: {user['username']}")
            audit_log("simulated_login", st.session_state.user, {"sim_user": sim_user})
            st.rerun()
        else:
            st.sidebar.error("Invalid simulated credentials")

# If not logged in, stop (user must login to use chat)
if not st.session_state.logged_in or not st.session_state.user:
    st.info("Please login from the sidebar to use MentorAssist.")
    st.stop()

# At this point user is logged in
user = st.session_state.user
username = user.get("username")
role = user.get("role", "mentor")
mentor_id = user.get("mentor_id")  # may be None for admin

# Show top bar info and quick actions
st.sidebar.markdown("---")
st.sidebar.write(f"**User:** {username}")
st.sidebar.write(f"**Role:** {role}")
st.sidebar.write(f"**Mentor ID:** {mentor_id}")
st.sidebar.markdown("---")

# Load mentees for mentor (safe)
mentees_list, mentees_err = safe_get_mentees(mentor_id) if mentor_id else ([], None)
if mentees_err:
    st.sidebar.error(f"Failed to load mentees: {mentees_err}")

st.sidebar.subheader("Your mentees")
if mentees_list:
    for m in mentees_list:
        st.sidebar.write(f"- {m.get('first_name','')} {m.get('last_name','')} ({m.get('roll_number','')})")
else:
    st.sidebar.write("No mentees found (or DB unavailable).")

# Chat display area
st.subheader("Mentor Chat")
for msg in st.session_state.messages:
    role_msg = msg.get("role", "user")
    with st.chat_message(role_msg):
        st.markdown(msg.get("content", ""))

# Input box (main)
query = st.chat_input("Ask about your mentees... (examples: 'profile of 23881A66F5', 'certificates of 23881A66F5', 'who is topper', 'mentees')")

# Helper: resolve student by meta (roll or name)
def resolve_student_from_meta(meta: Dict[str, Any], prefer_mentees: bool = True) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Returns (student, error_message)
    - meta contains roll_query or name_query
    - prefer_mentees: if True, prefer matching among the logged-in mentor's mentees
    """
    q = meta.get("roll_query") or meta.get("name_query")
    if not q:
        return None, "No search term given."

    found, err = safe_find_students(q, limit=200)
    if err:
        return None, f"DB error: {err}"

    # prefer exact/suffix roll match
    q_low = q.lower()
    if found:
        for f in found:
            rn = (f.get("roll_number") or "").lower()
            if rn == q_low or rn.endswith(q_low) or q_low in rn:
                # enforce mentor scoping: mentors can only see their mentees
                if role == "mentor" and f.get("mentor_id") != mentor_id:
                    return None, "Access denied — not your mentee."
                return f, None

        # prefer among mentees if requested
        if prefer_mentees and mentees_list:
            mentee_ids = {m["id"] for m in mentees_list}
            mentee_candidates = [f for f in found if f.get("id") in mentee_ids]
            if mentee_candidates:
                cand, score = fuzzy_best_candidate(q, mentee_candidates, key=lambda x: f"{x.get('first_name','')} {x.get('last_name','')} {x.get('roll_number','')}", score_cutoff=55)
                if cand:
                    return cand, None
                return mentee_candidates[0], None

        # fuzzy among found
        cand, score = fuzzy_best_candidate(q, found, key=lambda x: f"{x.get('first_name','')} {x.get('last_name','')} {x.get('roll_number','')}", score_cutoff=50)
        if cand:
            if role == "mentor" and cand.get("mentor_id") != mentor_id:
                return None, "Access denied — not your mentee."
            return cand, None
        return found[0], None

    # no DB results: try fuzzy among mentees
    if mentees_list:
        cand, score = fuzzy_best_candidate(q, mentees_list, key=lambda x: f"{x.get('first_name','')} {x.get('last_name','')} {x.get('roll_number','')}", score_cutoff=50)
        if cand:
            return cand, None

    return None, None

# Process query
if query:
    # Save user message
    st.session_state.messages.append({"role": "user", "content": query})
    save_chat_history_for(user, st.session_state.messages)
    audit_log("user_query", user, {"query": query})

    # parse intent
    intent, meta = parse_intent(query)
    reply = ""

    # Handle common intents
    try:
        # Greeting
        if intent == "greeting":
            reply = "Hello! 👋 How can I help you with your mentees today?"

        # Mentees list
        elif intent == "mentees":
            if not mentees_list:
                reply = "You have no mentees (or DB is unavailable)."
            else:
                lines = [f"{m.get('first_name','')} {m.get('last_name','')} — Roll: {m.get('roll_number','')}" for m in mentees_list]
                reply = "\n\n".join(lines)

        # Count mentees
        elif intent == "count_mentees":
            reply = f"You have {len(mentees_list)} mentees."

        # Name lookup (name of roll or name query)
        elif intent == "name_lookup":
            student, err = resolve_student_from_meta(meta)
            if err:
                reply = err
            elif not student:
                reply = "No student found."
            else:
                reply = f"Name: {student.get('first_name','')} {student.get('last_name','')} — Roll: {student.get('roll_number','')}"

        # Activity score
        elif intent == "activity_score":
            student, err = resolve_student_from_meta(meta)
            if err:
                reply = err
            elif not student:
                reply = "No student found."
            else:
                score = student.get("activity_score")
                reply = f"Activity score of {student.get('roll_number','')} is {score if score is not None else 'Not available'}."

        # Certificates or certificate count
        elif intent in ("certificates", "count_certificates", "summarize_certificates"):
            student, err = resolve_student_from_meta(meta)
            if err:
                reply = err
            elif not student:
                reply = "No student found."
            else:
                sid = student.get("id")
                certs, c_err = safe_get_certs(sid)
                if c_err:
                    reply = f"DB error fetching certificates: {c_err}"
                else:
                    if intent == "count_certificates":
                        cnt, _ = safe_count_certs(sid)
                        reply = f"{student.get('first_name','Student')} has {cnt} certificates."
                    elif intent == "summarize_certificates":
                        # produce a short summary (non-LLM)
                        titles = [c.get("title","Untitled") for c in certs]
                        cnt = len(titles)
                        if cnt == 0:
                            reply = "No certificates recorded."
                        else:
                            top3 = titles[:3]
                            reply = f"{student.get('first_name','Student')} has {cnt} certificates. Top examples: " + ", ".join(top3)
                    else:
                        if not certs:
                            reply = f"No certificates found for {student.get('first_name','Student')}."
                            if AI_AVAILABLE:
                                guidance_prompt = (
                                    f"Student {student.get('first_name','Student')} (roll {student.get('roll_number')}) has 0 certificates. "
                                    "As an expert mentor, provide 2 short actionable steps to start building credentials."
                                )
                                try:
                                    guidance = call_gemini_short(guidance_prompt)
                                    if guidance and not guidance.lower().startswith("ai error"):
                                        reply += f"\n\nGuidance:\n{guidance}"
                                except Exception:
                                    pass
                        else:
                            titles = [c.get("title","Untitled") for c in certs]
                            reply = "Certificates:\n- " + "\n- ".join(titles[:50])

        # Profile lookup (admin-style)
        elif intent == "profile":
            # admin can lookup anyone, mentor only their mentees
            student, err = resolve_student_from_meta(meta, prefer_mentees=True)
            if err:
                reply = err
            elif not student:
                reply = "No student found."
            else:
                sid = student.get("id")
                certs, _ = safe_get_certs(sid)
                cnt, _ = safe_count_certs(sid)
                dept = safe_get_department(student.get("department_id"))
                dept_name = dept.get("name") if dept else None
                mentor_name = None
                try:
                    if student.get("mentor_id"):
                        mrec, merr = safe_get_student_by_id(student.get("mentor_id"))
                        # most likely mentor lookup via faculty table; we'll fallback to ID text
                        mentor_name = f"Mentor ID {student.get('mentor_id')}"
                except Exception:
                    mentor_name = f"Mentor ID {student.get('mentor_id')}"
                activity = student.get("activity_score", "Not available")
                profile_text = pretty_student_profile(student, certs or [], dept_name, mentor_name, cnt, activity)
                # LLM assistance (optional)
                if AI_AVAILABLE:
                    payload = {
                        "student": {
                            "id": student.get("id"),
                            "name": f"{student.get('first_name','')} {student.get('last_name','')}",
                            "roll": student.get("roll_number"),
                            "batch": student.get("batch_year"),
                            "semester": student.get("current_semester"),
                            "department": dept_name,
                            "activity_score": activity,
                            "certificate_count": cnt,
                        },
                        "certificates": certs[:50] if certs else [],
                    }
                    try:
                        llm_prompt = (
                            "You are AdminAssist. Using ONLY the JSON below, produce:\n"
                            "1) a one-line summary of the student's certificate profile,\n"
                            "2) two concise mentor action items (each on its own line).\n\n"
                            + json.dumps(payload, indent=2)
                        )
                        llm_resp = call_gemini_short(llm_prompt)
                        if llm_resp and not llm_resp.lower().startswith("ai error"):
                            profile_text += "\n\nLLM SUMMARY & GUIDANCE:\n" + llm_resp
                    except Exception:
                        profile_text += "\n\n(LLM summary failed.)"
                reply = profile_text

        # Memory lookup (who is X)
        elif intent == "memory_lookup":
            phrase = (meta.get("memory_phrase") or "").strip()
            if not phrase:
                reply = "No phrase provided."
            else:
                mem = memory_lookup(phrase)
                if mem:
                    reply = f"I found this earlier in our chat: \"{mem}\""
                else:
                    # try to resolve as student
                    s, err = resolve_student_from_meta({"roll_query": phrase, "name_query": phrase})
                    if s:
                        reply = f"{s.get('first_name','')} {s.get('last_name','')} — Roll: {s.get('roll_number','')}"
                    else:
                        reply = "I couldn't find that phrase in our conversation or mentee list."

        # If none of the above: attempt to store simple fact "X is Y" or fallback to LLM-limited
        else:
            stored = False
            # store simple sentences of form "<subject> is <predicate>"
            m = re.match(r"^\s*([A-Za-z0-9\-_\. ]+?)\s+is\s+(.+)$", query.strip(), flags=re.IGNORECASE)
            if m:
                subj = m.group(1).strip()
                desc = m.group(2).strip()
                # Store in memory under normalized subject key
                memory_store(subj, desc)
                # Per your requirement: short confirmation (no long 'I'll remember' line)
                reply = f"Noted: '{subj}' → '{desc}'."
                stored = True
                audit_log("memory_store", user, {"subject": subj, "desc": desc})
            if not stored:
                # LLM fallback limited to student list and recent chat (if AI available)
                allowed_small = [{"id": m.get("id"), "name": f"{m.get('first_name','')} {m.get('last_name','')}", "roll": m.get("roll_number","")} for m in (mentees_list or [])]
                recent_chat = st.session_state.messages[-16:]
                prompt = (
                    "You are MentorAssist AI. Use ONLY the facts provided below about students and the recent conversation to answer. "
                    "If the user asks about a student not in the provided student list, reply 'Access Denied'. "
                    "Answer concisely and do NOT hallucinate.\n\n"
                    f"STUDENTS:\n{json.dumps(allowed_small, indent=2)}\n\n"
                    f"RECENT_CHAT:\n{json.dumps(recent_chat, indent=2)}\n\n"
                    f"USER QUESTION:\n{query}\n\nAnswer:"
                )
                if AI_AVAILABLE:
                    try:
                        llm_reply = call_gemini_short(prompt)
                        if llm_reply and not llm_reply.lower().startswith("ai error"):
                            reply = llm_reply
                        else:
                            reply = "I can answer: name, activity score, certificates, certificate count, mentees, mentee count. (LLM fallback failed.)"
                    except Exception:
                        reply = "I can answer: name, activity score, certificates, certificate count, mentees, mentee count. (LLM error.)"
                else:
                    reply = "I can answer: name, activity score, certificates, certificate count, mentees, mentee count. (LLM not configured.)"

    except Exception as ex:
        reply = f"Internal error while processing query: {ex}"
        # include traceback in audit log
        audit_log("error_processing_query", user, {"query": query, "error": str(ex), "trace": traceback.format_exc()})

    # persist reply and save chat
    st.session_state.messages.append({"role": "assistant", "content": reply})
    save_chat_history_for(user, st.session_state.messages)
    audit_log("assistant_reply", user, {"reply_preview": reply[:200]})

    # show reply
    with st.chat_message("assistant"):
        st.markdown(reply)

# EOF of conversation handling
# Additional notes & helper commands shown in the UI bottom area

st.markdown("---")
st.subheader("Quick testing & help")
st.markdown(
    """
Try these example queries (copy-paste into the chat box):

- `hi`
- `mentees`
- `how many mentees`
- `profile of 23881A66F5`
- `certificates of 23881A66F5`
- `how many certificates does 23881A66F5 have`
- `activity score of 23881A66F5`
- `who is topper`
- `k1 is topper`  (stores memory)
- `who is k1`    (retrieves memory)

Notes:
- Mentors only see their mentees. Admin role can access full profiles.
- Memory is session-scoped and cleared on logout.
- If you want to enable API login, set USE_API = True and configure API_* constants at top.
"""
)



# End of file
