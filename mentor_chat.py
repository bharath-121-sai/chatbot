# mentor_chat.py — Dynamic Login via Django API (GET /api/me)
# Full-featured MentorAssist — Mentor Chat (production-ready)
#
# Features:
# - Dynamic mentor login via GET /api/me (no passwords in Streamlit)
# - Mentor sees only their mentees (enforced)
# - Fuzzy search + partial roll support
# - Persistent chat history per mentor (saved to ./chats/chat_<username>.json)
# - In-session memory engine (store short facts; retrieval on later queries)
#   * When a fact is stored the bot responds succinctly with "k." (per your request).
#   * On subsequent queries it can retrieve stored facts.
# - Certificates: list, count, summary (LLM optional)
# - Activity score retrieval (reads DB field if present)
# - Profile lookup (full cleaned profile)
# - Robust DB error handling with helpful messages
# - LLM guidance when AI_AVAILABLE is True in ai_core.py
# - Exports: chat JSON download, CSV export of query results
# - Pagination for long lists (mentees / students)
#
# Requirements:
# - shared_utils.py providing: parse_intent, fuzzy_best_candidate, load_chat_history_for, save_chat_history_for, chat_file_for_user
# - db_utils.py providing: find_students_by_query, get_mentees, get_certificates_for_student, count_certificates, get_student_by_id, get_department_by_id, get_conn
# - ai_core.py providing: call_gemini_short, AI_AVAILABLE
# - requests (for GET /api/me)
#
# How it works:
# - The Streamlit app attempts to call GET {BASE_API_URL}/api/me using optional cookies
#   (you can configure BASE_API_URL via env var MENTORASSIST_BASE_API or edit below).
# - If the API responds with {"username": "...", "mentor_id": ...} the mentor is considered logged in.
# - If the API call fails or the endpoint is not present, the UI shows a fallback "Simulated login" option.
#
# Usage:
#   STREAMLIT:
#     streamlit run mentor_chat.py
#
# Notes:
# - This is a single-file implementation for easy deployment and testing.
# - You can adapt authentication and DB access to your environment as needed.
# -----------------------------------------------------------------------------

import os
import sys
import json
import re
import io
import traceback
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
import requests
import streamlit as st

# Project-local utilities — make sure these modules exist in the repo
from shared_utils import (
    parse_intent,
    fuzzy_best_candidate,
    load_chat_history_for,
    save_chat_history_for,
    chat_file_for_user,
)
from db_utils import (
    find_students_by_query,
    get_mentees,
    get_certificates_for_student,
    count_certificates,
    get_student_by_id,
    get_department_by_id,
    get_conn,
)
from ai_core import call_gemini_short, AI_AVAILABLE

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
APP_TITLE = "MentorAssist — Mentor Chat (Dynamic Login via API)"
PAGE_SIZE = 30  # pagination for lists
CHAT_DIR = "chats"
AUDIT_LOG = "mentor_audit.log"
# Base API URL for GET /api/me — set MENTORASSIST_BASE_API env var if needed
BASE_API_URL = os.environ.get("MENTORASSIST_BASE_API", "http://localhost:8000")

# Create chat dir if missing
os.makedirs(CHAT_DIR, exist_ok=True)

# Streamlit page config
st.set_page_config(page_title=APP_TITLE, layout="wide")
st.title(APP_TITLE)
st.caption("Dynamic login via GET /api/me (if available). Mentor sees only their mentees.")

# ---------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------
def audit(action: str, user: Optional[Dict[str, Any]], details: Optional[Dict[str, Any]] = None):
    """Append an audit log entry (non-critical)."""
    try:
        entry = {
            "ts": datetime.utcnow().isoformat(),
            "action": action,
            "user": user.get("username") if user else None,
            "details": details or {}
        }
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        # do not crash on audit failure
        pass

def safe_db_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs), None
    except Exception as e:
        return None, str(e)

def dicts_to_csv_bytes(dicts: List[Dict[str, Any]]) -> bytes:
    """Convert list of dicts to CSV (UTF-8 bytes)."""
    if not dicts:
        return b""
    # collect header
    keys = sorted({k for d in dicts for k in d.keys()})
    output = io.StringIO()
    # write header
    output.write(",".join(keys) + "\n")
    for d in dicts:
        row = []
        for k in keys:
            v = d.get(k, "")
            if isinstance(v, datetime):
                row.append(v.isoformat())
            else:
                # escape double quotes
                s = str(v).replace('"', '""')
                if "," in s or "\n" in s:
                    s = f'"{s}"'
                row.append(s)
        output.write(",".join(row) + "\n")
    return output.getvalue().encode("utf-8")

def pretty_student_profile(student: Dict[str, Any], certs: List[Dict[str, Any]], dept_name: Optional[str], mentor_name: Optional[str]) -> str:
    """Build a readable profile text block."""
    lines = []
    lines.append("📌 STUDENT PROFILE")
    lines.append("-" * 40)
    lines.append(f"Name         : {student.get('first_name','')} {student.get('last_name','')}")
    lines.append(f"Roll Number  : {student.get('roll_number','')}")
    lines.append(f"Batch        : {student.get('batch_year','')}")
    lines.append(f"Semester     : {student.get('current_semester','')}")
    lines.append(f"Department   : {dept_name or 'N/A'}")
    lines.append(f"Mentor       : {mentor_name or 'N/A'}")
    lines.append(f"Activity     : {student.get('activity_score', 'Not available')}")
    lines.append(f"Certificates : {len(certs) if certs is not None else 'N/A'}")
    lines.append("")
    lines.append("Certificates (top 50):")
    if certs:
        for c in certs[:50]:
            title = c.get("title", "Untitled")
            status = c.get("status", "")
            created = c.get("created_at")
            if isinstance(created, datetime):
                created = created.strftime("%Y-%m-%d")
            lines.append(f"- {title} [{status}] ({created})")
    else:
        lines.append("- No certificates recorded.")
    return "\n".join(lines)

# ---------------------------------------------------------------------
# Session initialization
# ---------------------------------------------------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user = None  # {"username": "...", "mentor_id": int}
    st.session_state.messages = []
    st.session_state.memory = {}  # key -> list of values
    st.session_state.mentees = []
    st.session_state.loading_warning_shown = False

# ---------------------------------------------------------------------
# Authentication: Try GET /api/me first, otherwise show simulated login
# ---------------------------------------------------------------------
def call_api_me(session_cookies: Optional[Dict[str, str]] = None, timeout: int = 5) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Call GET {BASE_API_URL}/api/me to retrieve {"username": "...", "mentor_id": ...}
    Returns (json, error_string)
    """
    url = f"{BASE_API_URL.rstrip('/')}/api/me"
    try:
        # If cookies provided, pass them; else rely on default requests session
        if session_cookies:
            resp = requests.get(url, cookies=session_cookies, timeout=timeout)
        else:
            resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            return None, f"API returned status {resp.status_code}"
        data = resp.json()
        # Validate shape
        if not isinstance(data, dict) or "username" not in data or "mentor_id" not in data:
            return None, "API returned unexpected payload (expecting username & mentor_id)"
        return data, None
    except Exception as e:
        return None, str(e)

def perform_login_via_api_or_simulated():
    """
    Attempt to login automatically using /api/me.
    If that fails, expose simulated login box (username only).
    """
    st.sidebar.header("Login (Dynamic / Simulated)")
    st.sidebar.write("Preferred: log in via web portal (session cookie). Fallback: simulated login.")

    # 1) Try API /api/me if user hasn't explicitly chosen simulated login
    use_simulated = st.sidebar.checkbox("Use simulated login instead of API", value=False)

    if not use_simulated:
        # Attempt to call API - we won't pass cookies unless provided by user.
        # Provide an input area where user may paste session cookie if needed.
        cookie_input = st.sidebar.text_input("Optional: session cookie string (e.g. sessionid=...)", value="", help="If your Django site uses a session cookie, paste it here to let Streamlit call /api/me.")
        cookies = None
        if cookie_input:
            # parse cookie string "k1=v1; k2=v2"
            try:
                parts = [p.strip() for p in cookie_input.split(";") if p.strip()]
                cookies = {}
                for p in parts:
                    if "=" in p:
                        kk, vv = p.split("=", 1)
                        cookies[kk.strip()] = vv.strip()
            except Exception:
                cookies = None

        if st.sidebar.button("Login via API (/api/me)"):
            st.sidebar.info("Attempting /api/me ...")
            data, err = call_api_me(session_cookies=cookies)
            if err:
                st.sidebar.error(f"/api/me failed: {err}")
                st.sidebar.warning("You can use simulated login or provide correct cookie.")
                audit("api_me_failed", None, {"error": err})
            else:
                # Success -> set session user
                st.session_state.logged_in = True
                st.session_state.user = {"username": data["username"], "mentor_id": int(data["mentor_id"])}
                st.session_state.messages = []
                st.session_state.memory = {}
                st.success(f"Logged in as {data['username']} (mentor id: {data['mentor_id']}) via API")
                audit("login_api", st.session_state.user)
                # Load mentees immediately
                load_mentees_for_session()

    # 2) Simulated login fallback
    st.sidebar.markdown("---")
    st.sidebar.subheader("Simulated login (fallback)")
    sim_user = st.sidebar.text_input("Mentor username (e.g., mentor5)", value="", key="sim_user")
    if st.sidebar.button("Simulated login"):
        # attempt to discover mentor_id from DB using username fuzzy search
        # We'll attempt to find by 'mentor' in faculty table via db_utils; if not available, require static mapping
        # Try a DB lookup for faculty by username (safe wrapper)
        # Because db_utils may not provide direct user lookup, we simply ask the user to enter mentor ID if not resolvable.
        # Ask the user for mentor id if not known
        suggested_mid = None
        try:
            # Try to find mentees for small candidate mentor ids 1..1000 to guess? (not safe)
            # Instead ask for mentor id prompt below
            pass
        except Exception:
            pass

        # Ask for mentor id via sidebar
        mid_input = st.sidebar.text_input("Enter mentor id (required for simulated login)", value="", key="sim_mid")
        if mid_input:
            try:
                mid = int(mid_input)
                st.session_state.logged_in = True
                st.session_state.user = {"username": sim_user or f"sim_{mid}", "mentor_id": mid}
                st.session_state.messages = []
                st.session_state.memory = {}
                st.success(f"Simulated login as {st.session_state.user['username']} (mentor id: {mid})")
                audit("login_simulated", st.session_state.user)
                load_mentees_for_session()
            except Exception:
                st.sidebar.error("Invalid mentor id. Must be integer.")
        else:
            st.sidebar.info("Enter mentor id to complete simulated login.")

def load_mentees_for_session():
    """Load mentees for current mentor into session state (safe)."""
    if not st.session_state.logged_in or not st.session_state.user:
        return
    mid = st.session_state.user.get("mentor_id")
    if mid is None:
        st.sidebar.warning("Mentor id not available.")
        return
    mentees, err = safe_db_call(get_mentees, mid)
    if err:
        st.sidebar.error(f"DB error loading mentees: {err}")
        st.session_state.mentees = []
        audit("load_mentees_error", st.session_state.user, {"error": err})
    else:
        st.session_state.mentees = mentees or []
        audit("load_mentees", st.session_state.user, {"count": len(st.session_state.mentees)})

# Run login flow (on page load)
perform_login_via_api_or_simulated()

# If logged in, show logout and user info in sidebar
if st.session_state.logged_in and st.session_state.user:
    with st.sidebar:
        st.markdown("---")
        st.markdown(f"**User:** {st.session_state.user['username']}")
        st.markdown(f"**Role:** Mentor")
        st.markdown(f"**Mentor ID:** {st.session_state.user['mentor_id']}")
        if st.button("Logout"):
            # clear chat file for safety and reset session
            try:
                f = chat_file_for_user(st.session_state.user)
                if os.path.exists(f):
                    os.remove(f)
            except Exception:
                pass
            audit("logout", st.session_state.user)
            st.session_state.logged_in = False
            st.session_state.user = None
            st.session_state.messages = []
            st.session_state.memory = {}
            st.session_state.mentees = []
            st.experimental_rerun()

# If still not logged in, stop UI here
if not st.session_state.logged_in or not st.session_state.user:
    st.info("Please login via the sidebar (API or simulated) to continue.")
    st.stop()

# ---------------------------------------------------------------------
# After login: display mentees in sidebar and main header
# ---------------------------------------------------------------------
user = st.session_state.user
mentor_id = user["mentor_id"]

st.sidebar.subheader("Your mentees")
if not st.session_state.get("mentees"):
    # attempt load once more
    load_mentees_for_session()

mentees = st.session_state.get("mentees", [])
if mentees:
    for m in mentees[:PAGE_SIZE]:
        st.sidebar.write(f"- {m.get('first_name','')} {m.get('last_name','')} ({m.get('roll_number','')})")
    if len(mentees) > PAGE_SIZE:
        st.sidebar.write(f"... and {len(mentees)-PAGE_SIZE} more")
else:
    st.sidebar.write("No mentees found or DB unavailable.")

# ---------------------------------------------------------------------
# Chat UI: render history
# ---------------------------------------------------------------------
st.subheader("Mentor Chat")
for m in st.session_state.messages:
    with st.chat_message(m.get("role", "user")):
        st.markdown(m.get("content", ""))

# Input box
query = st.chat_input("Ask about your mentees... (examples: 'profile of 23881A66F5', 'certificates of 23881A66F5', 'who is topper')")

# ---------------------------------------------------------------------
# Memory engine (session only)
# ---------------------------------------------------------------------
def memory_store(key: str, value: str) -> None:
    """
    Store a memory entry.
    - key: subject (lowercased)
    - value: short description string
    Behavior:
      - If key exists, append to list
      - Reply to user with 'k.' after storing (per your request)
    """
    if not key or not value:
        return
    k = key.strip().lower()
    v = value.strip()
    lst = st.session_state.memory.get(k)
    if lst is None:
        st.session_state.memory[k] = [v]
    else:
        lst.append(v)
        st.session_state.memory[k] = lst

def memory_lookup(phrase: str) -> Optional[str]:
    """
    Lookup logic (priority):
    1) exact key match returns the latest stored value
    2) fuzzy key match (token_set/partial) returns latest value if score >= 60
    3) fuzzy match inside values returns key (subject) if phrase maps to a value
    4) fuzzy over chat messages returns matched message content
    """
    if not phrase:
        return None
    phrase = phrase.strip().lower()

    # 1) exact key
    if phrase in st.session_state.memory:
        val = st.session_state.memory[phrase]
        return val[-1] if isinstance(val, list) else val

    # 2) fuzzy key match
    best_key = None
    best_score = 0
    # rapidfuzz import (local) via shared_utils fuzzy_best_candidate uses rapidfuzz; but to avoid circular use, import here
    try:
        from rapidfuzz import fuzz
        for k, vals in st.session_state.memory.items():
            score = fuzz.partial_ratio(phrase, k)
            if score > best_score:
                best_score = score
                best_key = k
        if best_key and best_score >= 60:
            vals = st.session_state.memory.get(best_key)
            return vals[-1] if isinstance(vals, list) else vals
    except Exception:
        # if rapidfuzz not present, fallback to substring match
        for k, vals in st.session_state.memory.items():
            if phrase in k:
                vals = st.session_state.memory[k]
                return vals[-1] if isinstance(vals, list) else vals

    # 3) fuzzy inside values -> return subject (key)
    try:
        from rapidfuzz import fuzz
        for k, vals in st.session_state.memory.items():
            for v in (vals if isinstance(vals, list) else [vals]):
                score = fuzz.partial_ratio(phrase, v.lower())
                if score >= 70:
                    # When the phrase matches a value, return the subject (key)
                    return k
    except Exception:
        for k, vals in st.session_state.memory.items():
            for v in (vals if isinstance(vals, list) else [vals]):
                if phrase in str(v).lower():
                    return k

    # 4) search recent chat messages
    for msg in reversed(st.session_state.messages):
        txt = msg.get("content", "").lower()
        if phrase in txt:
            return msg.get("content")

    return None

# ---------------------------------------------------------------------
# Helper: student resolution (search + fuzzy) tailored for mentor scope
# ---------------------------------------------------------------------
def find_student_within_scope(meta: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Resolve a student using meta (roll_query or name_query).
    Ensures that resolved student is in the mentor's mentee list; otherwise returns access denied.
    Returns (student, error_string).
    """
    q = meta.get("roll_query") or meta.get("name_query")
    if not q:
        return None, "No search term provided."

    # 1) Try DB-wide search
    found, err = safe_db_call(find_students_by_query, q, 200)
    if err:
        # DB error -> try local mentee fuzzy fallback
        found = []
    else:
        found = found or []

    q_low = q.lower()

    # prefer exact roll match in DB results
    for f in found:
        rn = (f.get("roll_number") or "").lower()
        if rn == q_low or rn.endswith(q_low) or q_low in rn:
            # verify mentee scope
            if is_student_in_mentor_scope(f):
                return f, None
            else:
                return None, "Access denied - not your mentee."

    # try fuzzy among found limited to mentees
    if found:
        mentee_ids = {m["id"] for m in mentees if m.get("id")}
        mentee_candidates = [f for f in found if f.get("id") in mentee_ids]
        if mentee_candidates:
            cand, score = fuzzy_best_candidate(q, mentee_candidates, key=lambda x: f"{x.get('first_name','')} {x.get('last_name','')} {x.get('roll_number','')}", score_cutoff=50)
            if cand:
                return cand, None
            # else return first mentee candidate
            return mentee_candidates[0], None

    # 2) DB found something but not mentee -> check if direct found entry is not mentee
    if found:
        # try to pick best fuzzy among found and ensure it's a mentee
        cand, score = fuzzy_best_candidate(q, found, key=lambda x: f"{x.get('first_name','')} {x.get('last_name','')} {x.get('roll_number','')}", score_cutoff=60)
        if cand:
            if is_student_in_mentor_scope(cand):
                return cand, None
            else:
                return None, "Access denied - not your mentee."

    # 3) If DB returned nothing or mentor wants to search within own mentees, fuzzy-match against mentees in session
    if mentees:
        cand, score = fuzzy_best_candidate(q, mentees, key=lambda x: f"{x.get('first_name','')} {x.get('last_name','')} {x.get('roll_number','')}", score_cutoff=50)
        if cand:
            return cand, None

    return None, None

def is_student_in_mentor_scope(student_rec: Dict[str, Any]) -> bool:
    """Return True if student_rec belongs to current mentor."""
    if not student_rec:
        return False
    sid = student_rec.get("mentor_id")
    # some student records have mentor_id; compare with session mentor_id
    return sid == mentor_id

# ---------------------------------------------------------------------
# Main processing: handle query
# ---------------------------------------------------------------------
if query:
    # Save user message (persist per-mentor)
    st.session_state.messages.append({"role": "user", "content": query})
    save_chat_history_for(st.session_state.user, st.session_state.messages)

    intent, meta = parse_intent(query)
    reply = ""
    audit_details = {"query": query, "intent": intent}

    try:
        # Greeting
        if intent == "greeting":
            reply = "Hello! 👋 How can I help you with your mentees today?"
            audit("greeting", st.session_state.user, audit_details)

        # Mentees list
        elif intent == "mentees":
            if not mentees:
                reply = "You have no mentees (DB unavailable or none assigned)."
            else:
                lines = [f"{m.get('first_name','')} {m.get('last_name','')} — Roll: {m.get('roll_number','')}" for m in mentees]
                reply = "\n\n".join(lines)
            audit("mentees_list", st.session_state.user, {"count": len(mentees)})

        # Count mentees
        elif intent == "count_mentees":
            reply = f"You have {len(mentees)} mentees."
            audit("count_mentees", st.session_state.user, {"count": len(mentees)})

        # Name lookup
        elif intent == "name_lookup":
            student, err = find_student_within_scope(meta)
            if err:
                reply = err
                audit("name_lookup_error", st.session_state.user, {"error": err})
            elif not student:
                reply = "No student found."
                audit("name_lookup_not_found", st.session_state.user, {"meta": meta})
            else:
                reply = f"Name: {student.get('first_name','')} {student.get('last_name','')} — Roll: {student.get('roll_number','')}"
                audit("name_lookup", st.session_state.user, {"student_id": student.get("id")})

        # Activity score
        elif intent == "activity_score":
            student, err = find_student_within_scope(meta)
            if err:
                reply = err
                audit("activity_error", st.session_state.user, {"error": err})
            elif not student:
                reply = "No student found."
            else:
                # Activity score might be in student record or computed; try DB field first
                act = student.get("activity_score")
                if act is None:
                    # maybe compute from certificates (example fallback) or mark as Not available
                    # Here, we will attempt to compute a simple activity heuristic: number of certificates
                    try:
                        certs, c_err = safe_db_call(get_certificates_for_student, student.get("id"))
                        if c_err:
                            reply = f"Activity score of {student.get('roll_number','')} is Not available"
                        else:
                            cnt = len(certs or [])
                            # heuristic: activity_score = min(100, cnt * 5)
                            activity_score_val = min(100, cnt * 5)
                            reply = f"Activity score of {student.get('roll_number','')} is {activity_score_val} (computed from {cnt} certificates)"
                    except Exception:
                        reply = f"Activity score of {student.get('roll_number','')} is Not available"
                else:
                    reply = f"Activity score of {student.get('roll_number','')} is {act}"
                audit("activity_lookup", st.session_state.user, {"student_id": student.get("id")})

        # Certificates or count
        elif intent in ("certificates", "count_certificates"):
            student, err = find_student_within_scope(meta)
            if err:
                reply = err
            elif not student:
                reply = "No student found."
            else:
                sid = student.get("id")
                if intent == "count_certificates":
                    cnt, cnt_err = safe_db_call(count_certificates, sid)
                    if cnt_err:
                        reply = f"Error counting certificates: {cnt_err}"
                    else:
                        reply = f"{student.get('first_name','Student')} has {cnt} certificates."
                    audit("count_certificates", st.session_state.user, {"student_id": sid, "count": cnt})
                else:
                    certs, c_err = safe_db_call(get_certificates_for_student, sid)
                    if c_err:
                        reply = f"Error fetching certificates: {c_err}"
                    else:
                        certs = certs or []
                        if not certs:
                            reply = f"No certificates found for {student.get('first_name','Student')}."
                            # optional: LLM guidance
                            if AI_AVAILABLE:
                                guidance_prompt = (
                                    f"Student {student.get('first_name','Student')} (roll {student.get('roll_number')}) has 0 certificates. "
                                    "Provide 2 concise, actionable recommendations the mentor can give the student to start building credentials."
                                )
                                guidance = call_gemini_short(guidance_prompt)
                                if guidance and not guidance.lower().startswith("ai error"):
                                    reply += f"\n\nGuidance:\n{guidance}"
                        else:
                            # If AI enabled, ask for short summary + guidance
                            if AI_AVAILABLE:
                                payload = {"student": {"id": student.get("id"), "name": f"{student.get('first_name','')} {student.get('last_name','')}", "roll": student.get("roll_number")}, "certificates": certs[:50]}
                                summary_prompt = (
                                    "You are MentorAssist. Using ONLY the JSON below, produce:\n"
                                    "1) a one-line summary of the student's certificates,\n"
                                    "2) two concise mentor action items (each on its own line).\n\n"
                                    + json.dumps(payload, indent=2)
                                )
                                llm_resp = call_gemini_short(summary_prompt)
                                if llm_resp and not llm_resp.lower().startswith("ai error"):
                                    reply = llm_resp
                                else:
                                    titles = [c.get("title") or "Untitled" for c in certs]
                                    reply = "Certificates:\n- " + "\n- ".join(titles[:50])
                            else:
                                titles = [c.get("title") or "Untitled" for c in certs]
                                reply = "Certificates:\n- " + "\n- ".join(titles[:50])
                    audit("list_certificates", st.session_state.user, {"student_id": sid, "count": len(certs) if certs else 0})

        # Profile lookup (admin-only originally; here mentors can get profile of their mentees)
        elif intent == "profile":
            student, err = find_student_within_scope(meta)
            if err:
                reply = err
            elif not student:
                reply = "No student found."
            else:
                # fetch department and mentor name
                try:
                    dept = get_department_by_id(student.get("department_id"))
                except Exception:
                    dept = None
                dept_name = dept.get("name") if dept else None

                # mentor name: use DB (get_conn)
                mentor_name = None
                try:
                    mid = student.get("mentor_id")
                    if mid:
                        with get_conn() as conn:
                            with conn.cursor() as cur:
                                cur.execute("SELECT u.first_name, u.last_name, u.email FROM vmeg.profiles_facultyprofile f LEFT JOIN vmeg.authentication_user u ON f.user_id = u.id WHERE f.id = %s", (mid,))
                                row = cur.fetchone()
                                if row:
                                    mentor_name = f"{row[0]} {row[1]} — {row[2]}"
                                else:
                                    mentor_name = f"Mentor ID {mid}"
                except Exception:
                    mentor_name = f"Mentor ID {student.get('mentor_id')}"

                certs, c_err = safe_db_call(get_certificates_for_student, student.get("id"))
                certs = certs or []
                profile_text = pretty_student_profile(student, certs, dept_name, mentor_name)

                # LLM summary & guidance if available
                if AI_AVAILABLE:
                    payload = {"student": {"id": student.get("id"), "name": f"{student.get('first_name','')} {student.get('last_name','')}", "roll": student.get("roll_number")}, "certificates": certs[:50]}
                    llm_prompt = (
                        "You are MentorAssist. Using ONLY the JSON below, produce:\n"
                        "1) a one-line summary of the student's certificate profile,\n"
                        "2) two concise mentor action items (each on its own line).\n\n"
                        + json.dumps(payload, indent=2)
                    )
                    try:
                        llm_resp = call_gemini_short(llm_prompt)
                        if llm_resp and not llm_resp.lower().startswith("ai error"):
                            profile_text += "\n\nLLM SUMMARY & GUIDANCE:\n" + llm_resp
                    except Exception:
                        pass

                reply = profile_text
                audit("profile", st.session_state.user, {"student_id": student.get("id")})

        # Memory lookup (who is X)
        elif intent == "memory_lookup":
            phrase = (meta.get("memory_phrase") or "").strip()
            if not phrase:
                reply = "No phrase provided."
            else:
                mem = memory_lookup(phrase)
                if mem:
                    # If memory_lookup returned a key (subject) or a message, echo it.
                    # We return it directly; earlier you asked that retrieval should occur when asked again.
                    # Example: "who is topper" -> returns stored fact string.
                    reply = f"I found this earlier in our chat: \"{mem}\""
                    audit("memory_hit", st.session_state.user, {"phrase": phrase})
                else:
                    # as fallback, try to resolve as student
                    student, err = find_student_within_scope({"roll_query": phrase, "name_query": phrase})
                    if student:
                        reply = f"{student.get('first_name','')} {student.get('last_name','')} — Roll: {student.get('roll_number','')}"
                        audit("memory_student", st.session_state.user, {"phrase": phrase, "student_id": student.get("id")})
                    else:
                        reply = "I couldn't find that phrase in our conversation or mentee list."
                        audit("memory_miss", st.session_state.user, {"phrase": phrase})

        # Topper / top performer query (custom intent added in shared_utils)
        elif intent == "topper_query":
            # We'll interpret "topper" as highest activity score among mentees (if available)
            try:
                # gather mentees and their activity
                if not mentees:
                    reply = "No mentees available to evaluate."
                else:
                    best = None
                    best_score = -1
                    for m in mentees:
                        # attempt to use activity_score field, else compute from certs
                        sc = m.get("activity_score")
                        if sc is None:
                            # try compute from certs
                            try:
                                certs, c_err = safe_db_call(get_certificates_for_student, m.get("id"))
                                if not c_err:
                                    cnt = len(certs or [])
                                    sc = min(100, cnt * 5)
                                else:
                                    sc = 0
                            except Exception:
                                sc = 0
                        try:
                            sc_num = int(sc) if sc is not None else 0
                        except Exception:
                            sc_num = 0
                        if sc_num > best_score:
                            best_score = sc_num
                            best = m
                    if best:
                        reply = f"Top performer: {best.get('first_name','')} {best.get('last_name','')} — Roll: {best.get('roll_number','')} (score: {best_score})"
                    else:
                        reply = "Couldn't determine topper."
            except Exception as e:
                reply = f"Error determining topper: {e}"
            audit("topper_query", st.session_state.user, {"result": reply})

        # Simple fact storage: detect "<subject> is <description>" pattern and store
        else:
            lower_q = query.strip()
            stored_any = False
            try:
                m = re.match(r"^\s*([A-Za-z0-9\-\_\s\.]+?)\s+is\s+(.+)$", lower_q, re.IGNORECASE)
                if m:
                    subj = m.group(1).strip()
                    desc = m.group(2).strip()
                    # store subject -> desc in memory
                    memory_store(subj, desc)
                    # Per your instruction, when storing memory the bot should not say "I will remember" but reply succinctly.
                    reply = "k."
                    stored_any = True
                    audit("memory_store", st.session_state.user, {"subject": subj, "desc": desc})
            except Exception:
                stored_any = False

            if not stored_any:
                # Unknown intent -> restricted LLM fallback or friendly guidance
                if AI_AVAILABLE:
                    # Provide a safe context: mentee list and recent chat
                    small_students = [{"id": m.get("id"), "name": f"{m.get('first_name','')} {m.get('last_name','')}", "roll": m.get("roll_number","")} for m in mentees]
                    recent_chat = st.session_state.messages[-12:]
                    prompt = (
                        "You are MentorAssist AI. Use ONLY the facts provided below about students and recent chat to answer the user's question. "
                        "If the user asks about a student not in the provided student list, reply 'Access Denied'. "
                        "Answer concisely and do NOT hallucinate.\n\n"
                        f"STUDENTS:\n{json.dumps(small_students, indent=2)}\n\n"
                        f"RECENT_CHAT:\n{json.dumps(recent_chat, indent=2)}\n\n"
                        f"USER QUESTION:\n{query}\n\nAnswer:"
                    )
                    try:
                        llm_resp = call_gemini_short(prompt)
                        if llm_resp and not llm_resp.lower().startswith("ai error"):
                            reply = llm_resp
                        else:
                            reply = "I can answer: name, activity score, certificates, certificate count, mentees, mentee count, profile, topper. (LLM fallback failed.)"
                    except Exception as e:
                        reply = f"LLM error: {e}"
                else:
                    reply = "I can answer: name, activity score, certificates, certificate count, mentees, mentee count, profile, topper. (LLM not configured.)"
                audit("fallback", st.session_state.user, {"query": query})

    except Exception as outer_e:
        reply = f"Internal error processing query: {outer_e}"
        audit("error_processing", st.session_state.user, {"error": str(outer_e), "trace": traceback.format_exc()})

    # Persist assistant reply (both in-memory and on-disk)
    st.session_state.messages.append({"role": "assistant", "content": reply})
    save_chat_history_for(st.session_state.user, st.session_state.messages)

    # Display assistant reply
    with st.chat_message("assistant"):
        st.markdown(reply)

# ---------------------------------------------------------------------
# Footer utilities: export / quick tests / help panel
# ---------------------------------------------------------------------
st.markdown("---")
st.subheader("Mentor Utilities & Quick Tests")

c1, c2, c3 = st.columns(3)

with c1:
    if st.button("Show recent chat (this session)"):
        if st.session_state.messages:
            st.write(st.session_state.messages[-30:])
        else:
            st.info("No chat yet.")

with c2:
    if st.button("Download chat JSON"):
        try:
            fpath = chat_file_for_user(st.session_state.user)
            if os.path.exists(fpath):
                with open(fpath, "r", encoding="utf-8") as fh:
                    data = fh.read()
                st.download_button("Download chat JSON", data=data, file_name=os.path.basename(fpath))
            else:
                # Save current messages then download
                save_chat_history_for(st.session_state.user, st.session_state.messages)
                with open(chat_file_for_user(st.session_state.user), "r", encoding="utf-8") as fh:
                    data = fh.read()
                st.download_button("Download chat JSON", data=data, file_name=os.path.basename(chat_file_for_user(st.session_state.user)))
        except Exception as e:
            st.error(f"Failed to download chat JSON: {e}")

with c3:
    if st.button("Clear session chat (delete file)"):
        try:
            fp = chat_file_for_user(st.session_state.user)
            if os.path.exists(fp):
                os.remove(fp)
            st.session_state.messages = []
            save_chat_history_for(st.session_state.user, st.session_state.messages)
            st.success("Session chat cleared.")
            audit("clear_session_chat", st.session_state.user)
        except Exception as e:
            st.error(f"Failed to clear chat: {e}")

st.markdown("### Quick test commands (copy-paste into the chat input)")
st.code(
    "\n".join([
        "profile of 23881A66F5",
        "certificates of 23881A66F5",
        "how many certificates does 23881A66F5 have",
        "activity score of 23881A66F5",
        "mentees",
        "who is topper",
        "k1 is topper",
        "who is topper"
    ])
)

st.caption("End of MentorAssist. If you want admin features or a version that uses simulated login only, ask and I will provide that file as well.")
