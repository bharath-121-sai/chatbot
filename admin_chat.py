# admin_chat.py
# Admin Chatbot — MentorAssist (Full, LLM-enabled) — Single-file deliverable (memory A1 enabled)
# Requirements:
#  - shared_utils.py (parse_intent, fuzzy_best_candidate, load_chat_history_for, save_chat_history_for, chat_file_for_user)
#  - db_utils.py (find_students_by_query, get_student_by_id, get_mentees, get_certificates_for_student, count_certificates, get_department_by_id, get_conn)
#  - ai_core.py (call_gemini_short, AI_AVAILABLE)
#  - rapidfuzz installed (used in shared_utils)
#
# Notes:
#  - This is a simulated admin login for demo. Replace with real auth for production.
#  - Memory is stored per-admin in chats/memory_<username>.json and loaded on login.
#  - Chat history is stored per-admin in chats/chat_<username>.json (via shared_utils).
#  - If your DB is unreachable, most features degrade gracefully; admin memory & chat still work.

import streamlit as st
import os
import re
import json
import csv
import io
import traceback
from typing import List, Dict, Optional, Tuple
from datetime import datetime

# project-specific imports (must exist)
from shared_utils import (
    parse_intent,
    fuzzy_best_candidate,
    load_chat_history_for,
    save_chat_history_for,
    chat_file_for_user,
)
from db_utils import (
    find_students_by_query,
    get_student_by_id,
    get_mentees,
    get_certificates_for_student,
    count_certificates,
    get_department_by_id,
    get_conn,
)
from ai_core import call_gemini_short, AI_AVAILABLE

# ----------------------------
# Config / constants
# ----------------------------
APP_TITLE = "Admin Chatbot — MentorAssist (Full)"
PAGE_SIZE = 40
AUDIT_LOG = "admin_audit.log"
CHAT_DIR = "chats"
MEMORY_DIR = CHAT_DIR  # store memory files alongside chat files
MAX_EXPORT_ROWS = 3000

# Simulated admin credentials (demo)
ADMIN_CREDENTIALS = {"username": "kondenagaruthvik@gmail.com", "password": "Ruthvik3234L"}

# Ensure storage dirs exist
os.makedirs(CHAT_DIR, exist_ok=True)
os.makedirs(MEMORY_DIR, exist_ok=True)

# Streamlit page config
st.set_page_config(page_title=APP_TITLE, layout="wide")
st.title(APP_TITLE)
st.caption("Admin console — DB queries, LLM summaries & guidance, session memory and audit logging.")

# ----------------------------
# Utility: audit log
# ----------------------------
def audit(action: str, user: Dict, details: Optional[Dict] = None):
    try:
        entry = {
            "ts": datetime.utcnow().isoformat(),
            "user": user.get("username") if user else None,
            "action": action,
            "details": details or {}
        }
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        # do not crash the app when auditing fails
        pass

# ----------------------------
# Session init
# ----------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user = None
    st.session_state.messages = []          # chat messages in-memory for session
    st.session_state.query_history = []     # admin queries in this session
    st.session_state.memory = {}            # in-memory memory store for admin (key -> list of values)
    st.session_state.memory_loaded = False

# ----------------------------
# Memory persistence helpers
# ----------------------------
def memory_file_for_user(user: Dict) -> str:
    uname = user.get("username", "unknown")
    return os.path.join(MEMORY_DIR, f"memory_{uname}.json")

def load_memory_for_user(user: Dict):
    path = memory_file_for_user(user)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                # ensure values are lists
                for k, v in list(data.items()):
                    if isinstance(v, list):
                        continue
                    data[k] = [v]
                return data
        except Exception:
            return {}
    return {}

def save_memory_for_user(user: Dict, memory: Dict):
    path = memory_file_for_user(user)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(memory, fh, indent=2, ensure_ascii=False)
    except Exception:
        pass

# ----------------------------
# Small DB-safe wrappers
# ----------------------------
def safe_db_call(fn, *args, **kwargs):
    try:
        res = fn(*args, **kwargs)
        return res, None
    except Exception as e:
        return None, str(e)

def safe_find_students(q: str, limit: int = 200):
    return safe_db_call(find_students_by_query, q, limit)

def safe_get_mentees(mid: int):
    return safe_db_call(get_mentees, mid)

def safe_get_student_by_id(sid: int):
    return safe_db_call(get_student_by_id, sid)

def safe_get_certs(sid: int):
    return safe_db_call(get_certificates_for_student, sid)

def safe_count_certs(sid: int):
    return safe_db_call(count_certificates, sid)

# ----------------------------
# Presentation helpers
# ----------------------------
def dicts_to_csv_bytes(dicts: List[Dict]) -> bytes:
    if not dicts:
        return b""
    output = io.StringIO()
    keys = sorted({k for d in dicts for k in d.keys()})
    writer = csv.DictWriter(output, fieldnames=keys)
    writer.writeheader()
    for d in dicts:
        safe_row = {}
        for k in keys:
            v = d.get(k, "")
            if isinstance(v, datetime):
                safe_row[k] = v.isoformat()
            else:
                safe_row[k] = v
        writer.writerow(safe_row)
    return output.getvalue().encode("utf-8")

def pretty_student_profile(student: Dict, certs: List[Dict], dept_name: Optional[str], mentor_name: Optional[str], cert_count: Optional[int], activity_score: Optional[str]) -> str:
    lines = []
    lines.append("📌 STUDENT PROFILE")
    lines.append("-" * 48)
    lines.append(f"Name         : {student.get('first_name','')} {student.get('last_name','')}")
    lines.append(f"Roll Number  : {student.get('roll_number','')}")
    lines.append(f"Batch        : {student.get('batch_year','')}")
    lines.append(f"Semester     : {student.get('current_semester','')}")
    lines.append(f"Department   : {dept_name or 'N/A'}")
    lines.append(f"Mentor       : {mentor_name or 'N/A'}")
    lines.append(f"Activity     : {activity_score or 'N/A'}")
    lines.append(f"Certificates : {cert_count if cert_count is not None else 'N/A'}")
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

# ----------------------------
# Memory utilities (admin)
# ----------------------------
def memory_store(key: str, value: str):
    """
    Store memory under a normalized key (lowercase).
    Values are lists (history). Persist to disk per admin user.
    """
    k = key.strip().lower()
    v = value.strip()
    if not k or not v or not st.session_state.user:
        return
    mem = st.session_state.memory
    if k in mem:
        if isinstance(mem[k], list):
            mem[k].append(v)
        else:
            mem[k] = [mem[k], v]
    else:
        mem[k] = [v]
    # persist immediately
    save_memory_for_user(st.session_state.user, mem)

def memory_lookup(phrase: str) -> Optional[str]:
    """
    Lookup memory by:
     - exact key match
     - fuzzy key match (partial)
     - search values substring
     - finally fallback to chat history fuzzy search
    Returns a string (latest value) or None.
    """
    if not phrase:
        return None
    p = phrase.strip().lower()
    mem = st.session_state.memory or {}
    # exact
    if p in mem:
        vals = mem[p]
        if isinstance(vals, list):
            return vals[-1]
        return vals
    # fuzzy-like scan keys
    best_key = None
    best_score = 0
    try:
        # use simple substring matching + token ratio heuristics (no extra libs required here)
        from rapidfuzz import fuzz
        for k, v in mem.items():
            score = fuzz.partial_ratio(p, k)
            if score > best_score:
                best_score = score
                best_key = k
        if best_key and best_score >= 70:
            vals = mem[best_key]
            return vals[-1] if isinstance(vals, list) else vals
        # search values
        for k, vlist in mem.items():
            for v in (vlist if isinstance(vlist, list) else [vlist]):
                if p in str(v).lower():
                    return v
    except Exception:
        # fallback to simple substring search
        for k, vlist in mem.items():
            if p in k:
                v = vlist[-1] if isinstance(vlist, list) else vlist
                return v
            for v in (vlist if isinstance(vlist, list) else [vlist]):
                if p in str(v).lower():
                    return v
    # fallback: search chat history messages
    for msg in reversed(st.session_state.messages or []):
        txt = msg.get("content", "").lower()
        if p in txt:
            return msg.get("content")
    return None

def memory_export_bytes():
    """Return memory JSON bytes for download."""
    mem = st.session_state.memory or {}
    return json.dumps(mem, indent=2, ensure_ascii=False).encode("utf-8")

# ----------------------------
# Helpers: student & mentor resolution
# ----------------------------
def find_student_admin(meta: Dict, prefer_list: Optional[List[Dict]] = None) -> Tuple[Optional[Dict], Optional[str]]:
    q = meta.get("roll_query") or meta.get("name_query")
    if not q:
        return None, "No search term given."
    found, err = safe_find_students(q, limit=200)
    if err:
        return None, f"DB error: {err}"
    if found:
        q_low = q.lower()
        for f in found:
            rn = (f.get("roll_number") or "").lower()
            if rn == q_low or rn.endswith(q_low) or q_low in rn:
                return f, None
        if prefer_list:
            mentee_ids = {m["id"] for m in prefer_list}
            mentee_candidates = [f for f in found if f.get("id") in mentee_ids]
            if mentee_candidates:
                cand, score = fuzzy_best_candidate(q, mentee_candidates, key=lambda x: f"{x.get('first_name','')} {x.get('last_name','')} {x.get('roll_number','')}", score_cutoff=55)
                if cand:
                    return cand, None
                return mentee_candidates[0], None
        cand, score = fuzzy_best_candidate(q, found, key=lambda x: f"{x.get('first_name','')} {x.get('last_name','')} {x.get('roll_number','')}", score_cutoff=50)
        if cand:
            return cand, None
        return found[0], None
    if prefer_list:
        cand, score = fuzzy_best_candidate(q, prefer_list, key=lambda x: f"{x.get('first_name','')} {x.get('last_name','')} {x.get('roll_number','')}", score_cutoff=50)
        if cand:
            return cand, None
    return None, None

def find_mentor_by_text(q: str) -> Tuple[Optional[Dict], Optional[str]]:
    q_clean = q.strip()
    if not q_clean:
        return None, "no query"
    if q_clean.isdigit():
        try:
            mid = int(q_clean)
            sql = "SELECT f.id AS mentor_id, u.first_name, u.last_name, u.email FROM vmeg.profiles_facultyprofile f LEFT JOIN vmeg.authentication_user u ON f.user_id = u.id WHERE f.id = %s;"
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, (mid,))
                    r = cur.fetchone()
                    if r:
                        cols = [c[0] for c in cur.description]
                        return dict(zip(cols, r)), None
            return None, None
        except Exception as e:
            return None, f"DB error: {e}"
    sql = "SELECT f.id AS mentor_id, u.first_name, u.last_name, u.email FROM vmeg.profiles_facultyprofile f LEFT JOIN vmeg.authentication_user u ON f.user_id = u.id WHERE u.first_name ILIKE %s OR u.last_name ILIKE %s LIMIT 50;"
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                like = f"%{q}%"
                cur.execute(sql, (like, like))
                rows = cur.fetchall()
                if not rows:
                    return None, None
                cols = [c[0] for c in cur.description]
                candidates = [dict(zip(cols, r)) for r in rows]
                if len(candidates) == 1:
                    return candidates[0], None
                cand, score = fuzzy_best_candidate(q, candidates, key=lambda x: f"{x.get('first_name','')} {x.get('last_name','')}", score_cutoff=55)
                if cand:
                    return cand, None
                return candidates[0], None
    except Exception as e:
        return None, f"DB error: {e}"

# ----------------------------
# UI: Sidebar login & quick tools
# ----------------------------
with st.sidebar:
    st.header("Admin Login (simulate)")
    if not st.session_state.logged_in:
        username = st.text_input("Username", key="admin_username")
        password = st.text_input("Password", type="password", key="admin_password")
        if st.button("Login"):
            if username == ADMIN_CREDENTIALS["username"] and password == ADMIN_CREDENTIALS["password"]:
                # clear prior chat file so every login starts fresh (as requested)
                try:
                    f = chat_file_for_user({"username": username})
                    if os.path.exists(f):
                        os.remove(f)
                except Exception:
                    pass
                st.session_state.logged_in = True
                st.session_state.user = {"username": username, "role": "admin"}
                # load chat history if present (but spec said fresh on login; we still load empty)
                st.session_state.messages = []
                st.session_state.query_history = []
                # load memory for admin
                st.session_state.memory = load_memory_for_user(st.session_state.user)
                st.session_state.memory_loaded = True
                st.success(f"Logged in as {username}")
                audit("login", st.session_state.user)
                st.rerun()
            else:
                st.error("Invalid credentials")
    else:
        st.markdown(f"**User:** {st.session_state.user['username']}")
        st.markdown("**Role:** Admin (Full Access)")
        if st.button("Logout"):
            # delete chat file and persist memory (memory already persisted on writes)
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
            st.session_state.query_history = []
            st.session_state.memory = {}
            st.session_state.memory_loaded = False
            st.rerun()

    st.markdown("---")
    st.subheader("Admin Quick Tools")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Show recent audit"):
            out = []
            try:
                with open(AUDIT_LOG, "r", encoding="utf-8") as f:
                    lines = f.readlines()[-50:]
                    out = [json.loads(l) for l in lines if l.strip()]
            except Exception as e:
                st.error(f"Failed to read audit log: {e}")
                out = []
            if out:
                st.write(out)
            else:
                st.write("No audit lines available.")
    with col2:
        if st.button("Export chat JSON"):
            try:
                fpath = chat_file_for_user(st.session_state.user)
                if os.path.exists(fpath):
                    with open(fpath, "r", encoding="utf-8") as fh:
                        data = fh.read()
                    st.download_button("Download chat JSON", data=data, file_name=os.path.basename(fpath))
                else:
                    st.info("No chat history file found.")
            except Exception as e:
                st.error(f"Export failed: {e}")

    st.markdown("---")
    st.write(f"AI available: {'Yes' if AI_AVAILABLE else 'No'}")
    if AI_AVAILABLE:
        st.info("LLM enabled: used for summaries & guidance")

    st.markdown("---")
    st.subheader("Memory Controls")
    c1, c2, c3 = st.columns([1,1,1])
    with c1:
        if st.button("Export memory"):
            b = memory_export_bytes()
            if b:
                st.download_button("Download memory JSON", data=b, file_name=f"memory_{st.session_state.user['username']}.json")
            else:
                st.info("No memory to export.")
    with c2:
        if st.button("Clear memory (session + file)"):
            try:
                st.session_state.memory = {}
                save_memory_for_user(st.session_state.user, st.session_state.memory)
                st.success("Memory cleared.")
                audit("clear_memory", st.session_state.user)
            except Exception as e:
                st.error(f"Failed to clear memory: {e}")
    with c3:
        if st.button("Show memory (current)"):
            mem = st.session_state.memory or {}
            if mem:
                st.json(mem)
            else:
                st.info("No memory stored.")

# ----------------------------
# Stop if not logged in
# ----------------------------
if not st.session_state.logged_in:
    st.info("Please login as admin from the sidebar to continue.")
    st.stop()

# ----------------------------
# Main chat area
# ----------------------------
st.subheader("Admin Chat")
for m in st.session_state.messages:
    with st.chat_message(m.get("role", "user")):
        st.markdown(m.get("content", ""))

query = st.chat_input("Ask admin (examples: 'profile of 23881A66F5', 'certificates of 21BD1A05A1', 'mentees of mentor 5', 'list mentors', 'who is topper', 'show all students')")

# ----------------------------
# LLM helper (safe small payload)
# ----------------------------
def build_safe_payload_for_llm(student: Dict, certs: List[Dict]):
    s_small = {
        "id": student.get("id"),
        "name": f"{student.get('first_name','')} {student.get('last_name','')}",
        "roll": student.get('roll_number'),
        "batch": student.get('batch_year'),
        "semester": student.get('current_semester'),
    }
    cert_small = []
    for c in certs[:50]:
        cert_small.append({
            "title": c.get("title"),
            "issuing_organization": c.get("issuing_organization"),
            "status": c.get("status"),
            "academic_year": c.get("academic_year"),
            "created_at": c.get("created_at").isoformat() if isinstance(c.get("created_at"), datetime) else c.get("created_at")
        })
    return {"student": s_small, "certificates": cert_small}

# ----------------------------
# Main processing
# ----------------------------
if query:
    # persist user message and session history
    st.session_state.messages.append({"role": "user", "content": query})
    save_chat_history_for(st.session_state.user, st.session_state.messages)
    st.session_state.query_history.append({"ts": datetime.utcnow().isoformat(), "q": query})

    intent, meta = parse_intent(query)
    reply = ""
    audit_details = {"query": query, "intent": intent}

    try:
        # 1) greeting
        if intent == "greeting":
            reply = "Hello Admin! How can I assist you today?"
            audit("greeting", st.session_state.user, audit_details)

        # 2) list mentors
        elif "list mentors" in query.lower() or "show mentors" in query.lower():
            try:
                sql = "SELECT f.id AS mentor_id, u.first_name, u.last_name, u.email FROM vmeg.profiles_facultyprofile f LEFT JOIN vmeg.authentication_user u ON f.user_id = u.id ORDER BY f.id;"
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(sql)
                        rows = cur.fetchall()
                        cols = [c[0] for c in cur.description]
                        mentors = [dict(zip(cols, r)) for r in rows]
                if not mentors:
                    reply = "No mentors found."
                else:
                    lines = [f"Mentor ID: {m['mentor_id']} — {m.get('first_name','')} {m.get('last_name','')} — {m.get('email','')}" for m in mentors]
                    reply = "\n\n".join(lines)
                audit("list_mentors", st.session_state.user, {"count": len(mentors)})
            except Exception as e:
                reply = f"Error listing mentors: {e}"
                audit("list_mentors_error", st.session_state.user, {"error": str(e)})

        # 3) mentees of X
        elif "mentees of" in query.lower():
            mm = re.search(r"mentees of(?: mentor)?\s*([0-9]+)", query.lower())
            if not mm:
                reply = "Please specify mentor id. Example: 'mentees of mentor 5'."
            else:
                mid = int(mm.group(1))
                mentees, err = safe_get_mentees(mid)
                if err:
                    reply = f"DB error fetching mentees: {err}"
                else:
                    if not mentees:
                        reply = f"No mentees found for mentor {mid}."
                    else:
                        lines = [f"{m.get('first_name','')} {m.get('last_name','')} — Roll: {m.get('roll_number','')} — Batch: {m.get('batch_year','')}" for m in mentees]
                        reply = "\n\n".join(lines)
                audit("mentees_of", st.session_state.user, {"mentor_id": mid, "count": len(mentees) if mentees else 0})

        # 4) show all students (paged)
        elif query.lower().startswith("show all students") or query.lower().startswith("list students") or query.lower().startswith("show students"):
            page_key = "all_students_page"
            if page_key not in st.session_state:
                st.session_state[page_key] = 0
            try:
                students = []
                sql = "SELECT s.id, s.roll_number, s.batch_year, s.current_semester, s.department_id, s.mentor_id, u.first_name, u.last_name FROM vmeg.profiles_studentprofile s LEFT JOIN vmeg.authentication_user u ON s.user_id = u.id ORDER BY s.id;"
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(sql)
                        rows = cur.fetchall()
                        cols = [c[0] for c in cur.description]
                        students = [dict(zip(cols, r)) for r in rows]
                if not students:
                    reply = "No students found."
                else:
                    total = len(students)
                    pages = (total + PAGE_SIZE - 1) // PAGE_SIZE
                    page = st.session_state[page_key]
                    start = page * PAGE_SIZE
                    end = start + PAGE_SIZE
                    subset = students[start:end]
                    lines = [f"{s.get('first_name','')} {s.get('last_name','')} — Roll: {s.get('roll_number','')} — Batch: {s.get('batch_year','')}" for s in subset]
                    reply = f"Showing students {start + 1} to {min(end, total)} of {total}:\n\n" + "\n\n".join(lines)
                    # pagination buttons (these rerun the app)
                    c1, c2, c3 = st.columns([1,1,2])
                    with c1:
                        if st.button("Prev page"):
                            if st.session_state[page_key] > 0:
                                st.session_state[page_key] -= 1
                                st.rerun()
                    with c2:
                        if st.button("Next page"):
                            if st.session_state[page_key] < pages - 1:
                                st.session_state[page_key] += 1
                                st.rerun()
                    with c3:
                        if st.button("Export shown students as CSV"):
                            csv_bytes = dicts_to_csv_bytes(subset)
                            st.download_button("Download CSV", data=csv_bytes, file_name="students_page.csv")
                audit("show_all_students", st.session_state.user, {"total": len(students) if students else 0})
            except Exception as e:
                reply = f"DB error fetching students: {e}"
                audit("show_all_students_error", st.session_state.user, {"error": str(e)})

        # 5) departments & batches
        elif query.lower().startswith("show departments") or query.lower().startswith("list departments"):
            try:
                sql = "SELECT id, name, code FROM vmeg.academics_department ORDER BY id;"
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(sql)
                        rows = cur.fetchall()
                        if not rows:
                            reply = "No departments found."
                        else:
                            cols = [c[0] for c in cur.description]
                            deps = [dict(zip(cols, r)) for r in rows]
                            reply = "\n\n".join([f"{d['id']} — {d.get('name','')} ({d.get('code','')})" for d in deps])
                audit("list_departments", st.session_state.user)
            except Exception as e:
                reply = f"DB error fetching departments: {e}"
                audit("list_departments_error", st.session_state.user, {"error": str(e)})

        elif query.lower().startswith("show batch") or "batch years" in query.lower() or "list batches" in query.lower():
            try:
                sql = "SELECT DISTINCT batch_year FROM vmeg.profiles_studentprofile ORDER BY batch_year DESC;"
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(sql)
                        rows = cur.fetchall()
                        years = [r[0] for r in rows]
                        if not years:
                            reply = "No batch years found."
                        else:
                            reply = "Batch years: " + ", ".join([str(y) for y in years])
                audit("list_batches", st.session_state.user)
            except Exception as e:
                reply = f"DB error fetching batch years: {e}"
                audit("list_batches_error", st.session_state.user, {"error": str(e)})

        # 6) student lookups (profile/name/activity/certs/count)
        elif intent in ("profile", "name_lookup", "activity_score", "certificates", "count_certificates"):
            student, err = find_student_admin(meta)
            if err:
                reply = f"DB error: {err}"
                audit("student_lookup_error", st.session_state.user, {"error": err, "query": query})
            elif not student:
                reply = "No student found."
                audit("student_lookup_notfound", st.session_state.user, {"query": query})
            else:
                sid = student.get("id")
                # PROFILE
                if intent == "profile":
                    try:
                        dept = None
                        try:
                            dept = get_department_by_id(student.get("department_id"))
                        except Exception:
                            dept = None
                        dept_name = dept.get("name") if dept else None
                        mentor_id = student.get("mentor_id")
                        mentor_name = None
                        if mentor_id:
                            try:
                                mrec, m_err = find_mentor_by_text(str(mentor_id))
                                if mrec:
                                    mentor_name = f"{mrec.get('first_name','')} {mrec.get('last_name','')} — {mrec.get('email','')}"
                                else:
                                    mentor_name = f"Mentor ID {mentor_id}"
                            except Exception:
                                mentor_name = f"Mentor ID {mentor_id}"
                        certs, c_err = safe_get_certs(sid)
                        certs = certs or []
                        cert_count, cc_err = safe_count_certs(sid)
                        activity = student.get("activity_score", "Not available")
                        profile_text = pretty_student_profile(student, certs or [], dept_name, mentor_name, cert_count, activity)

                        # LLM summary & guidance (if enabled)
                        if AI_AVAILABLE:
                            payload = {
                                "student": {
                                    "id": student.get("id"),
                                    "name": f"{student.get('first_name','')} {student.get('last_name','')}",
                                    "roll": student.get('roll_number'),
                                    "batch": student.get('batch_year'),
                                    "semester": student.get('current_semester'),
                                    "department": dept_name,
                                    "activity_score": activity,
                                    "certificate_count": cert_count
                                },
                                "certificates": certs[:50] if certs else []
                            }
                            try:
                                llm_prompt = (
                                    "You are AdminAssist. Using ONLY the JSON facts below, produce:\n"
                                    "1) a one-line summary of the student's certificate profile,\n"
                                    "2) two concise mentor action items (each on its own line).\n\n"
                                    + json.dumps(payload, indent=2)
                                )
                                llm_resp = call_gemini_short(llm_prompt)
                                if llm_resp and not llm_resp.lower().startswith("ai error"):
                                    profile_text += "\n\nLLM SUMMARY & GUIDANCE:\n" + llm_resp
                            except Exception as e:
                                profile_text += f"\n\nAI error: {e}"
                        reply = profile_text
                        audit("student_profile", st.session_state.user, {"student_id": sid})
                    except Exception as e:
                        reply = f"Error building profile: {e}"
                        audit("student_profile_error", st.session_state.user, {"error": str(e), "student_id": sid})

                # NAME lookup
                elif intent == "name_lookup":
                    reply = f"Name: {student.get('first_name','')} {student.get('last_name','')} — Roll: {student.get('roll_number','')}"
                    audit("name_lookup", st.session_state.user, {"student_id": sid})

                # ACTIVITY SCORE
                elif intent == "activity_score":
                    score = student.get("activity_score", "Not available")
                    reply = f"Activity score of {student.get('roll_number','')} is {score}"
                    audit("activity_lookup", st.session_state.user, {"student_id": sid, "score": score})

                # COUNT CERTIFICATES
                elif intent == "count_certificates":
                    cnt, cnt_err = safe_count_certs(sid)
                    if cnt_err is not None:
                        reply = f"Error counting certificates: {cnt_err}"
                    else:
                        reply = f"{student.get('first_name','Student')} has {cnt} certificates."
                    audit("count_certificates", st.session_state.user, {"student_id": sid, "count": cnt})

                # LIST CERTIFICATES
                elif intent == "certificates":
                    certs, c_err = safe_get_certs(sid)
                    if c_err:
                        reply = f"Error fetching certificates: {c_err}"
                    else:
                        if not certs:
                            reply = f"No certificates found for {student.get('first_name','Student')}."
                            if AI_AVAILABLE:
                                try:
                                    guidance_prompt = (
                                        f"Student {student.get('first_name','Student')} (roll {student.get('roll_number')}) has 0 certificates. "
                                        "As an expert mentor, provide 3 short actionable steps the student can follow to start building credible certificates or projects."
                                    )
                                    guidance = call_gemini_short(guidance_prompt)
                                    if guidance and not guidance.lower().startswith("ai error"):
                                        reply += "\n\nGuidance:\n" + guidance
                                except Exception as e:
                                    reply += f"\n\nAI error: {e}"
                        else:
                            titles = [c.get("title", "Untitled") for c in certs]
                            reply = "Certificates:\n" + "\n".join([f"- {t}" for t in titles[:200]])
                    audit("list_certificates", st.session_state.user, {"student_id": sid, "count": len(certs) if certs else 0})

        # 7) memory lookup ("who is X")
        elif intent == "memory_lookup":
            phrase = (meta.get("memory_phrase") or "").strip()
            found_val = None
            if phrase:
                found_val = memory_lookup(phrase)
            if found_val:
                reply = f"I found this earlier in the conversation: \"{found_val}\""
                audit("memory_lookup_hit", st.session_state.user, {"phrase": phrase})
            else:
                # as fallback, try student resolution
                s, s_err = find_student_admin({"roll_query": phrase, "name_query": phrase})
                if s:
                    reply = f"{s.get('first_name','')} {s.get('last_name','')} — Roll: {s.get('roll_number','')}"
                    audit("memory_lookup_student", st.session_state.user, {"phrase": phrase, "student_id": s.get("id")})
                else:
                    reply = "No memory found for that phrase."
                    audit("memory_lookup_miss", st.session_state.user, {"phrase": phrase})

        # 8) Detect simple memory statements "X is Y" and store them
        else:
            # try simple pattern: "<subject> is <predicate>" — store as memory
            stored_any = False
            try:
                m = re.match(r"^\s*([A-Za-z0-9\-\._ ]+?)\s+is\s+(.+)$", query.strip(), re.IGNORECASE)
                if m:
                    subj = m.group(1).strip()
                    pred = m.group(2).strip()
                    if subj and pred:
                        memory_store(subj, f"{subj} is {pred}")
                        reply = f"Noted: '{subj}' → '{pred}'. I will remember this."
                        audit("memory_store", st.session_state.user, {"subject": subj, "predicate": pred})
                        stored_any = True
            except Exception:
                stored_any = False

            if not stored_any:
                # Admin open questions allowed: use LLM fallback if enabled
                if AI_AVAILABLE:
                    try:
                        llm_prompt = f"You are AdminAssist. Answer concisely and accurately. Question: {query}"
                        llm_resp = call_gemini_short(llm_prompt)
                        if llm_resp:
                            reply = llm_resp
                            audit("llm_fallback", st.session_state.user, {"query": query})
                        else:
                            reply = "LLM returned no answer."
                            audit("llm_fallback_empty", st.session_state.user, {"query": query})
                    except Exception as e:
                        reply = f"AI error: {e}"
                        audit("llm_fallback_error", st.session_state.user, {"error": str(e), "query": query})
                else:
                    # guide admin about supported quick queries
                    reply = "I can answer: student profile, name lookup, activity score, certificates, certificate count, list mentors, mentees, departments, show all students. You can also tell me short facts like 'bob is topper' and ask 'who is topper'."
                    audit("fallback_no_llm", st.session_state.user, {"query": query})

    except Exception as outer_e:
        reply = f"Internal error: {outer_e}"
        audit("internal_error", st.session_state.user, {"error": str(outer_e), "query": query, "trace": traceback.format_exc()})

    # persist assistant reply & display
    st.session_state.messages.append({"role": "assistant", "content": reply})
    save_chat_history_for(st.session_state.user, st.session_state.messages)
    with st.chat_message("assistant"):
        st.markdown(reply)

# ----------------------------
# Bottom admin utilities
# ----------------------------
st.markdown("---")
st.subheader("Admin Utilities")

c1, c2, c3 = st.columns(3)
with c1:
    if st.button("Show recent queries (this session)"):
        if st.session_state.query_history:
            st.table(st.session_state.query_history[-20:])
        else:
            st.info("No queries this session.")
with c2:
    if st.button("Download audit log"):
        try:
            if os.path.exists(AUDIT_LOG):
                with open(AUDIT_LOG, "r", encoding="utf-8") as f:
                    data = f.read()
                st.download_button("Download audit log", data=data, file_name="admin_audit.log")
            else:
                st.info("No audit log found.")
        except Exception as e:
            st.error(f"Failed to read audit log: {e}")
with c3:
    if st.button("Clear session chat (delete chat file)"):
        try:
            f = chat_file_for_user(st.session_state.user)
            if os.path.exists(f):
                os.remove(f)
            st.session_state.messages = []
            save_chat_history_for(st.session_state.user, st.session_state.messages)
            st.success("Session chat cleared.")
            audit("clear_session_chat", st.session_state.user)
        except Exception as e:
            st.error(f"Failed to clear chat: {e}")

st.caption("End of Admin console. Use exports and audit log for records.")

# EOF
