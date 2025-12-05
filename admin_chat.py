# admin_chat.py (FINAL — FIXED & CLEANED)
import streamlit as st
import os, json, re
from datetime import datetime

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
    get_conn
)
from ai_core import call_gemini_short, AI_AVAILABLE


# --------------------------------------------------------------
# Streamlit setup
# --------------------------------------------------------------
st.set_page_config(page_title="Admin Chat", layout="wide")
st.title("Admin Chatbot — Full Access (FINAL FIXED)")


# --------------------------------------------------------------
# Hardcoded Admin user
# --------------------------------------------------------------
ADMIN = {
    "username": "kondenagaruthvik@gmail.com",
    "password": "Ruthvik3234L",
    "role": "admin"
}


# --------------------------------------------------------------
# Session init
# --------------------------------------------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user = None
    st.session_state.messages = []


# --------------------------------------------------------------
# Sidebar login/logout
# --------------------------------------------------------------
with st.sidebar:
    st.header("Admin Login")

    if not st.session_state.logged_in:
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")

        if st.button("Login"):
            if u == ADMIN["username"] and p == ADMIN["password"]:
                # remove old chat history every login
                chat_file = chat_file_for_user({"username": u})
                if os.path.exists(chat_file):
                    os.remove(chat_file)

                st.session_state.logged_in = True
                st.session_state.user = {"username": u, "role": "admin"}
                st.session_state.messages = []
                st.rerun()
            else:
                st.error("Invalid credentials")

    else:
        st.markdown(f"**User:** {st.session_state.user['username']} (Admin)")

        if st.button("Logout"):
            chat_file = chat_file_for_user(st.session_state.user)
            if os.path.exists(chat_file):
                os.remove(chat_file)

            st.session_state.logged_in = False
            st.session_state.user = None
            st.session_state.messages = []
            st.rerun()


# stop page if not logged in
if not st.session_state.logged_in:
    st.stop()


# --------------------------------------------------------------
# Helpers
# --------------------------------------------------------------
def fix_datetime(row):
    for k, v in list(row.items()):
        if isinstance(v, datetime):
            row[k] = v.strftime("%Y-%m-%d %H:%M:%S")
    return row


def find_student_anywhere(meta):
    """Admin can search any student (DB-wide + fuzzy)."""
    q = meta.get("roll_query") or meta.get("name_query")
    if not q:
        return None

    found = find_students_by_query(q, limit=30)
    if found:
        q_low = q.lower()
        # exact / suffix roll match
        for f in found:
            rn = f.get("roll_number", "").lower()
            if rn == q_low or rn.endswith(q_low) or q_low in rn:
                return f

        # fuzzy best among all found
        cand, score = fuzzy_best_candidate(
            q,
            found,
            key=lambda x: f"{x.get('first_name','')} {x.get('last_name','')} {x.get('roll_number','')}",
            score_cutoff=50
        )
        return cand if cand else found[0]

    return None


def search_memory(phrase):
    phrase = phrase.lower()
    for msg in reversed(st.session_state.messages):
        if phrase in msg["content"].lower():
            return msg["content"]
    return None


def get_all_mentors():
    """Return mentors from DB."""
    sql = """
    SELECT f.id AS mentor_id, u.first_name, u.last_name, u.email
    FROM vmeg.profiles_facultyprofile f
    LEFT JOIN vmeg.authentication_user u ON f.user_id = u.id;
    """
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
                rows = cur.fetchall()
                cols = [x[0] for x in cur.description]
                return [dict(zip(cols, r)) for r in rows]
    except:
        return []


# --------------------------------------------------------------
# Chat UI
# --------------------------------------------------------------
st.subheader("Admin Chat")

for m in st.session_state.messages:
    with st.chat_message(m["role"]):
        st.markdown(m["content"])

query = st.chat_input("Ask something as Admin...")


# --------------------------------------------------------------
# Main Logic
# --------------------------------------------------------------
if query:
    # save user question
    st.session_state.messages.append({"role": "user", "content": query})
    save_chat_history_for(st.session_state.user, st.session_state.messages)

    intent, meta = parse_intent(query)
    reply = ""


    # ----------------------------------------------------------
    # 1️⃣ Greeting
    # ----------------------------------------------------------
    if intent == "greeting":
        reply = "Hello Admin! How can I help you today?"


    # ----------------------------------------------------------
    # 2️⃣ List Mentors
    # ----------------------------------------------------------
    elif "list mentors" in query.lower() or "show mentors" in query.lower():
        mentors = get_all_mentors()
        if not mentors:
            reply = "No mentors found."
        else:
            reply = "\n\n".join([
                f"Mentor ID: {m['mentor_id']} — {m.get('first_name','')} {m.get('last_name','')} — {m.get('email','')}"
                for m in mentors
            ])


    # ----------------------------------------------------------
    # 3️⃣ Mentees of mentor X
    # ----------------------------------------------------------
    elif "mentees of" in query.lower():
        mm = re.search(r"mentor\s*([0-9]+)", query.lower())
        if not mm:
            reply = "Please specify mentor: e.g., 'mentees of mentor 5'."
        else:
            mid = int(mm.group(1))
            mentees = get_mentees(mid)
            if not mentees:
                reply = f"No mentees found for mentor {mid}."
            else:
                reply = "\n\n".join([
                    f"{x['first_name']} {x['last_name']} — Roll: {x['roll_number']}"
                    for x in mentees
                ])


    # ----------------------------------------------------------
    # 4️⃣ Student Lookup (name / profile / certificates / count)
    # ----------------------------------------------------------
    elif intent in ("name_lookup", "activity_score", "certificates", "count_certificates"):
        student = find_student_anywhere(meta)

        if not student:
            reply = "No student found."
        else:
            sid = student["id"]

            if intent == "name_lookup":
                reply = f"Name: {student['first_name']} {student['last_name']} — Roll: {student['roll_number']}"

            elif intent == "activity_score":
                reply = f"Activity score: {student.get('activity_score', 'Not available')}"

            elif intent == "count_certificates":
                cnt = count_certificates(sid)
                reply = f"{student['first_name']} has {cnt} certificates."

            elif intent == "certificates":
                certs = get_certificates_for_student(sid)
                certs = [fix_datetime(c) for c in certs]

                if not certs:
                    reply = f"No certificates found for {student['first_name']}."
                else:
                    titles = [c["title"] for c in certs]
                    reply = "Certificates:\n- " + "\n- ".join(titles[:20])


    # ----------------------------------------------------------
    # 5️⃣ Memory Lookup
    # ----------------------------------------------------------
    elif intent == "memory_lookup":
        phrase = meta.get("memory_phrase", "")
        found = search_memory(phrase)

        if found:
            reply = f"I found this earlier: \"{found}\""
        else:
            reply = "No memory found for that phrase."


    # ----------------------------------------------------------
    # 6️⃣ Fallback LLM (Admin unrestricted)
    # ----------------------------------------------------------
    else:
        if AI_AVAILABLE:
            reply = call_gemini_short(
                f"You are AdminAssist. Answer the admin's question accurately.\n\nQUESTION: {query}"
            )
        else:
            reply = "LLM not available. Ask: certificates, student lookup, mentors, mentees, etc."


    # save assistant reply
    st.session_state.messages.append({"role": "assistant", "content": reply})
    save_chat_history_for(st.session_state.user, st.session_state.messages)

    with st.chat_message("assistant"):
        st.markdown(reply)
