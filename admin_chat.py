# admin_chat.py
import streamlit as st
from shared_utils import parse_intent, load_chat_history_for, save_chat_history_for
from db_utils import find_students_by_query, get_certificates_for_student, get_student_by_id, get_mentees, get_department_by_id, count_certificates
from ai_core import call_gemini_short
import json

st.set_page_config(page_title="Admin Chat", layout="wide")
st.title("Admin Chatbot (admin only)")
st.sidebar.header("Admin Login (simulate)")

USERS = {
    "admin": {"username":"admin","password":"admin123","role":"admin","admin_id":1}
}

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user = None
    st.session_state.messages = []

with st.sidebar:
    if not st.session_state.logged_in:
        u = st.text_input("Username", key="au")
        p = st.text_input("Password", type="password", key="ap")
        if st.button("Login"):
            user = USERS.get(u)
            if user and user.get("password")==p:
                st.session_state.logged_in = True
                st.session_state.user = user.copy()
                st.session_state.messages = load_chat_history_for(user)
                st.rerun()
            else:
                st.error("Invalid")
    else:
        st.markdown(f"**User:** {st.session_state.user['username']}\n**Role:** admin")
        if st.button("Logout"):
            st.session_state.logged_in=False
            st.session_state.user=None
            st.session_state.messages=[]
            st.rerun()

if not st.session_state.logged_in:
    st.stop()

user = st.session_state.user

st.subheader("Chat")
for m in st.session_state.messages:
    with st.chat_message(m["role"]):
        st.markdown(m["content"])

query = st.chat_input("Ask admin questions (e.g., 'certificates of 21BD1A05A1', 'how many certificates does Priya have')")

if query:
    st.session_state.messages.append({"role":"user","content":query})
    save_chat_history_for(user, st.session_state.messages)

    intent, meta = parse_intent(query)
    reply = ""

    if intent in ("certificates", "count_certificates"):
        student = None
        if meta.get("student_id"):
            student = get_student_by_id(meta["student_id"])
        elif meta.get("roll_query"):
            found = find_students_by_query(meta["roll_query"], limit=5)
            for f in found:
                if f.get("roll_number") and f.get("roll_number").lower() == meta["roll_query"].lower():
                    student = f; break
            if not student and found:
                student = found[0]
        elif meta.get("name_query"):
            found = find_students_by_query(meta["name_query"], limit=5)
            student = found[0] if found else None

        if not student:
            reply = "No student found."
        else:
            if intent == "count_certificates":
                cnt = count_certificates(student.get("id"))
                reply = f"{student.get('first_name','')} {student.get('last_name','')} has {cnt} certificates."
            else:
                certs = get_certificates_for_student(student.get("id"))
                if not certs:
                    reply = "No certificates found."
                else:
                    payload = {"query": query, "student": student, "certificates": certs}
                    prompt = f"Answer concisely using only the data below. Do not invent facts.\n\n{json.dumps(payload, indent=2)}"
                    reply = call_gemini_short(prompt)

    elif intent == "mentees":
        # admin can view mentees of any mentor by asking "mentees of mentor <id>" or "my mentees" (admin's contextless)
        reply = "As admin you can query mentees by mentor id or search a student."

    elif intent in ("profile", "find_student"):
        student = None
        if meta.get("roll_query"):
            found = find_students_by_query(meta["roll_query"], limit=5)
            student = found[0] if found else None
        elif meta.get("name_query"):
            found = find_students_by_query(meta["name_query"], limit=5)
            student = found[0] if found else None

        if not student:
            reply = "No student found."
        else:
            dept = get_department_by_id(student.get("department_id"))
            lines = [
                f"Name: {student.get('first_name','')} {student.get('last_name','')}",
                f"Roll: {student.get('roll_number')}",
                f"Batch: {student.get('batch_year')}",
                f"Semester: {student.get('current_semester')}",
                f"Department: {dept.get('name') if dept else 'N/A'}",
                f"Mentor ID: {student.get('mentor_id')}"
            ]
            reply = "\n\n".join(lines)
    else:
        reply = "I can answer certificate and profile queries. Try: 'certificates of 21BD1A05A1' or 'how many certificates does Priya have'."

    st.session_state.messages.append({"role":"assistant","content":reply})
    save_chat_history_for(user, st.session_state.messages)
    with st.chat_message("assistant"):
        st.markdown(reply)
