# mentor_chat.py (FINAL — production-ready)
import streamlit as st
import os
import json
from datetime import datetime

from shared_utils import (
    parse_intent,
    save_chat_history_for,
    chat_file_for_user,
    fuzzy_best_candidate
)
from db_utils import (
    find_students_by_query,
    get_mentees,
    get_certificates_for_student,
    count_certificates
)
from ai_core import call_gemini_short, AI_AVAILABLE

# -----------------------
# Page config
# -----------------------
st.set_page_config(page_title="MentorAssist — Mentor Chat", layout="wide")
st.title("MentorAssist — Mentor Chat (Fuzzy + Memory + LLM Guidance)")

# -----------------------
# Simulated mentors (replace with real auth later)
# -----------------------
USERS = {
    "mentor5": {"username": "mentor5", "password": "mentor5", "mentor_id": 5},
    "mentor1": {"username": "mentor1", "password": "mentor1", "mentor_id": 1}
}

# -----------------------
# Streamlit session init
# -----------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user = None
    st.session_state.messages = []  # in-memory messages for current login session

# -----------------------
# Sidebar: Login / Logout
# -----------------------
with st.sidebar:
    st.header("Mentor Login (simulate)")

    if not st.session_state.logged_in:
        username_input = st.text_input("Username")
        password_input = st.text_input("Password", type="password")
        if st.button("Login"):
            user = USERS.get(username_input)
            if user and user["password"] == password_input:
                # Ensure fresh chat: delete any existing chat file for this user
                f = chat_file_for_user(user)
                try:
                    if os.path.exists(f):
                        os.remove(f)
                except Exception:
                    pass

                st.session_state.logged_in = True
                st.session_state.user = user.copy()
                # start fresh in-memory chat
                st.session_state.messages = []
                st.success(f"Logged in as {user['username']}")
                st.rerun()

            else:
                st.error("Invalid username or password")
    else:
        st.markdown(f"**User:** {st.session_state.user['username']}")
        st.markdown(f"**Role:** Mentor")
        if st.button("Logout"):
            # delete chat file and clear session memory
            f = chat_file_for_user(st.session_state.user)
            try:
                if os.path.exists(f):
                    os.remove(f)
            except Exception:
                pass

            st.session_state.logged_in = False
            st.session_state.user = None
            st.session_state.messages = []
            st.rerun()


# Stop if not logged in
if not st.session_state.logged_in:
    st.stop()

# -----------------------
# After login: user and mentees
# -----------------------
user = st.session_state.user
mentor_id = user["mentor_id"]

mentees = get_mentees(mentor_id) or []

st.sidebar.subheader("Your mentees")
if mentees:
    for m in mentees:
        st.sidebar.write(f"- {m.get('first_name','')} {m.get('last_name','')} ({m.get('roll_number','')})")
else:
    st.sidebar.write("No mentees found")

# -----------------------
# Display chat history (in-memory for this login)
# -----------------------
st.subheader("Chat")
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# -----------------------
# Input box
# -----------------------
query = st.chat_input("Ask something about your mentees... (partial names/rolls & typos OK)")

# -----------------------
# Helpers
# -----------------------
def fix_datetime(row):
    for k, v in list(row.items()):
        if isinstance(v, datetime):
            row[k] = v.strftime("%Y-%m-%d %H:%M:%S")
    return row

def search_memory(phrase: str):
    """Search previous messages (user + assistant) for a phrase."""
    if not phrase:
        return None
    phrase = phrase.lower()
    for msg in reversed(st.session_state.messages):
        if phrase in msg["content"].lower():
            return msg["content"]
    return None

def find_student_by_meta(meta):
    """Try DB ILIKE search then fuzzy among mentees, support partial roll/name."""
    q = meta.get("roll_query") or meta.get("name_query")
    if not q:
        return None

    # 1) Try DB ILIKE (broad)
    found = find_students_by_query(q, limit=30)
    if found:
        q_low = q.lower()
        # prefer exact or suffix roll matches
        for f in found:
            rn = (f.get("roll_number") or "").lower()
            if rn == q_low or rn.endswith(q_low) or q_low in rn:
                return f
        # restrict to mentees if possible
        mentee_ids = {m["id"] for m in mentees}
        mentee_candidates = [f for f in found if f["id"] in mentee_ids]
        if mentee_candidates:
            # fuzzy choose among mentee candidates
            cand, score = fuzzy_best_candidate(q, mentee_candidates,
                                               key=lambda x: f"{x.get('first_name','')} {x.get('last_name','')} {x.get('roll_number','')}",
                                               score_cutoff=55)
            if cand:
                return cand
            return mentee_candidates[0]
        # fallback to first DB result
        return found[0]

    # 2) If DB returned nothing -> fuzzy over current mentees
    if mentees:
        cand, score = fuzzy_best_candidate(q, mentees,
                                           key=lambda x: f"{x.get('first_name','')} {x.get('last_name','')} {x.get('roll_number','')}",
                                           score_cutoff=50)
        if cand:
            return cand

    return None

def guidance_by_llm(student: dict, certificates: list):
    """Call LLM to generate mentor guidance (2-3 bullets)."""
    payload = {
        "student": {"id": student.get("id"), "name": f"{student.get('first_name','')} {student.get('last_name','')}", "roll": student.get("roll_number")},
        "certificate_count": len(certificates),
        "certificates_sample": certificates[:6]
    }
    prompt = (
        "You are MentorAssist — an expert mentor assistant. "
        "Using ONLY the JSON below produce 2 concise, actionable recommendations the mentor can give the student to improve employability or skills. "
        "Write each recommendation on its own line.\n\n"
        f"{json.dumps(payload, indent=2)}\n\n"
        "Do NOT invent facts."
    )
    return call_gemini_short(prompt)

# -----------------------
# Main processing
# -----------------------
if query:
    # save user message to in-memory session
    st.session_state.messages.append({"role": "user", "content": query})
    # also persist during session (so reruns retain history); file will be deleted on logout
    save_chat_history_for(user, st.session_state.messages)

    intent, meta = parse_intent(query)
    reply = ""

    # GREETING
    if intent == "greeting":
        reply = "Hello! 👋 How can I help you today?"

    # MENTEE COUNT
    elif intent == "count_mentees":
        reply = f"You have {len(mentees)} mentees."

    # MENTEES LIST
    elif intent == "mentees":
        if not mentees:
            reply = "You have no mentees."
        else:
            reply = "\n\n".join([f"{m.get('first_name','')} {m.get('last_name','')} — Roll: {m.get('roll_number','')}" for m in mentees])

    # NAME LOOKUP
    elif intent == "name_lookup":
        s = find_student_by_meta(meta)
        if not s:
            reply = "No student found."
        elif s.get("mentor_id") != mentor_id:
            reply = "Access denied — not your mentee."
        else:
            reply = f"Name: {s.get('first_name','')} {s.get('last_name','')} — Roll: {s.get('roll_number','')}"

    # ACTIVITY SCORE
    elif intent == "activity_score":
        s = find_student_by_meta(meta)
        if not s:
            reply = "No student found."
        elif s.get("mentor_id") != mentor_id:
            reply = "Access denied — not your mentee."
        else:
            # DB may not have activity_score; handle safely
            score = s.get("activity_score")
            reply = f"Activity score of {s.get('roll_number','')} is {score if score is not None else 'Not available'}."

    # CERTIFICATES / COUNT
    elif intent in ("certificates", "count_certificates"):
        s = find_student_by_meta(meta)
        if not s:
            reply = "No student found."
        elif s.get("mentor_id") != mentor_id:
            reply = "Access denied — not your mentee."
        else:
            sid = s["id"]
            if intent == "count_certificates":
                cnt = count_certificates(sid)
                reply = f"{s.get('first_name','Student')} has {cnt} certificates."
            else:
                certs = get_certificates_for_student(sid)
                certs = [fix_datetime(c) for c in certs]
                if not certs:
                    reply = f"No certificates found for {s.get('first_name','Student')}."
                    # Optional: LLM guidance even when zero certificates
                    if AI_AVAILABLE:
                        guidance = call_gemini_short(
                            f"Student {s.get('first_name','Student')} (roll {s.get('roll_number')}) has 0 certificates. "
                            "As an expert mentor, provide 2 short actionable recommendations (each on its own line) they can follow to start building credentials."
                        )
                        if guidance:
                            reply += f"\n\nGuidance:\n{guidance}"
                else:
                    payload = {"student": s, "certificates": certs}
                    # LLM: short summary + guidance
                    summary_prompt = (
                        "You are MentorAssist. Using ONLY the JSON below, produce:\n"
                        "1) a one-line summary of the student's certificates, then\n"
                        "2) two concise mentor action items (each on its own line).\n\n"
                        + json.dumps(payload, indent=2)
                    )
                    summary = call_gemini_short(summary_prompt) if AI_AVAILABLE else None
                    guidance = guidance_by_llm(s, certs) if AI_AVAILABLE else None

                    # Build reply carefully in case AI not available / returned error
                    parts = []
                    if summary and not summary.lower().startswith("ai error") and not summary.lower().startswith("ai not available"):
                        parts.append(summary)
                    else:
                        # fallback to a simple titles list
                        titles = [c.get("title") for c in certs if c.get("title")]
                        parts.append("Certificates: " + (", ".join(titles[:10]) if titles else "Available."))

                    if guidance and not guidance.lower().startswith("ai error") and not guidance.lower().startswith("ai not available"):
                        parts.append("Guidance:\n" + guidance)
                    else:
                        # safe rule-based guidance fallback
                        cnt = len(certs)
                        if cnt <= 2:
                            parts.append("Guidance:\n- Encourage building small projects and participating in hackathons.")
                        else:
                            parts.append("Guidance:\n- Encourage internships and project-based portfolio.")

                    reply = "\n\n".join(parts)

    # MEMORY LOOKUP (who is ...)
    elif intent == "memory_lookup":
        phrase = (meta.get("memory_phrase") or "").lower()
        found = search_memory(phrase)
        if found:
            reply = f"I found this earlier in our chat: \"{found}\""
        else:
            # fallback: try to resolve as student partial name/roll
            s = find_student_by_meta({"roll_query": phrase, "name_query": phrase})
            if s:
                reply = f"{s.get('first_name','')} {s.get('last_name','')} — Roll: {s.get('roll_number','')}"
            else:
                reply = "I couldn't find that phrase in our conversation or mentee list."

    # UNKNOWN -> LLM fallback (restricted context)
    else:
        # Build safe context: small allowed student list + recent chat
        allowed_small = [{"id": m["id"], "name": f"{m.get('first_name','')} {m.get('last_name','')}", "roll": m.get('roll_number','')} for m in mentees]
        recent_chat = st.session_state.messages[-12:]
        prompt = (
            "You are MentorAssist AI. Use ONLY the facts provided below about students and the recent conversation to answer. "
            "If the user asks about a student not in the provided student list, reply 'Access Denied'. "
            "Answer concisely and do NOT hallucinate.\n\n"
            f"STUDENTS:\n{json.dumps(allowed_small, indent=2)}\n\n"
            f"RECENT_CHAT:\n{json.dumps(recent_chat, indent=2)}\n\n"
            f"USER QUESTION:\n{query}\n\nAnswer:"
        )

        if AI_AVAILABLE:
            llm_reply = call_gemini_short(prompt)
            if llm_reply and not llm_reply.lower().startswith("ai error") and not llm_reply.lower().startswith("ai not available"):
                reply = llm_reply
            else:
                reply = "I can answer: name, activity score, certificates, certificate count, mentees, mentee count. (LLM fallback failed.)"
        else:
            reply = "I can answer: name, activity score, certificates, certificate count, mentees, mentee count. (LLM not configured.)"

    # -----------------------
    # Save assistant reply in-memory and persist
    # -----------------------
    st.session_state.messages.append({"role": "assistant", "content": reply})
    save_chat_history_for(user, st.session_state.messages)

    with st.chat_message("assistant"):
        st.markdown(reply)
