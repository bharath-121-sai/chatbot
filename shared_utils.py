# shared_utils.py
"""
Shared utilities for MentorAssist apps.

Features:
- chat file helpers (per-user JSON)
- spelling fixer / intent parser (mentor+admin)
- fuzzy matching helper (RapidFuzz)
- in-session memory API:
    memory_store(session, key, value)       # stores small facts in session
    memory_lookup(session, phrase)          # fuzzy/heuristic lookup from session memory + messages
    smart_memory_lookup(messages, phrase)   # fuzzy search in message history
Notes:
- This memory API is IN-SESSION only. Use st.session_state as `session` in Streamlit apps.
- RapidFuzz required: pip install rapidfuzz
"""
import re
import json
from pathlib import Path
from rapidfuzz import process, fuzz

CHAT_DIR = Path("chats")
CHAT_DIR.mkdir(exist_ok=True)


# ------------------------------
# Chat history helpers
# ------------------------------
def chat_file_for_user(user):
    """Return Path for the per-user chat JSON file (user is dict with 'username')."""
    return CHAT_DIR / f"chat_{user['username']}.json"


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


# ------------------------------
# Spelling / simple normalization
# ------------------------------
def fix_spelling(text: str) -> str:
    corrections = {
        "certifcats": "certificates",
        "certifactes": "certificates",
        "certifcate": "certificate",
        "crificates": "certificates",
        "ctificates": "certificates",
        "actvity": "activity",
        "scorre": "score",
        "undr": "under",
        "menti": "mentee",
        "mentis": "mentees",
        "howmany": "how many",
        "cnt": "count",
        "toper": "topper",
        "toppr": "topper",
        "perfomer": "performer",
        "whi is": "who is",
    }
    if not isinstance(text, str):
        return text
    t = text.lower()
    for bad, good in corrections.items():
        t = t.replace(bad, good)
    return t


# ------------------------------
# Intent parser (mentor + admin)
# ------------------------------
def parse_intent(text: str):
    """
    Return (intent, meta)
    meta = {"roll_query": None, "name_query": None, "memory_phrase": None}
    """
    t = fix_spelling((text or "").strip().lower())
    meta = {"roll_query": None, "name_query": None, "memory_phrase": None}

    # greetings
    if t in ("hi", "hello", "hey", "hii", "hlo", "good morning", "good evening"):
        return "greeting", meta

    # roll-like token (partial supported)
    roll = re.search(r"\b[0-9]{1,}[a-z0-9\-]{1,}\b", t)
    if roll:
        meta["roll_query"] = roll.group(0)

    # memory lookup: who is <phrase>
    m = re.match(r"who is (.+)", t)
    if m:
        meta["memory_phrase"] = m.group(1).strip()
        return "memory_lookup", meta

    # name lookup
    if "name of" in t or t.startswith("name "):
        if meta["roll_query"]:
            return "name_lookup", meta
        m2 = re.search(r"name of ([a-zA-Z ]+)", t)
        if m2:
            meta["name_query"] = m2.group(1).strip()
            return "name_lookup", meta

    # certificates
    if "certificate" in t or "certificates" in t:
        if "how many" in t or "count" in t or "number" in t:
            return "count_certificates", meta
        if "summary" in t or "summarize" in t:
            return "summarize_certificates", meta
        return "certificates", meta

    # activity score
    if "activity score" in t or ("activity" in t and "score" in t):
        return "activity_score", meta

    # mentees list
    if ("mentees" in t or "my mentees" in t or "students under me" in t or "who are my mentees" in t):
        return "mentees", meta

    # mentee count
    if (("how many" in t and "mentee" in t) or ("count" in t and "mentee" in t) or ("how many under" in t)):
        return "count_mentees", meta

    # admin-only intents
    if t.startswith("profile of") or t.startswith("student profile"):
        return "profile", meta
    if t.startswith("find student") or t.startswith("search student"):
        return "find_student", meta
    if t.startswith("show all students") or t.startswith("list students"):
        return "show_students", meta
    if "departments" in t or t.startswith("show departments"):
        return "departments", meta
    if "topper" in t or "top performer" in t:
        return "topper_query", meta

    # unknown
    return "unknown", meta


# ------------------------------
# Fuzzy candidate chooser (RapidFuzz)
# ------------------------------
def fuzzy_best_candidate(query: str, candidates: list, key=lambda x: x, score_cutoff: int = 60):
    """
    Return (best_candidate_obj, score) or (None, 0).
    `key` extracts string from candidate.
    """
    if not candidates:
        return None, 0
    mapping = {i: key(c) for i, c in enumerate(candidates)}
    best = process.extractOne(query, mapping, scorer=fuzz.token_set_ratio)
    if best and best[1] >= score_cutoff:
        idx = best[2]
        return candidates[idx], best[1]
    return None, 0


# ------------------------------
# Memory API (IN-SESSION ONLY)
# ------------------------------
# The functions expect a session-like dict (e.g., streamlit st.session_state).
#
# Design:
# - memory stored under session['memory'] as a dict: key -> list of values (history order).
# - memory_store(session, key, value) appends value to list.
# - memory_lookup(session, phrase) matches in following priority:
#     1) exact key match
#     2) fuzzy key match (partial ratio >= 75)
#     3) fuzzy match inside values (>=75)
#     4) fuzzy search across session['messages'] (chat history) using smart_memory_lookup
#
def _ensure_memory_container(session):
    if session is None:
        # fallback to process-level memory (not recommended, but provides a safe default)
        global _PROCESS_MEMORY
        try:
            _PROCESS_MEMORY
        except NameError:
            _PROCESS_MEMORY = {"memory": {}, "messages": []}
        return _PROCESS_MEMORY
    # ensure memory slot exists
    if "memory" not in session:
        session["memory"] = {}
    if "messages" not in session:
        # messages: list of {"role":..., "content":...}
        session["messages"] = []
    return session


def memory_store(session, key: str, value: str):
    """
    Store a small fact in session memory.
    Example: memory_store(st.session_state, "topper", "bharathsai is topper")
    """
    if not key or not value:
        return
    session = _ensure_memory_container(session)
    k = key.strip().lower()
    v = value.strip()
    mem = session["memory"].get(k)
    if mem:
        if isinstance(mem, list):
            mem.append(v)
        else:
            session["memory"][k] = [mem, v]
    else:
        session["memory"][k] = [v]


def memory_lookup(session, phrase: str):
    """
    Lookup memory by exact key or fuzzy match.
    Returns the most relevant stored string or None.
    """
    if not phrase:
        return None
    session = _ensure_memory_container(session)
    phrase_l = phrase.strip().lower()

    # exact key
    if phrase_l in session["memory"]:
        vals = session["memory"][phrase_l]
        if isinstance(vals, list):
            return vals[-1]
        return vals

    # fuzzy match on keys
    best_key = None
    best_score = 0
    for k in session["memory"].keys():
        score = fuzz.partial_ratio(phrase_l, k)
        if score > best_score:
            best_score = score
            best_key = k
    if best_key and best_score >= 75:
        vals = session["memory"].get(best_key)
        if isinstance(vals, list):
            return vals[-1]
        return vals

    # fuzzy match inside values
    for k, vals in session["memory"].items():
        if isinstance(vals, list):
            for v in reversed(vals):  # prefer latest
                score = fuzz.partial_ratio(phrase_l, v.lower())
                if score >= 75:
                    return v
        else:
            score = fuzz.partial_ratio(phrase_l, str(vals).lower())
            if score >= 75:
                return vals

    # last fallback: search messages (chat history)
    messages = session.get("messages", [])
    msg = smart_memory_lookup(messages, phrase_l)
    return msg


def smart_memory_lookup(messages, phrase: str):
    """
    Fuzzy search chat messages list (each message is dict with 'content').
    Returns the full message content if found, otherwise None.
    """
    if not phrase:
        return None
    best_msg = None
    best_score = 0
    for msg in reversed(messages):
        text = msg.get("content", "").lower()
        score = fuzz.partial_ratio(phrase, text)
        if score > best_score and score >= 70:
            best_score = score
            best_msg = msg.get("content")
    return best_msg
