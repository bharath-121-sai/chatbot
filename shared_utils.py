# shared_utils.py
import re
import json
from pathlib import Path
from rapidfuzz import process, fuzz

CHAT_DIR = Path("chats")
CHAT_DIR.mkdir(exist_ok=True)

# --------------------------------------------
# CHAT HISTORY HELPERS
# --------------------------------------------

def chat_file_for_user(user):
    return CHAT_DIR / f"chat_{user['username']}.json"

def load_chat_history_for(user):
    f = chat_file_for_user(user)
    if f.exists():
        return json.loads(open(f).read())
    return []

def save_chat_history_for(user, messages):
    f = chat_file_for_user(user)
    with open(f, "w") as fw:
        json.dump(messages, fw, indent=2)


# --------------------------------------------
# SPELLING CORRECTION (typo-fix engine)
# --------------------------------------------

def fix_spelling(text: str) -> str:
    corrections = {
        "certifcats": "certificates",
        "certifactes": "certificates",
        "certifcate": "certificate",
        "actvity": "activity",
        "scorre": "score",
        "undr": "under",
        "menti": "mentee",
        "mentis": "mentees",
        "howmany": "how many",
        "countmy": "count my"
    }
    t = text.lower()
    for bad, good in corrections.items():
        t = t.replace(bad, good)
    return t


# --------------------------------------------
# INTENT PARSER (MENTOR VERSION)
# --------------------------------------------

def parse_intent(text: str):
    """
    Clean text → detect intent → return (intent_name, meta_data)
    """
    t = fix_spelling(text.strip().lower())
    meta = {"roll_query": None, "name_query": None, "memory_phrase": None}

    # 1) Greetings
    if t in ("hi", "hello", "hey", "hii", "hlo", "good morning", "good evening"):
        return "greeting", meta

    # 2) Roll number (partial also supported)
    roll = re.search(r"\b[0-9]{1,}[A-Za-z0-9\-]{1,}\b", t)
    if roll:
        meta["roll_query"] = roll.group(0)

    # 3) Memory lookup (who is ___)
    m = re.match(r"who is (.+)", t)
    if m:
        meta["memory_phrase"] = m.group(1).strip()
        return "memory_lookup", meta

    # 4) Name lookup
    if "name of" in t or t.startswith("name "):
        # case: name of <roll>
        if meta["roll_query"]:
            return "name_lookup", meta

        # case: name of John
        m2 = re.search(r"name of ([a-zA-Z ]+)", t)
        if m2:
            meta["name_query"] = m2.group(1).strip()
            return "name_lookup", meta

    # 5) Certificates / count
    if "certificate" in t or "certificates" in t:
        if "how many" in t or "count" in t or "number" in t:
            return "count_certificates", meta
        return "certificates", meta

    # 6) Activity score
    if "activity score" in t or ("activity" in t and "score" in t):
        return "activity_score", meta

    # 7) Mentee list
    if ("mentees" in t or "my mentees" in t or 
        "students under me" in t or "who are my mentees" in t):
        return "mentees", meta

    # 8) Mentee count
    if ("how many" in t and "mentee" in t) or \
       ("count" in t and "mentee" in t) or \
       ("how many under" in t):
        return "count_mentees", meta

    # 9) Unknown → delegate to LLM
    return "unknown", meta


# --------------------------------------------
# FUZZY MATCH HELPER
# --------------------------------------------

def fuzzy_best_candidate(query: str, candidates: list, key=lambda x: x, score_cutoff: int = 60):
    """
    Choose best fuzzy match from candidate objects.
    key(obj) must return string for fuzzy matching.
    Returns (best_candidate, score)
    """
    if not candidates:
        return None, 0

    mapping = {i: key(c) for i, c in enumerate(candidates)}

    best = process.extractOne(query, mapping, scorer=fuzz.token_set_ratio)

    if best and best[1] >= score_cutoff:
        idx = best[2]
        return candidates[idx], best[1]

    return None, 0
