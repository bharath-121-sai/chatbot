# ai_core.py
from dotenv import load_dotenv
import os
import google.generativeai as genai

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
print("DEBUG: GEMINI_API_KEY =", bool(GEMINI_API_KEY))

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    AI_AVAILABLE = True
else:
    AI_AVAILABLE = False

def call_gemini_short(prompt: str, model_name: str = "gemini-1.5-pro") -> str:
    """
    Send prompt to Gemini and return text. If API not available, return a fallback message.
    """
    if not AI_AVAILABLE:
        return "AI not available (no API key configured)."

    try:
        model = genai.GenerativeModel(model_name)
        result = model.generate_content(prompt)
        # try common fields
        if getattr(result, "text", None):
            return result.text
        if getattr(result, "candidates", None):
            first = result.candidates[0]
            return getattr(first, "content", None) or getattr(first, "text", None) or str(first)
        return str(result)
    except Exception as e:
        return f"AI error: {e}"
