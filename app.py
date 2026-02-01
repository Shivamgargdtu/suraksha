"""
Suraksha Streamlit app — Gemini (google-genai) version.

Requires:
    pip install -U streamlit google-genai

Set API key in `.streamlit/secrets.toml`:
    GEMINI_API_KEY = "your_api_key_here"
"""

import streamlit as st
import json
import logging
import re
import time
import os
from typing import Optional
from google import genai

# ================= CONFIG =================
MODEL_NAME = "gemini-3-flash-preview"   # matches Gemini quickstart docs
MAX_API_RETRIES = 1
TIMEOUT_BACKOFF = 1.0  # seconds

# ================= LOGGING =================
logger = logging.getLogger("Suraksha")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

# ================= PROMPT =================
def build_prompt(message_text: str) -> str:
    return f"""
You are a professional financial fraud investigator.
Analyze the following message for phishing, scams, or social engineering.

Return a JSON object with exactly these keys:
- Risk_Score (integer 0-100)
- Risk_Level ("Low" | "Medium" | "High")
- Reason (two concise sentences)

Message:
\"\"\"{message_text}\"\"\"
"""

# ================= JSON PARSING (robust) =================
def parse_json_response(text: str) -> Optional[dict]:
    """
    Try to parse the response as JSON. If it fails, try to extract the first {...} block.
    Return None if parsing fails.
    """
    if not text:
        return None
    # Prefer direct parse
    try:
        return json.loads(text)
    except Exception:
        pass

    # Fallback: find first JSON object in the text (braced block)
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        try:
            return json.loads(match.group(0))
        except Exception:
            return None
    return None

# ================= HEURISTIC FALLBACK =================
def heuristic_analysis(message_text: str) -> dict:
    text = (message_text or "").lower()

    urgency_terms = [
        "urgent", "immediately", "asap", "blocked", "suspended",
        "verify", "account locked", "otp", "one-time", "transfer",
        "click here", "verify now", "act now"
    ]

    suspicious_hits = sum(1 for w in urgency_terms if w in text)
    has_money = any(w in text for w in ["rs", "₹", "rupees", "upi", "pay", "transfer", "amount", "withdraw"])
    has_link = "http" in text or "www." in text or ".com" in text

    if suspicious_hits >= 2 or has_link:
        score = 85
    elif suspicious_hits == 1 or has_money:
        score = 55
    else:
        score = 5

    if score >= 80:
        level = "High"
        reason = "Urgent or monetary language detected with suspicious structure. High likelihood of social engineering."
    elif score >= 40:
        level = "Medium"
        reason = "Some indicators of potential manipulation or pressure tactics detected. Verification is advised."
    else:
        level = "Low"
        reason = "No significant indicators of phishing or fraud detected from rule-based analysis."

    return {
        "Risk_Score": score,
        "Risk_Level": level,
        "Reason": reason,
        "fallback": True
    }

# ================= RETRY HELPER =================
def with_retries(fn, max_attempts=1, backoff=TIMEOUT_BACKOFF):
    last_exc = None
    for attempt in range(max_attempts + 1):
        try:
            return fn()
        except Exception as e:
            last_exc = e
            logger.warning("Attempt %d failed: %s", attempt + 1, e)
            if attempt < max_attempts:
                time.sleep(backoff * (2 ** attempt))
    raise last_exc

# ================= AI ANALYSIS (google-genai) =================
def analyze_message_impl(message_text: str, api_key: Optional[str]) -> dict:
    """
    Use google-genai Client to request structured JSON from Gemini.
    Falls back to local heuristic on any failure.
    """
    if not api_key:
        return heuristic_analysis(message_text)

    # Initialize client explicitly with API key (client picks from env if None)
    client = genai.Client(api_key=api_key)

    prompt = build_prompt(message_text)

    def call():
        # generate_content returns a response object with .text
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
            config={
                "response_mime_type": "application/json",  # ask for strict JSON
                "temperature": 0.15,
                "max_output_tokens": 512
            }
        )

        # Some SDKs place the text on response.text; ensure we handle both
        text = getattr(response, "text", None) or getattr(response, "content", None) or str(response)
        logger.info("LLM raw output:\n%s", text)

        parsed = parse_json_response(text)
        if not parsed:
            raise ValueError("Empty or Invalid JSON received from LLM")

        # Normalize and validate fields
        try:
            parsed["Risk_Score"] = max(0, min(100, int(parsed.get("Risk_Score", 0))))
        except Exception:
            parsed["Risk_Score"] = 0

        parsed["Risk_Level"] = str(parsed.get("Risk_Level", "Low")).capitalize()
        parsed["Reason"] = str(parsed.get("Reason", "")).strip()
        parsed["fallback"] = False
        return parsed

    try:
        parsed = with_retries(call, max_attempts=MAX_API_RETRIES)
        return parsed
    except Exception as e:
        # If error mentions quota/429, we keep it logged
        errstr = str(e).lower()
        if "quota" in errstr or "429" in errstr:
            logger.warning("Quota/Rate limit detected: %s", e)
        else:
            logger.error("AI Analysis Failed: %s", e)
        return heuristic_analysis(message_text)

# ================= STREAMLIT APP =================
st.set_page_config(page_title="Suraksha", page_icon="🛡️", layout="centered")

st.markdown("## SURAKSHA")
st.caption("System for Unified Risk Assessment & Knowledge-based Security Heuristics & AI")

if "history" not in st.session_state:
    st.session_state.history = []

# Obtain API key from Streamlit secrets first, else environment
api_key = None
try:
    api_key = st.secrets.get("GEMINI_API_KEY")
except Exception:
    api_key = None
if not api_key:
    api_key = os.environ.get("GEMINI_API_KEY")

if not api_key:
    st.info("No GEMINI_API_KEY found. The app will run in local (heuristic) mode only.")

# UI input
message = st.text_area("Paste message for analysis", height=160, placeholder="Your account has been blocked. Verify immediately...")

if st.button("Check message risk") and message.strip():
    with st.spinner("Analyzing message…"):
        result = analyze_message_impl(message, api_key)

    # Save history
    st.session_state.history.insert(0, {
        "message": message,
        "result": result,
        "timestamp": int(time.time())
    })

    score = result["Risk_Score"]
    level = result["Risk_Level"]
    reason = result["Reason"]
    fallback = result.get("fallback", False)

    st.markdown("### Recommended actions")
    if level == "High":
        st.error("Do not click links or share credentials. Contact your bank immediately.")
    elif level == "Medium":
        st.warning("Proceed cautiously. Verify sender through official channels.")
    else:
        st.success("No immediate threat detected. Remain vigilant.")

    st.markdown(f"""
    <div style="background:#f6f7f8;border:1px solid #e1e3e6;border-radius:8px;padding:18px;margin-top:12px;">
        <div style="display:inline-block;padding:6px 12px;border-radius:6px;font-weight:700;background:{'#b42318' if level=='High' else ('#b54708' if level=='Medium' else '#027a48')};color:white;">
            {level.upper()}
        </div>
        <h3 style="margin-top:8px;">Threat score: {score}/100</h3>
        <p><strong>Analysis:</strong> {reason}</p>
        {("<p style='color:gray;font-size:0.9em'><em>⚠️ AI Unavailable — Local heuristic analysis used.</em></p>") if fallback else ""}
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### Confidence estimate")
    st.progress(score / 100)

    # Downloadable report
    report = {
        "message": message,
        "score": score,
        "level": level,
        "reason": reason,
        "fallback": fallback,
        "timestamp": int(time.time())
    }
    st.download_button("Download report (JSON)", json.dumps(report, indent=2), file_name="suraksha_report.json", mime="application/json")

# Sidebar: recent history
with st.sidebar:
    st.header("Recent analyses")
    if not st.session_state.history:
        st.caption("No scans yet.")
    else:
        for h in st.session_state.history[:10]:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(h["timestamp"]))
            r = h["result"]
            st.markdown(f"- **{r['Risk_Level']} {r['Risk_Score']}/100**  \n_{ts}_")
