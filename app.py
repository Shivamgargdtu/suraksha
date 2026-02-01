import streamlit as st
import json
from google import genai
import logging
import re
import time
from typing import Optional

# ================= CONFIG =================
MODEL_NAME = "models/gemini-2.5-flash"
MAX_API_RETRIES = 1

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
Analyze the message below for phishing, scams, or social engineering.

Return ONLY valid JSON with:
- Risk_Score (integer 0-100)
- Risk_Level ("Low" | "Medium" | "High")
- Reason (two concise sentences)

Message:
\"\"\"{message_text}\"\"\"
"""

# ================= JSON EXTRACTION =================
def extract_json_from_text(text: str) -> Optional[dict]:
    try:
        return json.loads(text)
    except Exception:
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
        "click here"
    ]

    suspicious_hits = sum(1 for w in urgency_terms if w in text)
    has_money = any(w in text for w in ["rs", "₹", "rupees", "upi", "pay", "transfer"])
    has_link = "http" in text or "www." in text

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

# ================= RETRY WRAPPER =================
def with_retries(fn, max_attempts=1, backoff=0.6):
    for attempt in range(max_attempts):
        try:
            return fn()
        except Exception as e:
            logger.warning(f"Attempt {attempt+1} failed: {e}")
            time.sleep(backoff * (2 ** attempt))
    raise RuntimeError("Maximum retry attempts reached")

# ================= AI ANALYSIS =================
def analyze_message_impl(message_text: str, api_key: str) -> dict:
    client = genai.Client(api_key=api_key)
    prompt = build_prompt(message_text)

    def call():
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
            config={
                "response_mime_type": "application/json",
                "temperature": 0.15,
                "max_output_tokens": 512
            }
        )

        text = getattr(response, "text", str(response))
        parsed = extract_json_from_text(text)
        if not parsed:
            raise ValueError("Invalid JSON returned")

        parsed["Risk_Score"] = max(0, min(100, int(parsed.get("Risk_Score", 0))))
        parsed["Risk_Level"] = parsed.get("Risk_Level", "Low").capitalize()
        parsed["Reason"] = parsed.get("Reason", "").strip()
        parsed["fallback"] = False
        return parsed

    try:
        return with_retries(call, MAX_API_RETRIES)
    except Exception as e:
        err = str(e).lower()
        if "quota" in err or "429" in err:
            logger.warning("Quota exceeded — using heuristic fallback")
            return heuristic_analysis(message_text)
        return heuristic_analysis(message_text)

# ================= PAGE CONFIG =================
st.set_page_config(
    page_title="Suraksha",
    page_icon="🛡️",
    layout="centered"
)

# ================= STYLES =================
st.markdown("""
<style>
:root {
    --bg: #ffffff;
    --surface: #f6f7f8;
    --border: #e1e3e6;
    --text-primary: #111827;
    --text-secondary: #4b5563;

    --danger: #b42318;
    --warning: #b54708;
    --success: #027a48;
}

.stApp {
    background-color: var(--bg);
    color: var(--text-primary);
}

.results-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin-top: 24px;
}

.risk-badge {
    padding: 4px 12px;
    border-radius: 6px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    display: inline-block;
    margin-bottom: 8px;
}

.high { background: var(--danger); color: white; }
.medium { background: var(--warning); color: white; }
.low { background: var(--success); color: white; }

button[kind="primary"] {
    transition: transform 160ms cubic-bezier(.2,.8,.2,1),
                box-shadow 160ms cubic-bezier(.2,.8,.2,1);
}

button[kind="primary"]:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 14px rgba(0,0,0,0.08);
}
</style>
""", unsafe_allow_html=True)

# ================= MAIN APP =================
def main():
    st.markdown("## SURAKSHA")
    st.caption(
        "System for Unified Risk Assessment & Knowledge-based Security Heuristics & AI"
    )

    if "history" not in st.session_state:
        st.session_state.history = []

    api_key = st.secrets.get("GEMINI_API_KEY")

    if not api_key:
        st.info("LLM analysis disabled. Using local risk engine.")

    message = st.text_area(
        "Paste message for analysis",
        height=160,
        placeholder="Your account has been blocked. Verify immediately..."
    )

    scan = st.button("Check message risk")

    if scan and message.strip():
        with st.spinner("Analyzing message…"):
            result = analyze_message_impl(message, api_key) if api_key else heuristic_analysis(message)

        st.session_state.history.insert(0, {
            "message": message,
            "result": result,
            "timestamp": int(time.time())
        })

        score = result["Risk_Score"]
        level = result["Risk_Level"]
        reason = result["Reason"]

        st.markdown("### Recommended actions")
        if level == "High":
            st.error("Do not click links or share credentials. Contact your bank immediately.")
        elif level == "Medium":
            st.warning("Proceed cautiously. Verify sender through official channels.")
        else:
            st.success("No immediate threat detected. Remain vigilant.")

        st.markdown(f"""
        <div class="results-card">
            <div class="risk-badge {level.lower()}">RISK LEVEL: {level.upper()}</div>
            <h3>Threat score: {score}/100</h3>
            <p><strong>Analysis:</strong> {reason}</p>
            {"<p><em>Local heuristic analysis used.</em></p>" if result.get("fallback") else ""}
        </div>
        """, unsafe_allow_html=True)

        st.markdown("### Confidence estimate")
        st.progress(score / 100)

        report = {
            "message": message,
            "score": score,
            "level": level,
            "reason": reason,
            "fallback": result.get("fallback", False),
            "timestamp": int(time.time())
        }

        st.download_button(
            "Download report (JSON)",
            json.dumps(report, indent=2),
            file_name="Suraksha_report.json",
            mime="application/json"
        )

    with st.sidebar:
        st.header("Recent analyses")
        if not st.session_state.history:
            st.caption("No scans yet.")
        else:
            for h in st.session_state.history[:10]:
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(h["timestamp"]))
                st.markdown(f"- **{h['result']['Risk_Level']} {h['result']['Risk_Score']}/100**  \n_{ts}_")

if __name__ == "__main__":
    main()
