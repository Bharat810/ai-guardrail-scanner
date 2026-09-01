import streamlit as st
import requests

st.set_page_config(page_title="AI Guardrail Gateway", page_icon="🛡️", layout="wide")

st.title("🛡️ 3-Tier AI Guardrail Scanner Gateway")
st.write("Real-time threat analysis via FastAPI Security Service")

API_URL = "http://127.0.0.1:8000"

# Fetch live stats from FastAPI /v1/stats
def fetch_stats():
    try:
        res = requests.get(f"{API_URL}/v1/stats", timeout=3)
        if res.status_code == 200:
            return res.json()
    except Exception:
        pass
    return None

stats_data = fetch_stats()

# Live Gateway Stats Bar
st.subheader("📊 Live Gateway Stats")
col1, col2, col3, col4 = st.columns(4)

if stats_data and "tier_breakdown" in stats_data:
    tb = stats_data["tier_breakdown"]
    col1.metric("Tier 1: Regex", tb.get("tier1_regex", 0))
    col2.metric("Tier 1: Decodes", tb.get("tier1_decoding", 0))
    col3.metric("Tier 2: Local SLM", tb.get("tier2_slm_local", 0))
    col4.metric("Tier 3: Cloud LLM", tb.get("tier3_llm_consensus", 0))
else:
    col1.metric("Tier 1: Regex", "Offline")
    col2.metric("Tier 1: Decodes", "Offline")
    col3.metric("Tier 2: Local SLM", "Offline")
    col4.metric("Tier 3: Cloud LLM", "Offline")

st.divider()

# Input prompt area
user_prompt = st.text_area("Enter prompt to scan:", height=120, placeholder="Type a prompt or injection payload...")
content_source = st.selectbox("Content Source:", ["user_input", "retrieved_content"])

if st.button("Scan Prompt", type="primary"):
    if not user_prompt.strip():
        st.warning("Please enter a prompt first.")
    else:
        with st.spinner("Scanning through security tiers..."):
            try:
                payload = {"user_input": user_prompt, "content_source": content_source}
                response = requests.post(f"{API_URL}/v1/scan", json=payload, timeout=10)
                
                if response.status_code == 200:
                    result = response.json()
                    
                    if result.get("is_threat"):
                        st.error(f"🚨 **THREAT DETECTED**")
                        st.write(f"**Reason:** {result.get('reason')}")
                        st.write(f"**OWASP Category:** {result.get('owasp')}")
                    else:
                        st.success("✅ **PROMPT SAFE**")
                        st.write(f"**Verdict:** {result.get('reason')}")
                    
                    st.json(result.get("provider_breakdown", {}))
                    st.rerun()  # Refresh metrics after scan
                else:
                    st.error(f"Server error: {response.status_code}")
            except requests.exceptions.ConnectionError:
                st.error("⚠️ Could not connect to FastAPI server. Make sure `uvicorn app.main:app` is running on port 8000.")