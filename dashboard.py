import streamlit as st
import requests

st.title("AI Security Guardrail Scanner")
st.write("Enter a prompt below to check if it's a prompt injection attempt.")

user_input = st.text_area("Prompt to check:")

if st.button("Scan"):
    if user_input:
        response = requests.post(
            "http://127.0.0.1:8000/v1/scan-prompt",
            params={"user_input": user_input}
        )
        result = response.json()
        
        if result["is_threat"]:
            st.error(f"⚠️ THREAT DETECTED: {result['reason']}")
        else:
            st.success(f"✅ Safe: {result['reason']}")
    else:
        st.warning("Please enter some text to scan.")