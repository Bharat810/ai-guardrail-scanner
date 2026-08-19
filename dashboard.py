import streamlit as st
from test_api import full_check

st.title("AI Security Guardrail Scanner")
st.write("Enter a prompt below to check if it's a prompt injection attempt.")

user_input = st.text_area("Prompt to check:")
if st.button("Scan"):
    if user_input:
        result = full_check(user_input)
        if result.is_threat:
            st.error(f"⚠️ THREAT DETECTED: {result.reason}")
        else:
            st.success(f"✅ Safe: {result.reason}")

        if result.provider_breakdown:
            with st.expander("Provider breakdown"):
                for provider, flagged in result.provider_breakdown.items():
                    label = "🔴 Threat" if flagged else "🟢 Safe"
                    st.write(f"**{provider.capitalize()}**: {label}")
    else:
        st.warning("Please enter some text to scan.")