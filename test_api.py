"""
Main Security Guardrail Pipeline Module
Implements Tier 1 (Regex & Encodings), Tier 2 (Local SLM Boundary),
Tier 3 (Multi-Provider Consensus), and Global Fail-Secure Fallbacks.
"""

import re
import urllib.parse
import base64
from dataclasses import dataclass, field
from typing import Optional, Dict

# Global telemetry tracking metrics
request_stats = {
    "regex_only": 0,
    "encoding_decoded": 0,
    "slm_tier2": 0,
    "llm_consensus": 0,
}

class ProviderUnavailableError(Exception):
    """Raised when an external LLM provider API is unreachable or failing."""
    pass

@dataclass
class ThreatVerdict:
    is_threat: bool
    reason: str
    owasp: Optional[str] = None
    provider_breakdown: Dict[str, bool] = field(default_factory=dict)

# ------------------------------------------------------------------------------
# TIER 1: REGEX, ENCODINGS, AND KNOWN THREAT PATTERNS
# ------------------------------------------------------------------------------

DIRECT_INJECTION_PATTERNS = [
    r"(?i)ignore\s+all\s+previous\s+instructions",
    r"(?i)reveal\s+system\s+prompt",
    r"(?i)DAN\s+mode\s+activated",
    r"(?i)do\s+anything\s+now",
]

EXCESSIVE_AGENCY_PATTERNS = [
    r"(?i)SELECT\s+.*\s+FROM\s+.*;\s*DELETE\s+FROM",
    r"\$\(whoami\)",
    r"(?i)run\s+command:",
]

INDIRECT_INJECTION_PATTERNS = [
    r"(?i)Attention\s+AI:",
    r"(?i)disregard\s+user\s+instructions",
]

def try_base64_decode(text: str) -> Optional[str]:
    """Helper to safely attempt Base64 decoding of input strings."""
    try:
        decoded_bytes = base64.b64decode(text.encode("utf-8"), validate=True)
        decoded_str = decoded_bytes.decode("utf-8")
        if decoded_str.isprintable() and len(decoded_str.strip()) > 0:
            return decoded_str
    except Exception:
        pass
    return None

def check_tier1_patterns(prompt: str, content_source: str = "user_input") -> Optional[ThreatVerdict]:
    """Inspects raw or decoded input against Tier 1 deterministic patterns."""
    
    # Check 1: Direct Prompt Injections
    for pattern in DIRECT_INJECTION_PATTERNS:
        if re.search(pattern, prompt):
            request_stats["regex_only"] += 1
            return ThreatVerdict(
                is_threat=True,
                reason="Matched known attack pattern: Direct Prompt Injection",
                owasp="LLM01: Prompt Injection",
                provider_breakdown={"Tier1_Regex": True}
            )

    # Check 2: Excessive Agency / Command Injection
    for pattern in EXCESSIVE_AGENCY_PATTERNS:
        if re.search(pattern, prompt):
            request_stats["regex_only"] += 1
            return ThreatVerdict(
                is_threat=True,
                reason="Matched known attack pattern: Excessive Agency / Command Execution",
                owasp="LLM06: Excessive Agency",
                provider_breakdown={"Tier1_Regex": True}
            )

    # Check 3: Indirect Prompt Injection (for non-user retrieved content)
    if content_source == "retrieved_content":
        for pattern in INDIRECT_INJECTION_PATTERNS:
            if re.search(pattern, prompt):
                request_stats["regex_only"] += 1
                return ThreatVerdict(
                    is_threat=True,
                    reason="Retrieved content contains AI-directed instruction language",
                    owasp="LLM01: Prompt Injection",
                    provider_breakdown={"Tier1_Regex": True}
                )

    # Check 4: Recursive Encoding Decoders (URL Decoding & Base64)
    # URL Decode Check
    unquoted = urllib.parse.unquote(prompt)
    if unquoted != prompt:
        decoded_verdict = check_tier1_patterns(unquoted, content_source)
        if decoded_verdict and decoded_verdict.is_threat:
            request_stats["encoding_decoded"] += 1
            decoded_verdict.reason = f"Detected URL-encoded threat payload: {decoded_verdict.reason}"
            return decoded_verdict

    # Base64 Decode Check
    decoded_b64 = try_base64_decode(prompt)
    if decoded_b64 and decoded_b64 != prompt:
        decoded_verdict = check_tier1_patterns(decoded_b64, content_source)
        if decoded_verdict and decoded_verdict.is_threat:
            request_stats["encoding_decoded"] += 1
            decoded_verdict.reason = f"Detected Base64-encoded threat payload: {decoded_verdict.reason}"
            return decoded_verdict

    return None

# ------------------------------------------------------------------------------
# TIER 2: LOCAL SLM STUB / INTERFACE
# ------------------------------------------------------------------------------

def analyze_prompt_tier2(prompt: str) -> dict:
    """
    Placeholder for actual local SLM model (e.g., DeBERTa-v3 guardrail).
    Override via unittest.mock.patch in pytest tests.
    """
    return {"is_jailbreak": False, "confidence": 0.10}

# ------------------------------------------------------------------------------
# TIER 3: MULTI-PROVIDER CONSENSUS & FALLBACKS
# ------------------------------------------------------------------------------

def check_prompt_gemini(prompt: str) -> ThreatVerdict:
    """Mock/Stub call to Gemini Guardrail API."""
    return ThreatVerdict(is_threat=False, reason="Gemini safe", owasp=None)

def check_prompt_groq(prompt: str) -> ThreatVerdict:
    """Mock/Stub call to Groq Guardrail API."""
    return ThreatVerdict(is_threat=False, reason="Groq safe", owasp=None)

def check_prompt(prompt: str) -> ThreatVerdict:
    """Evaluates prompt against Tier 3 multi-provider consensus with fallback logic."""
    gemini_verdict = None
    groq_verdict = None
    gemini_error = None
    groq_error = None

    try:
        gemini_verdict = check_prompt_gemini(prompt)
    except ProviderUnavailableError as e:
        gemini_error = e

    try:
        groq_verdict = check_prompt_groq(prompt)
    except ProviderUnavailableError as e:
        groq_error = e

    # Case 1: Both providers fail -> Escalates to global fail-secure
    if gemini_error and groq_error:
        raise ProviderUnavailableError(f"Both providers unavailable: Gemini ({gemini_error}), Groq ({groq_error})")

    # Case 2: Gemini fails, fall back to Groq
    if gemini_error:
        groq_verdict.reason = f"Gemini unavailable; using Groq only: {groq_verdict.reason}"
        return groq_verdict

    # Case 3: Groq fails, fall back to Gemini
    if groq_error:
        gemini_verdict.reason = f"Groq unavailable; using Gemini only: {gemini_verdict.reason}"
        return gemini_verdict

    # Case 4: Both available -> Multi-provider consensus
    if gemini_verdict.is_threat == groq_verdict.is_threat:
        return ThreatVerdict(
            is_threat=gemini_verdict.is_threat,
            reason=f"Both providers agree: {gemini_verdict.reason}",
            owasp=gemini_verdict.owasp or groq_verdict.owasp,
            provider_breakdown={"Gemini": gemini_verdict.is_threat, "Groq": groq_verdict.is_threat}
        )

    # Case 5: Disagreement -> Default to Threat / Flag for Human Review
    flagged_owasp = gemini_verdict.owasp if gemini_verdict.is_threat else groq_verdict.owasp
    return ThreatVerdict(
        is_threat=True,
        reason="Providers disagree — flagged for review",
        owasp=flagged_owasp,
        provider_breakdown={"Gemini": gemini_verdict.is_threat, "Groq": groq_verdict.is_threat}
    )

# ------------------------------------------------------------------------------
# FULL PIPELINE ENTRYPOINT (WITH FAIL-SECURE DEFAULT)
# ------------------------------------------------------------------------------

def full_check(prompt: str, content_source: str = "user_input") -> ThreatVerdict:
    """
    Executes complete 3-Tier Security Guardrail Pipeline.
    Guarantees Global Fail-Secure Default on multi-tier crashes.
    """
    try:
        # Tier 1: Fast Deterministic Pattern Matching
        tier1_verdict = check_tier1_patterns(prompt, content_source)
        if tier1_verdict and tier1_verdict.is_threat:
            return tier1_verdict

        # Tier 2: Local SLM Boundary
        try:
            slm_result = analyze_prompt_tier2(prompt)
            request_stats["slm_tier2"] += 1
            confidence = slm_result.get("confidence", 0.0)
            is_jailbreak = slm_result.get("is_jailbreak", False)

            # High confidence or Jailbreak flag -> Short circuit threat
            if is_jailbreak or confidence >= 0.60:
                return ThreatVerdict(
                    is_threat=True,
                    reason=f"Flagged by Tier 2 Local SLM (Confidence: {confidence:.2%})",
                    owasp="LLM01: Prompt Injection",
                    provider_breakdown={"Tier2_SLM": True}
                )

            # Low confidence -> Short circuit safe
            if confidence < 0.25:
                return ThreatVerdict(
                    is_threat=False,
                    reason="Passed Tier 2 Local SLM",
                    owasp=None,
                    provider_breakdown={"Tier2_SLM": False}
                )

        except Exception as tier2_err:
            print(f"⚠️ Tier 2 SLM Error: {tier2_err}. Escalating to Tier 3 LLM Consensus.")

        # Tier 3: Multi-Provider LLM Consensus
        try:
            request_stats["llm_consensus"] += 1
            return check_prompt(prompt)
        except ProviderUnavailableError as tier3_err:
            print(f"⚠️ Tier 3 Outage: {tier3_err}")

    except Exception as global_err:
        print(f"🚨 CRITICAL PIPELINE FAILURE: {global_err}")

    # GLOBAL FAIL-SECURE DEFAULT
    # Reached ONLY when Tier 2 fails/escalates AND Tier 3 providers completely fail.
    return ThreatVerdict(
        is_threat=True,
        reason="System Security Fallback: Processing unavailable across all guardrail tiers.",
        owasp="LLM10: Unchecked System Failures",
        provider_breakdown={"Global_FailSecure_Fallback": True}
    )