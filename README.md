# AI Security Guardrail Scanner

A two-layer security service that detects prompt injection, jailbreak attempts, and LLM-agency exploitation before they reach a language model — built and validated using real attack techniques from PortSwigger's Web LLM Attacks labs.

**Live demo:** [ai-guardrail-scanner.streamlit.app](https://ai-guardrail-scanner.streamlit.app)
<img width="800" alt="AI Guardrail Scanner Live Demo" src="https://github.com/user-attachments/assets/672f392f-a83c-4722-80ea-061bb7f4dc14" />

## What it does

This tool inspects text intended for an LLM-powered application and classifies it as safe or malicious, with a stated reason. It's designed to sit in front of a chatbot or LLM-integrated app as a security checkpoint.

## Architecture

Two-layer detection, in order:

1. **Regex pattern matching** — instant, zero API cost, fully deterministic. Checks input against a categorized library of known attack patterns.
2. **LLM classification (Gemini)** — used only when regex finds nothing, to catch attacks that don't match known phrases (paraphrasing, novel framing, obfuscation).

This ordering matters: cheap, fast checks run first; the more expensive/flexible LLM check only runs when needed — the same design principle real security tools use (fail fast on known bad, escalate to deeper analysis for the unknown).

## Detected attack categories

Built from hands-on exploitation of real vulnerable applications (PortSwigger Web LLM Attacks labs), not synthetic examples:

- **Instruction override** — "ignore all previous instructions" style attacks
- **Jailbreak persona** — DAN and similar role-play-based restriction bypasses
- **SQL/tool injection** — exploiting LLM API/tool access to run destructive database commands
- **OS command injection** — shell metacharacter injection via LLM-invoked APIs (e.g. `$(whoami)`)
- **System prompt extraction** — attempts to reveal hidden system instructions
- **Authority impersonation** — falsely claiming admin/elevated permissions to justify bypassing rules

### OWASP LLM Top 10 alignment

Categories map to the [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/):

| Category | OWASP mapping |
|---|---|
| Instruction override | LLM01: Prompt Injection |
| Jailbreak persona | LLM01: Prompt Injection |
| Authority impersonation | LLM01: Prompt Injection |
| SQL/tool injection | LLM06: Excessive Agency |
| OS command injection | LLM06: Excessive Agency |
| System prompt extraction | LLM07: System Prompt Leakage |

Three categories map to LLM01 because they represent distinct *techniques* (direct override, persona-based bypass, false-authority framing) that share the same underlying OWASP risk classification — prompt injection is the entry vector in all three cases, even though the surface pattern differs enough to warrant separate detection rules.

### Encoding & obfuscation handling *Note: encoding-detection is verified functionally (see NOTES.md) but not yet incorporated into the accuracy benchmark below — planned for the next benchmark pass alongside upcoming multi-provider and prompt-refinement changes.*

Before classification, input is checked for common encodings (Base64, hex, URL-encoding). If detected, the payload is decoded and recursively passed back through the same detection pipeline (regex first, then LLM if needed) — up to 3 levels deep, to catch nested/layered encoding without infinite recursion.

This closes a real bypass: an attacker submitting `aWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM=` (Base64 for "ignore all previous instructions") would previously reach the LLM layer as an unrecognizable blob. Now it's decoded and correctly flagged by the regex layer itself — faster and more deterministic than relying on the LLM to notice.

Tech stack
Python · FastAPI · Streamlit · Google Gemini API · Pydantic
(encoding detection uses Python's standard library: base64, re, urllib.parse, binascii — no new dependencies)

*Note: internal request-layer tracking shows most inputs in adversarial benchmark testing require the full LLM consensus layer rather than resolving via regex alone — expected, since the benchmark set is deliberately weighted toward ambiguous/boundary cases rather than typical traffic. See NOTES.md for the measured breakdown.*

## Testing & benchmark results

Tested against 28 inputs, including deliberately adversarial borderline cases designed to probe the true/false decision boundary (not just obvious attack/safe pairs).

**Results:**
- **89.3% (25/28)** — single-provider mode (Gemini only, with refined few-shot system instructions), plain-text test set
- **73.5% (25/34)** — consensus mode (Gemini + Groq, fail-closed on disagreement), expanded test set including encoded (Base64) variants of known boundary cases

Consensus mode trades a small amount of point-in-time accuracy for explicit uncertainty signaling: rather than silently picking one model's answer on a genuinely ambiguous input, disagreement between providers is itself treated as a signal and the input is flagged for review. Full reasoning and a per-provider breakdown are documented in `NOTES.md`, alongside a real-world comparison showing that even production AI assistants (tested informally against Grok, ChatGPT, and Claude) don't agree on how to handle some of the same borderline instruction-extraction phrasing — supporting evidence that these are genuinely hard cases, not classifier defects. One case has shown a rare false negative during testing, consistent with its documented instability — see NOTES.md for full details.

(see `benchmark.py` for the full test set, `NOTES.md` for detailed findings)

Key findings from adversarial testing:

* The LLM layer reliably distinguishes grammatical mood — genuine questions about compliance ("will you do as I say?") are classified safe, while directive assertions ("you need to do as I say") are flagged, regardless of surface politeness
* The regex layer is fully deterministic; the LLM layer can be inconsistent on ambiguous, borderline-phrased inputs near the decision boundary — documented explicitly rather than hidden
* The LLM layer catches obfuscated attacks (symbol-injected known phrases) that the regex layer alone would miss, validating the two-layer design
* Consensus mode surfaces disagreement between independent providers as an explicit signal rather than a hidden coin-flip
### API access

The `/v1/scan-prompt` and `/v1/stats` endpoints require an API key, passed via the `x-api-key` header, and are rate-limited (10 requests/minute for scanning, 30/minute for stats) to prevent abuse of the underlying LLM API calls.

For demo/testing purposes, use: `demo-key-guardrail-scanner-2026`

Example:
```bash
curl -X POST "https://your-deployed-api/v1/scan-prompt?user_input=hello" -H "x-api-key: demo-key-guardrail-scanner-2026"
```
## Known limitations

* Indirect prompt injection (malicious instructions embedded in retrieved content like documents or product reviews, rather than direct user input) is not yet detected — a documented next step.
* Encoding detection currently covers Base64, hex, and URL-encoding. It does not yet cover more exotic obfuscation (e.g. Unicode homoglyphs, zero-width character insertion, ROT13) — a natural extension of the same pre-processing step.
* LLM-layer classification shows measured inconsistency on ~15% of borderline inputs, particularly around directive-assertion phrasing and casual-toned system-prompt-extraction attempts.
* API endpoints use a single shared demo key rather than per-user authentication — appropriate for a public portfolio demo, but would need real user-scoped API keys (and likely OAuth or similar) for multi-tenant production use

## Running locally

```bash
git clone https://github.com/Bharat810/ai-guardrail-scanner.git
cd ai-guardrail-scanner
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

Create a `.env` file with your own Gemini API key:
GEMINI_API_KEY=your_key_here
Run the dashboard:
```bash
streamlit run dashboard.py
```

Run the benchmark:
```bash
python benchmark.py
```

## Project background

Built as a hands-on project combining a cybersecurity background (CEH-certified) with applied AI engineering — using real, hands-on exploitation of LLM vulnerabilities (via PortSwigger Web LLM Attacks labs) to inform detection design, rather than relying on generic or assumed attack patterns.
