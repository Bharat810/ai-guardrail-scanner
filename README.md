# AI Guardrail Scanner

A three-tier security service that detects prompt injection, jailbreak attempts, and LLM-agency exploitation before they reach a language model — built and validated using real attack techniques from PortSwigger's Web LLM Attacks labs.

**Live demo:** [ai-guardrail-scanner.streamlit.app](https://ai-guardrail-scanner.streamlit.app)

## What it does

This tool inspects text intended for an LLM-powered application and classifies it as safe or malicious, with a stated reason. It's designed to sit in front of a chatbot or LLM-integrated app as a security checkpoint.

## Architecture

Three-layer cascade, in order — cheap and deterministic first, expensive and flexible last:

1. **Tier 1 — Regex & encoding detection.** Instant, zero API cost, fully deterministic. Checks input against a categorized library of known attack patterns. Also detects Base64 and URL-encoded input, decodes it, and recursively re-runs the same pipeline on the decoded text (capped at depth 3, to catch nested/layered encoding without infinite recursion).
2. **Tier 2 — Local fine-tuned SLM.** A LoRA-adapted `microsoft/deberta-v3-small` classifier, fine-tuned on injection/jailbreak examples and run entirely locally (no API cost, no network dependency). Catches subtler attacks that don't match a known regex phrase.
3. **Tier 3 — Multi-provider LLM consensus.** When Tier 1 and Tier 2 don't resolve the input confidently, it's sent to two independent providers — Google Gemini (`gemini-3.6-flash`) and Groq (`openai/gpt-oss-20b`) — in parallel. If both agree, that verdict is returned. If they disagree, the input is flagged as a threat regardless (fail-closed): provider disagreement is treated as a signal of genuine ambiguity, not something to silently resolve.

This ordering matters: fast, deterministic checks run first; the more expensive/flexible checks only run when needed — the same design principle real security tools use (fail fast on known bad, escalate to deeper analysis for the unknown).

## Detected attack categories

Built from hands-on exploitation of real vulnerable applications (PortSwigger Web LLM Attacks labs), not synthetic examples:

- **Instruction override** — "ignore all previous instructions" style attacks
- **Jailbreak persona** — DAN and similar role-play-based restriction bypasses
- **SQL/tool injection** — exploiting LLM API/tool access to run destructive database commands
- **OS command injection** — shell metacharacter injection via LLM-invoked APIs (e.g. `$(whoami)`)
- **System prompt extraction** — attempts to reveal hidden system instructions
- **Authority impersonation** — falsely claiming admin/elevated permissions to justify bypassing rules

### OWASP LLM Top 10 alignment

| Category | OWASP mapping |
|---|---|
| Instruction override | LLM01: Prompt Injection |
| Jailbreak persona | LLM01: Prompt Injection |
| Authority impersonation | LLM01: Prompt Injection |
| SQL/tool injection | LLM06: Excessive Agency |
| OS command injection | LLM06: Excessive Agency |
| System prompt extraction | LLM07: System Prompt Leakage |

## Tech stack

Python · FastAPI · Streamlit · Google Gemini API · Groq API · PyTorch · Transformers · PEFT (LoRA) · Pydantic

## Deployment

- **Frontend:** Streamlit Cloud (live demo link above)
- **Backend:** Render, running in `CLOUD_ONLY_MODE=true` — Tier 1 and Tier 3 only. Render's free tier can't accommodate the PyTorch/Transformers/PEFT stack needed for Tier 2, so the local SLM is skipped there and the pipeline falls back to Tier 1 → Tier 3 directly.
- **Tier 2 (local SLM):** currently only active when running the project locally, where the full dependency set can be installed. See "Running locally" below.

## Testing & benchmark results

**Current status: v3 of the Tier 2 LoRA model, iterating toward higher accuracy (v4 in progress).**

Most recent run of the 10-case adversarial benchmark suite (`benchmark.py`, hitting the live `/v1/scan` endpoint):

- **9/10 passed — 90.0% accuracy**
- Tier handling breakdown: 1 resolved by Tier 1 regex, 7 resolved by Tier 2 local SLM, 2 escalated to Tier 3 consensus
- The one failure: a hypothetical-framing jailbreak attempt ("if a developer wanted to disable security constraints...") was scored confidently *safe* by Tier 2 and, per the current pipeline design, a confident-safe Tier 2 verdict skips Tier 3 entirely. This is a known, reproducible gap (see Known limitations) rather than one-off noise — the same prompt was also misjudged by the pre-retrained (v2) model.

This benchmark set is deliberately adversarial and boundary-probing — it is not representative of expected real-world traffic, where most inputs would likely resolve at Tier 1 or Tier 2 alone.

(See `NOTES.md` for the full development history, including the two-layer-era benchmark results from before the Tier 2/Tier 3 migration.)

## API endpoints

- `GET /health` — health check
- `POST /v1/scan` — main scanning endpoint, takes `{"prompt": "...", "content_source": "user_input" | "retrieved_content"}`
- `POST /v1/scan-image` — upload a QR code image; extracts and scans its visible text content
- `POST /v1/debug-tier3` — bypasses Tier 1/2, directly triggers Tier 3 Gemini + Groq consensus
- `GET /v1/stats` — real-time per-tier request counts and efficiency metrics

No API key or rate limiting is currently implemented on these endpoints.

## Known limitations

- **Tier 2 confident-safe verdicts bypass Tier 3 entirely.** The pipeline treats a low-confidence (safe) Tier 2 score as final rather than spot-checking it against Tier 3. This is a deliberate cost/latency tradeoff, but it means a confidently-wrong Tier 2 verdict currently has no safety net. Worth revisiting as Tier 2 accuracy improves.
- **Indirect prompt injection detection** relies on the calling system correctly labeling `content_source` as `"retrieved_content"` — the scanner cannot independently verify content provenance.
- **Encoding detection** currently covers Base64 and URL-encoding only. It does not cover hex, Unicode homoglyphs, zero-width character insertion, or ROT13.
- **QR code scanning** reads only standard, visible QR content — it does not detect steganographically hidden payloads.
- **No persistent audit logging in production.** The SQLite audit log (`scans.db`) works locally, but Render's filesystem is ephemeral — logs do not survive a redeploy or restart there.
- **No API key auth or rate limiting** on any endpoint currently.
- This project does not fetch web content or browse pages itself — it's a detection checkpoint that assumes an external system passes it content to evaluate.
- It returns a binary threat/safe verdict on a whole piece of text, not a way to surgically strip just the malicious portion while preserving legitimate content around it.

### Beyond detection: mitigating excessive agency risk

This scanner detects text resembling SQL/tool injection or OS command injection (OWASP LLM06: Excessive Agency), but detection alone doesn't eliminate risk if flagged content still reaches an agent with real tool access. Downstream systems integrating this scanner should also apply defense-in-depth: least-privilege agent credentials, separating scanning identities from admin identities, and treating a flagged verdict as a signal to halt the action pipeline, not just log a warning. See [PortSwigger's guidance on AI-powered scanner vulnerabilities](https://portswigger.net/web-security/llm-attacks/ai-powered-scanner-vulnerabilities).

### QR code scanning

⚠️ Avoid scanning QR codes that encode live credentials or authentication tokens with this or any similar tool — decoded content is sent to external LLM providers (Gemini/Groq) as part of classification, which is appropriate for URLs and payment references but not for live secrets.

## Running locally

```bash
git clone https://github.com/Bharat810/ai-guardrail-scanner.git
cd ai-guardrail-scanner
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt -r requirements-local.txt
```

`requirements-local.txt` adds `torch`, `transformers`, and `peft` on top of the base dependencies — needed for Tier 2 to actually run locally. Don't install these on Render or similar constrained hosts; use `CLOUD_ONLY_MODE=true` there instead.

Create a `.env` file:
```
GEMINI_API_KEY=your_key_here
GROQ_API_KEY=your_key_here
```

Run the backend:
```bash
uvicorn app.main:app --reload
```

Run the dashboard:
```bash
streamlit run dashboard.py
```

Run the benchmark:
```bash
python benchmark.py
```

## Project background

Built as a hands-on project combining a cybersecurity background (CEH-certified) with applied AI engineering — using real, hands-on exploitation of LLM vulnerabilities (via PortSwigger Web LLM Attacks labs) to inform detection design, rather than relying on generic or assumed attack patterns. The Tier 2 LoRA classifier is fine-tuned and iterated on via Google Colab, with each version's regressions and improvements tracked in `NOTES.md`.
