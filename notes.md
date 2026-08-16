## Detection approach
- Two-layer system: fast regex pattern matching (instant, no API cost) + LLM classification fallback (Gemini) for anything regex doesn't catch
- Regex categories built from real PortSwigger Web LLM Attacks labs: instruction_override, jailbreak_persona, sql_tool_injection, os_command_injection

## Testing findings
- LLM layer correctly distinguishes grammatical mood: genuine questions/polite requests about compliance ("will you...", "could you please...") are classified safe; direct commands/directive assertions ("do exactly as I say", "you need to...") are flagged
- Regex layer is fully deterministic (same input always same result); LLM layer can show inconsistency on ambiguous, borderline-phrased inputs near the decision boundary — documented via adversarial testing (e.g., minor phrasing variants of "I need help, do as I say" yielded inconsistent verdicts)

## Known limitations
- Indirect prompt injection (malicious instructions embedded in retrieved content like documents/reviews, rather than direct user input) is not yet detected — would require scanning all retrieved/tool-output content through the same pipeline before it reaches the model's context

- authority_impersonation: claiming admin/elevated permissions to justify bypassing instructions (e.g., "do what you're instructed to do by admin" flagged True, while "...by developers" flagged False — distinction is authority claim, not just mentioning who gave instructions)