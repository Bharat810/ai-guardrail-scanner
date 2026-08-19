from fastapi import FastAPI
from test_api import full_check, request_stats

app = FastAPI()

@app.post("/v1/scan-prompt")
def scan_prompt(user_input: str):
    return full_check(user_input)

@app.get("/v1/stats")
def get_stats():
    total = sum(request_stats.values())
    return {
        "counts": request_stats,
        "total": total,
        "regex_only_pct": round(request_stats["regex_only"] / total * 100, 1) if total else 0,
        "llm_consensus_pct": round(request_stats["llm_consensus"] / total * 100, 1) if total else 0,
    }