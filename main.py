from fastapi import FastAPI, Header, HTTPException, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os
from dotenv import load_dotenv

from test_api import full_check, request_stats, ProviderUnavailableError, ScanRequest

load_dotenv()

DEMO_API_KEY = os.getenv("DEMO_API_KEY")

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


def verify_api_key(x_api_key: str):
    if x_api_key != DEMO_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key. See README for the demo key.")


@app.post("/v1/scan-prompt")
@limiter.limit("10/minute")
def scan_prompt(request: Request, payload: ScanRequest, x_api_key: str = Header(...)):
    verify_api_key(x_api_key)
    try:
        return full_check(payload.user_input, content_source=payload.content_source)
    except ProviderUnavailableError as e:
        print(f"Provider outage: {e}")
        raise HTTPException(status_code=503, detail="Detection service temporarily unavailable. Please try again shortly.")


@app.get("/v1/stats")
@limiter.limit("30/minute")
def get_stats(request: Request, x_api_key: str = Header(...)):
    verify_api_key(x_api_key)
    total = sum(request_stats.values())
    return {
        "counts": request_stats,
        "total": total,
        "regex_only_pct": round(request_stats["regex_only"] / total * 100, 1) if total else 0,
        "llm_consensus_pct": round(request_stats["llm_consensus"] / total * 100, 1) if total else 0,
    }