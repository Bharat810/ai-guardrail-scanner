import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from test_api import full_check, full_check_image, request_stats, ThreatVerdict, ScanRequest
from app.slm_engine import load_tier2_model

# Initialize logger
logger = logging.getLogger("uvicorn")

# Check if Cloud-Only mode is explicitly enabled
CLOUD_ONLY_MODE = os.getenv("CLOUD_ONLY_MODE", "false").lower() == "true"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Pre-load Tier 2 DeBERTa model and tokenizer into memory if not in Cloud-Only mode
    print("🚀 Initializing Guardrail Gateway...")
    
    if CLOUD_ONLY_MODE:
        logger.info("⚡ Running in CLOUD-ONLY Mode: Bypassing local DeBERTa SLM pre-loading.")
        print("⚡ Cloud-Only mode active. Tier 2 DeBERTa SLM bypassed.")
    else:
        print("⏳ Pre-loading Tier 2 Local SLM model...")
        try:
            load_tier2_model()
            print("✅ Tier 2 SLM loaded successfully. Gateway ready.")
        except Exception as e:
            logger.warning(f"⚠️ Could not load Tier 2 SLM model: {e}. Falling back to Cloud-Only execution.")
            print("⚠️ SLM load failed. Gateway proceeding without Tier 2 local model.")

    yield  # Server runs and handles requests here
    
    # Shutdown logic
    print("🛑 Shutting down Guardrail Gateway...")


app = FastAPI(
    title="3-Tier LLM Security Guardrail Gateway",
    description="Multi-tier detection system using Tier 1 (Regex/Decoding), Tier 2 (Local DeBERTa SLM), and Tier 3 (Cloud LLM Consensus).",
    version="2.0.0",
    lifespan=lifespan
)


@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    """Health check endpoint for container orchestration & load balancers."""
    return {
        "status": "healthy",
        "service": "llm-guardrail-gateway",
        "cloud_only_mode": CLOUD_ONLY_MODE
    }


@app.post("/v1/scan", response_model=ThreatVerdict)
async def scan_prompt(request: ScanRequest):
    """
    Scans a prompt or retrieved content for injection / jailbreak attempts across:
    - Tier 1: Pattern matching & recursive decoding
    - Tier 2: Local SLM inference (short-circuits high-confidence safe/threats)
    - Tier 3: Cloud LLM consensus for borderline cases (Gemini + Groq)
    """
    try:
        verdict = full_check(request.user_input, content_source=request.content_source)
        return verdict
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Guardrail scanning error: {str(e)}"
        )


@app.get("/v1/stats")
async def get_stats():
    """
    Returns real-time processing statistics across all detection tiers.
    """
    total_scans = sum(request_stats.values())
    return {
        "total_requests_processed": total_scans,
        "tier_breakdown": {
            "tier1_regex": request_stats["regex_only"],
            "tier1_decoding": request_stats["encoding_decoded"],
            "tier2_slm_local": request_stats["slm_tier2"],
            "tier3_llm_consensus": request_stats["llm_consensus"]
        },
        "efficiency_metrics": {
            "local_filtered_percentage": (
                f"{((request_stats['regex_only'] + request_stats['encoding_decoded'] + request_stats['slm_tier2']) / total_scans * 100):.2f}%"
                if total_scans > 0 else "0.00%"
            ),
            "cloud_escalation_percentage": (
                f"{(request_stats['llm_consensus'] / total_scans * 100):.2f}%"
                if total_scans > 0 else "0.00%"
            )
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)