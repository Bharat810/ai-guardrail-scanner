import os
import sys
import io
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, UploadFile, File, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from PIL import Image
 
# 1. Add project root directory to sys.path first so test_api can be found
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
 
# 2. Import database functions & pipeline components
from app.database import init_db, log_scan
from test_api import full_check, check_prompt, request_stats
from schemas import ThreatVerdict, ScanRequest
from app.slm_engine import load_tier2_model
 
# Suppress noisy logs
os.environ["STREAMLIT_LOG_LEVEL"] = "error"
 
# Initialize logger
logger = logging.getLogger("uvicorn")
 
# Check if Cloud-Only mode is explicitly enabled
CLOUD_ONLY_MODE = os.getenv("CLOUD_ONLY_MODE", "false").lower() == "true"
 
 
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    print("🚀 Initializing Guardrail Gateway...")
 
    # Initialize SQLite Audit DB
    try:
        init_db()
        print("💾 SQLite audit database initialized successfully.")
    except Exception as db_err:
        logger.error(f"⚠️ Database initialization failed: {db_err}")
 
    if CLOUD_ONLY_MODE:
        logger.info("⚡ Running in CLOUD-ONLY Mode: Bypassing local LoRA SLM pre-loading.")
        print("⚡ Cloud-Only mode active. Tier 2 local SLM bypassed.")
    else:
        print("⏳ Pre-loading Tier 2 Local LoRA SLM model...")
        try:
            load_tier2_model()
            print("✅ Tier 2 SLM loaded successfully. Gateway ready.")
        except Exception as e:
            logger.warning(f"⚠️ Could not load Tier 2 SLM model: {e}. Falling back to Cloud-Only execution.")
            print("⚠️ SLM load failed. Gateway proceeding without Tier 2 local model.")
 
    yield  # Application handles requests here
 
    # Shutdown logic
    print("🛑 Shutting down Guardrail Gateway...")
 
 
# 3. Instantiate app object before defining any @app routes
app = FastAPI(
    title="3-Tier LLM Security Guardrail Gateway",
    description="Multi-tier detection system using Tier 1 (Regex/Decoding), Tier 2 (Local LoRA SLM), and Tier 3 (Cloud LLM Consensus).",
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
    try:
        verdict = await run_in_threadpool(full_check, request.user_input, content_source=request.content_source)
 
        # Audit log to SQLite
        try:
            log_scan(
                prompt=request.user_input,
                content_source=request.content_source,
                is_threat=verdict.is_threat,
                reason=verdict.reason,
                owasp=verdict.owasp
            )
        except Exception as log_err:
            logger.error(f"⚠️ Failed to write audit log: {log_err}")
 
        return verdict
    except Exception as e:
        logger.error(f"❌ Guardrail processing exception on input '{request.user_input[:30]}...': {e}")
 
        return ThreatVerdict(
            is_threat=True,
            reason=f"System Security Fallback: Scanner evaluation encountered an unhandled error ({str(e)}). Payload blocked for safety.",
            owasp="LLM10: Unchecked System Failures",
            provider_breakdown={"Global_FailSecure_Fallback": True}
        )
 
 
@app.post("/v1/scan-image")
async def scan_image(file: UploadFile = File(...)):
    """Extracts text/payload from uploaded QR code images and runs it through the guardrail scanner."""
    try:
        try:
            from pyzbar.pyzbar import decode
        except ImportError:
            raise HTTPException(
                status_code=503,
                detail="QR code scanning is unavailable in this environment (missing zbar system library)."
            )
 
        contents = await file.read()
        image = Image.open(io.BytesIO(contents))
 
        decoded_objects = decode(image)
        if not decoded_objects:
            raise HTTPException(status_code=400, detail="No readable QR code payload found in image.")
 
        extracted_text = decoded_objects[0].data.decode("utf-8")
 
        # Route extracted payload to scanner engine
        verdict = await run_in_threadpool(full_check, prompt=extracted_text, content_source="qr_image")
 
        # Audit log to SQLite
        try:
            log_scan(
                prompt=extracted_text,
                content_source="qr_image",
                is_threat=verdict.is_threat,
                reason=verdict.reason,
                owasp=verdict.owasp
            )
        except Exception as log_err:
            logger.error(f"⚠️ Failed to write QR audit log: {log_err}")
 
        response_dict = verdict.model_dump() if hasattr(verdict, "model_dump") else verdict.dict()
        response_dict["extracted_text"] = extracted_text
        return response_dict
 
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Image processing error: {e}")
        raise HTTPException(status_code=500, detail=f"Image processing failed: {str(e)}")
 
 
@app.post("/v1/debug-tier3", response_model=ThreatVerdict)
async def debug_tier3(request: ScanRequest):
    """Directly triggers Tier 3 Gemini & Groq Consensus evaluation."""
    return await run_in_threadpool(check_prompt, request.user_input)
 
 
@app.get("/v1/stats")
async def get_stats():
    """Returns real-time processing statistics across all detection tiers."""
    total_scans = sum(request_stats.values())
 
    regex_scans = request_stats.get("tier1_regex", 0)
    decode_scans = request_stats.get("tier1_decoding", 0)
    slm_scans = request_stats.get("tier2_slm_local", 0)
    llm_scans = request_stats.get("tier3_llm_consensus", 0)
 
    local_filtered = regex_scans + decode_scans + slm_scans
 
    return {
        "total_requests_processed": total_scans,
        "tier_breakdown": {
            "tier1_regex": regex_scans,
            "tier1_decoding": decode_scans,
            "tier2_slm_local": slm_scans,
            "tier3_llm_consensus": llm_scans
        },
        "efficiency_metrics": {
            "local_filtered_percentage": (
                f"{(local_filtered / total_scans * 100):.2f}%" if total_scans > 0 else "0.00%"
            ),
            "cloud_escalation_percentage": (
                f"{(llm_scans / total_scans * 100):.2f}%" if total_scans > 0 else "0.00%"
            )
        }
    }
 
 
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)