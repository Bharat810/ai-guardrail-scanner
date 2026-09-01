import io
import time
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, File, UploadFile
from pydantic import BaseModel, Field
from PIL import Image

# Import detection logic from test_api
from test_api import full_check, full_check_image, request_stats

app = FastAPI(
    title="AI Security Guardrail Gateway",
    description="3-Tier Security Gateway protecting LLMs against Direct & Indirect Prompt Injection attacks.",
    version="1.0.0"
)

class ScanRequest(BaseModel):
    user_input: str = Field(..., description="The prompt or retrieved content string to evaluate.")
    content_source: str = Field(default="user_input", description="Source of content: 'user_input' or 'retrieved_content'")

class ScanResponse(BaseModel):
    is_threat: bool
    reason: str
    owasp: Optional[str] = None
    provider_breakdown: Optional[Dict[str, bool]] = None
    extracted_text: Optional[str] = None

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "AI Security Guardrail Gateway",
        "version": "1.0.0",
        "docs": "/docs"
    }

@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": time.time()}

@app.get("/v1/stats")
def get_stats():
    return {
        "total_requests": sum(request_stats.values()),
        "tier_breakdown": {
            "tier1_regex": request_stats.get("tier1_regex", 0),
            "tier1_decoding": request_stats.get("tier1_decoding", 0),
            "tier2_slm_local": request_stats.get("tier2_slm_local", 0),
            "tier3_llm_consensus": request_stats.get("tier3_llm_consensus", 0)
        }
    }

@app.post("/v1/scan", response_model=ScanResponse)
def scan_prompt(request: ScanRequest):
    if not request.user_input.strip():
        raise HTTPException(status_code=400, detail="Text input cannot be empty.")
    
    result = full_check(
        user_input=request.user_input,
        content_source=request.content_source
    )
    
    return ScanResponse(
        is_threat=result.is_threat,
        reason=result.reason,
        owasp=result.owasp,
        provider_breakdown=result.provider_breakdown
    )

@app.post("/v1/scan-image", response_model=ScanResponse)
async def scan_image(file: UploadFile = File(...)):
    """
    Scans an uploaded image/QR code for embedded multimodal prompt injections.
    """
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Uploaded file must be an image.")
    
    try:
        contents = await file.read()
        image = Image.open(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid image format: {str(e)}")

    # Run existing image detection pipeline
    result = full_check_image(image)
    
    extracted_txt = getattr(result, "extracted_text", None) or getattr(result, "decoded_text", None)
    
    return ScanResponse(
        is_threat=result.is_threat,
        reason=result.reason,
        owasp=result.owasp,
        provider_breakdown=getattr(result, "provider_breakdown", None),
        extracted_text=extracted_txt
    )