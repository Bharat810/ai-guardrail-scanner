from typing import Optional, Dict
from pydantic import BaseModel, Field

class ProviderUnavailableError(Exception):
    """Raised when an external LLM provider API is unreachable or failing."""
    pass

class ScanRequest(BaseModel):
    user_input: str = Field(..., alias="prompt", description="The prompt text to analyze for security threats")
    content_source: Optional[str] = Field("user_input", description="Source of payload")

    class Config:
        populate_by_name = True

class ThreatVerdict(BaseModel):
    is_threat: bool
    reason: str
    owasp: Optional[str] = None
    provider_breakdown: Dict[str, bool] = Field(default_factory=dict)