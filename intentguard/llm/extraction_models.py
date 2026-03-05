from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class ExtractedIntent(BaseModel):
    """Schema-bound LLM output.

    IMPORTANT:
    - No IPs/CIDRs are allowed here (LLM must only reference context names).
    - No firewall syntax.
    - Direction is not decided here.
    """

    action: Optional[str] = Field(
        default=None, description="One of: allow, deny, reject; null if unclear."
    )
    sources: List[str] = Field(default_factory=list, description="Named zones/objects.")
    destinations: List[str] = Field(default_factory=list, description="Named zones/objects.")
    services: List[str] = Field(
        default_factory=list, description="Named services from context (e.g., https)."
    )
    logging: Optional[bool] = Field(default=None, description="true/false/null if unspecified.")
    raw_policy: str = Field(description="Original natural language string.")
    ambiguities: List[str] = Field(default_factory=list)

