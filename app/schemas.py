"""Pydantic v2 response schemas for PromptVeil local host."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class HealthResponse(BaseModel):
    """Health check payload confirming client-side zero-egress mode."""

    model_config = ConfigDict(frozen=True)

    status: Literal["ok"] = "ok"
    mode: Literal["client-side-zero-egress"] = "client-side-zero-egress"
    version: str
