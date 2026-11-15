"""Pydantic-Schemas der API (Request/Response)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["safe", "suspicious", "dangerous"]


class UrlRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)


class UrlsRequest(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=300)


class UrlResult(BaseModel):
    url: str
    score: float = Field(..., ge=0.0, le=1.0, description="Phishing-Wahrscheinlichkeit")
    verdict: Verdict
    reasons: list[str]


class UrlsResponse(BaseModel):
    results: list[UrlResult]


class TextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50_000)


class TextResponse(BaseModel):
    score: float = Field(..., ge=0.0, le=1.0)
    verdict: Verdict
    text_score: float
    text_reasons: list[str]
    links: list[UrlResult]


class HealthResponse(BaseModel):
    status: str
    version: str
    url_model: dict
    text_model: dict
