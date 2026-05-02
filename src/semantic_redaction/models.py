from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


UseCase = Literal["card", "insurance", "debt"]
AuditStatus = Literal["passed", "repaired", "blocked_privacy_risk"]


class PrivateCase(BaseModel):
    id: str
    usecase: UseCase
    title: str
    utterance: str
    private_records: dict[str, Any]
    sensitive_terms: list[str]
    redaction_map: dict[str, str]
    rehydration_map: dict[str, str]


class ResolutionCandidate(BaseModel):
    token: str
    category: str
    confidence: float = Field(ge=0.0, le=1.0)
    reasons: list[str]
    conflicts: list[str] = Field(default_factory=list)
    facts: dict[str, Any] = Field(default_factory=dict)


class QwenDraft(BaseModel):
    intent: str
    summary: str
    candidates: list[ResolutionCandidate]
    resolved_facts: dict[str, Any]
    uncertainty: str
    confidence: float = Field(ge=0.0, le=1.0)
    required_action: str


class DecisionState(BaseModel):
    intent: str
    candidates: list[ResolutionCandidate]
    resolved_facts: dict[str, Any]
    uncertainty: str
    confidence: float
    required_action: str
    techniques_applied: list[str]
    utility_preservation: dict[str, Any]
    residual_risks: list[str]


class ExternalPayload(BaseModel):
    intent: str
    facts: dict[str, Any]
    candidates: list[dict[str, Any]]
    uncertainty: str
    required_action: str
    techniques_applied: list[str]
    utility_preservation: dict[str, Any]
    instruction: str


class PrivacyFinding(BaseModel):
    path: str
    value: str
    reason: str
    severity: Literal["low", "medium", "high"]


class PrivacyAudit(BaseModel):
    case_id: str
    usecase: UseCase
    status: AuditStatus
    risk_level: Literal["low", "medium", "high"]
    findings: list[PrivacyFinding]
    techniques_applied: list[str]
    utility_preservation: dict[str, Any]
    guideline_controls: list[str]
    residual_risks: list[str]


class PipelineResult(BaseModel):
    case: PrivateCase
    qwen_draft: QwenDraft
    policy_audit: PrivacyAudit
    decision_state: DecisionState | None
    external_payload: ExternalPayload | None
    external_response: str | None
    final_response: str | None
    repaired: bool
    runtime: str
