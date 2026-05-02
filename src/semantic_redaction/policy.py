from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any

from semantic_redaction.models import (
    DecisionState,
    ExternalPayload,
    PrivacyAudit,
    PrivacyFinding,
    PrivateCase,
    QwenDraft,
)
from semantic_redaction.strategy import SemanticStrategyEngine


FORBIDDEN_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{2,4}-\d{3,4}-\d{4}\b"), "phone_number"),
    (re.compile(r"\b\d{2,6}-\d{2,6}-\d{2,8}\b"), "account_or_policy_like_number"),
    (re.compile(r"[가-힣A-Z]{2,}은행"), "raw_bank_name"),
    (re.compile(r"\d{1,3}(,\d{3})+원"), "exact_amount"),
]


GUIDELINE_CONTROLS = [
    "처리 목적 달성 가능성과 재식별 위험 통제의 균형",
    "추가정보와 매핑테이블은 Private Zone에 분리 보관",
    "외부 LLM 전달 전 적정성 검토 역할의 deterministic policy gate 적용",
    "잔존 위험과 차단 필드 감사로그 생성",
]


class PrivacyPolicyGate:
    def __init__(self) -> None:
        self.strategy_engine = SemanticStrategyEngine()

    def inspect(self, case: PrivateCase, draft: QwenDraft) -> list[PrivacyFinding]:
        data = draft.model_dump()
        findings: list[PrivacyFinding] = []
        self._scan_value(data, "$", case, findings)
        if not draft.uncertainty:
            findings.append(
                PrivacyFinding(
                    path="$.uncertainty",
                    value="",
                    reason="missing_uncertainty",
                    severity="high",
                )
            )
        if draft.confidence <= 0:
            findings.append(
                PrivacyFinding(
                    path="$.confidence",
                    value=str(draft.confidence),
                    reason="missing_confidence",
                    severity="high",
                )
            )
        return findings

    def sanitize(self, case: PrivateCase, draft: QwenDraft) -> QwenDraft:
        data = deepcopy(draft.model_dump())
        sanitized = self._sanitize_value(data, case)
        return QwenDraft.model_validate(sanitized)

    def enrich(self, case: PrivateCase, draft: QwenDraft) -> tuple[QwenDraft, list[str], dict[str, Any]]:
        return self.strategy_engine.enrich(case, draft)

    def to_decision_state(
        self,
        draft: QwenDraft,
        techniques_applied: list[str],
        utility_preservation: dict[str, Any],
        residual_risks: list[str],
    ) -> DecisionState:
        return DecisionState(
            intent=draft.intent,
            candidates=draft.candidates,
            resolved_facts=draft.resolved_facts,
            uncertainty=draft.uncertainty,
            confidence=draft.confidence,
            required_action=draft.required_action,
            techniques_applied=techniques_applied,
            utility_preservation=utility_preservation,
            residual_risks=residual_risks,
        )

    def to_external_payload(self, decision_state: DecisionState) -> ExternalPayload:
        return ExternalPayload(
            intent=decision_state.intent,
            facts=decision_state.resolved_facts,
            candidates=[
                {
                    "token": candidate.token,
                    "category": candidate.category,
                    "confidence": candidate.confidence,
                    "reasons": candidate.reasons,
                    "conflicts": candidate.conflicts,
                    "facts": candidate.facts,
                }
                for candidate in decision_state.candidates
            ],
            uncertainty=decision_state.uncertainty,
            required_action=decision_state.required_action,
            techniques_applied=decision_state.techniques_applied,
            utility_preservation=decision_state.utility_preservation,
            instruction=(
                "Generate a short Korean response using only provided tokens and safe categories. "
                "Do not infer or reveal real names, raw merchants, hospitals, institutions, account numbers, or exact balances."
            ),
        )

    def build_audit(
        self,
        case: PrivateCase,
        findings: list[PrivacyFinding],
        repaired: bool,
        blocked: bool,
        techniques_applied: list[str] | None = None,
        utility_preservation: dict[str, Any] | None = None,
    ) -> PrivacyAudit:
        if blocked:
            status = "blocked_privacy_risk"
            risk = "high"
        elif repaired:
            status = "repaired"
            risk = "medium"
        else:
            status = "passed"
            risk = "low"
        return PrivacyAudit(
            case_id=case.id,
            usecase=case.usecase,
            status=status,
            risk_level=risk,
            findings=findings,
            techniques_applied=techniques_applied or [],
            utility_preservation=utility_preservation or {},
            guideline_controls=GUIDELINE_CONTROLS,
            residual_risks=[
                "로컬 LLM 출력은 확률적이므로 schema 및 privacy regression test가 계속 필요함",
                "외부 LLM 출력 토큰은 Safe Rehydration allowlist로만 복원 가능함",
            ],
        )

    def _scan_value(
        self,
        value: Any,
        path: str,
        case: PrivateCase,
        findings: list[PrivacyFinding],
    ) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                self._scan_value(child, f"{path}.{key}", case, findings)
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                self._scan_value(child, f"{path}[{index}]", case, findings)
            return
        if not isinstance(value, str):
            return

        for term in case.sensitive_terms:
            if term and term in value:
                findings.append(
                    PrivacyFinding(path=path, value=term, reason="case_sensitive_term", severity="high")
                )
        for pattern, reason in FORBIDDEN_PATTERNS:
            for match in pattern.findall(value):
                matched = match if isinstance(match, str) else match[0]
                findings.append(
                    PrivacyFinding(path=path, value=matched, reason=reason, severity="high")
                )

    def _sanitize_value(self, value: Any, case: PrivateCase) -> Any:
        if isinstance(value, dict):
            return {key: self._sanitize_value(child, case) for key, child in value.items()}
        if isinstance(value, list):
            return [self._sanitize_value(child, case) for child in value]
        if not isinstance(value, str):
            return value

        sanitized = value
        for raw, replacement in sorted(case.redaction_map.items(), key=lambda item: len(item[0]), reverse=True):
            sanitized = sanitized.replace(raw, replacement)
        return sanitized


def payload_contains_sensitive_data(case: PrivateCase, payload: ExternalPayload) -> bool:
    gate = PrivacyPolicyGate()
    serialized = json.dumps(payload.model_dump(), ensure_ascii=False)
    findings: list[PrivacyFinding] = []
    gate._scan_value(serialized, "$", case, findings)
    return bool(findings)
