from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any

from semantic_redaction.models import (
    CrossReferenceWarning,
    DecisionState,
    ExternalPayload,
    PrivacyAudit,
    PrivacyFinding,
    PrivateCase,
    QwenDraft,
    RiskTierAssessment,
)
from semantic_redaction.strategy import SemanticStrategyEngine


FORBIDDEN_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # 전화번호
    (re.compile(r"\b\d{2,4}-\d{3,4}-\d{4}\b"), "phone_number"),
    # 계좌번호·증권번호 형식 (대시 구분 숫자열)
    (re.compile(r"\b\d{2,6}-\d{2,6}-\d{2,8}\b"), "account_or_policy_like_number"),
    # 은행명 (KB은행, 신한은행 등)
    (re.compile(r"[가-힣A-Z]{2,}은행"), "raw_bank_name"),
    # 정확한 원화 금액 (콤마 구분)
    (re.compile(r"\d{1,3}(,\d{3})+원"), "exact_amount"),
    # 주민등록번호 YYMMDD-[1-4]NNNNNN
    (re.compile(r"\b\d{6}-[1-4]\d{6}\b"), "resident_registration_number"),
    # 카드번호 16자리 (공백 또는 대시 구분)
    (re.compile(r"\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b"), "card_number"),
    # 사업자등록번호 NNN-NN-NNNNN
    (re.compile(r"\b\d{3}-\d{2}-\d{5}\b"), "business_registration_number"),
    # 이메일 주소
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "email_address"),
    # 카드사·증권사·보험사·캐피탈·저축은행명
    (re.compile(r"[가-힣A-Za-z0-9]{2,}(카드|증권|생명|화재|캐피탈|저축은행|보험)"), "raw_financial_institution"),
    # 병원·의원명
    (re.compile(r"[가-힣]{2,}(병원|의원)"), "raw_medical_institution"),
    # 만원·억원·천원 단위 금액
    (re.compile(r"\d+(,\d+)*(만원|억원|천원)"), "exact_amount_korean_unit"),
]


GUIDELINE_CONTROLS = [
    "처리 목적 달성 가능성과 재식별 위험 통제의 균형",
    "추가정보와 매핑테이블은 Private Zone에 분리 보관",
    "외부 LLM 전달 전 적정성 검토 역할의 deterministic policy gate 적용",
    "잔존 위험과 차단 필드 감사로그 생성",
    "교차 참조 탐지를 통한 세션 레벨 재식별 위험 모니터링",
    "외부 LLM 출력물 outbound 필터 적용",
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

    def inspect_string(
        self, case: PrivateCase, text: str, path: str = "$.external_response"
    ) -> list[PrivacyFinding]:
        findings: list[PrivacyFinding] = []
        self._scan_string(text, path, case, findings)
        return findings

    def sanitize(self, case: PrivateCase, draft: QwenDraft) -> QwenDraft:
        data = deepcopy(draft.model_dump())
        sanitized = self._sanitize_value(data, case)
        return QwenDraft.model_validate(sanitized)

    def sanitize_string(self, case: PrivateCase, text: str) -> str:
        result = text
        for raw, replacement in sorted(case.redaction_map.items(), key=lambda item: len(item[0]), reverse=True):
            result = re.sub(re.escape(raw), replacement, result, flags=re.IGNORECASE)
        return result

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
        outbound_findings: list[PrivacyFinding] | None = None,
        cross_reference_warnings: list[CrossReferenceWarning] | None = None,
        external_called: bool = True,
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

        utility_preservation = utility_preservation or {}
        utility_score = float(utility_preservation.get("score", 0.0))

        return PrivacyAudit(
            case_id=case.id,
            usecase=case.usecase,
            status=status,
            risk_level=risk,
            findings=findings,
            techniques_applied=techniques_applied or [],
            utility_preservation=utility_preservation,
            utility_score=utility_score,
            guideline_controls=GUIDELINE_CONTROLS,
            residual_risks=[
                "로컬 LLM 출력은 확률적이므로 schema 및 privacy regression test가 계속 필요함",
                "외부 LLM 출력 토큰은 Safe Rehydration allowlist로만 복원 가능함",
                "교차 참조 공격: 동일 엔티티에 대한 반복 쿼리로 의미 차원이 누적될 경우 재식별 위험 증가",
            ],
            outbound_findings=outbound_findings or [],
            cross_reference_warnings=cross_reference_warnings or [],
            risk_tier_assessment=self._assess_risk_tier(external_called, blocked),
        )

    def _assess_risk_tier(self, external_called: bool, blocked: bool) -> RiskTierAssessment:
        if blocked:
            return RiskTierAssessment(
                tier="high",
                rationale=(
                    "민감정보 포함 draft가 차단됨. "
                    "외부 LLM 전송은 방지되었으나 위험 제어 로직이 작동한 고위험 상황."
                ),
                reviewer_count_required=3,
                guideline_reference=(
                    "개인정보보호위원회 가명정보 처리 가이드라인(2026.03) "
                    "고위험: 처리 목적·안전성 적정성 심의위원회 필수"
                ),
            )
        if external_called:
            return RiskTierAssessment(
                tier="high",
                rationale=(
                    "범용 외부 LLM API 사용으로 제3자 통제권 제한적. "
                    "DPA 없이 외부 API 활용 시 고위험 등급에 해당. "
                    "가명정보 처리 목적 적정성 심의 및 잔존 위험 모니터링 필요."
                ),
                reviewer_count_required=3,
                guideline_reference=(
                    "개인정보보호위원회 가명정보 처리 가이드라인(2026.03) "
                    "고위험: 처리 목적·안전성 심의위원회 필수 / "
                    "금융위원회 금융분야 AI 활용 가이드라인(2026.Q1) 외부 AI 모델 활용 원칙"
                ),
            )
        return RiskTierAssessment(
            tier="low",
            rationale=(
                "외부 LLM 전송 없이 내부 처리만 수행. "
                "동일 관리자 내부 활용으로 저위험 등급 해당."
            ),
            reviewer_count_required=1,
            guideline_reference=(
                "개인정보보호위원회 가명정보 처리 가이드라인(2026.03) "
                "저위험: 내부 활용 최소 절차 적용"
            ),
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
                # dict key 자체도 민감정보 스캔 대상
                if isinstance(key, str):
                    self._scan_string(key, f"{path}[key:{key}]", case, findings)
                self._scan_value(child, f"{path}.{key}", case, findings)
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                self._scan_value(child, f"{path}[{index}]", case, findings)
            return
        if isinstance(value, str):
            self._scan_string(value, path, case, findings)

    def _scan_string(
        self,
        value: str,
        path: str,
        case: PrivateCase,
        findings: list[PrivacyFinding],
    ) -> None:
        value_lower = value.lower()
        for term in case.sensitive_terms:
            if term and term.lower() in value_lower:
                findings.append(
                    PrivacyFinding(path=path, value=term, reason="sensitive_term", severity="high")
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
        return self.sanitize_string(case, value)


def payload_contains_sensitive_data(case: PrivateCase, payload: ExternalPayload) -> bool:
    gate = PrivacyPolicyGate()
    serialized = json.dumps(payload.model_dump(), ensure_ascii=False)
    findings: list[PrivacyFinding] = []
    gate._scan_string(serialized, "$", case, findings)
    return bool(findings)
