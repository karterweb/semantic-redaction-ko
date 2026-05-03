from __future__ import annotations

import json
from pathlib import Path

from semantic_redaction.cases import get_case
from semantic_redaction.crossref import CrossReferenceDetector
from semantic_redaction.external import MockExternalLLM, SafeRehydrator
from semantic_redaction.models import CrossReferenceWarning, PrivacyFinding, PipelineResult, UseCase
from semantic_redaction.policy import PrivacyPolicyGate
from semantic_redaction.redactor import SemanticRedactor


LAST_RUN_PATH = Path(".semantic-redaction/last-run.json")


class PipelineRunner:
    def __init__(self, model: str = "qwen3:30b-a3b", runtime: str = "auto") -> None:
        self.redactor = SemanticRedactor(model=model, runtime=runtime)
        self.policy = PrivacyPolicyGate()
        self.external_llm = MockExternalLLM()
        self.rehydrator = SafeRehydrator()
        self.crossref = CrossReferenceDetector()

    def run(self, usecase: UseCase) -> PipelineResult:
        case = get_case(usecase)
        draft, runtime = self.redactor.draft(case)

        # --- Phase 1: Qwen draft 검사 ---
        initial_findings = self.policy.inspect(case, draft)

        repaired = False
        blocked = False
        safe_draft = draft
        findings_for_audit = initial_findings

        if initial_findings:
            repaired = True
            safe_draft = self.policy.sanitize(case, draft)
            remaining_findings = self.policy.inspect(case, safe_draft)
            findings_for_audit = initial_findings
            blocked = bool(remaining_findings)

        # --- Phase 2: 의미 보존 enrichment ---
        techniques_applied: list[str] = []
        utility_preservation: dict[str, object] = {}
        if not blocked:
            safe_draft, techniques_applied, utility_preservation = self.policy.enrich(case, safe_draft)
            post_enrichment_findings = self.policy.inspect(case, safe_draft)
            if post_enrichment_findings:
                blocked = True
                findings_for_audit = [*findings_for_audit, *post_enrichment_findings]

        # --- Phase 3: External LLM + Outbound 필터 + 교차 참조 탐지 ---
        decision_state = None
        external_payload = None
        external_response = None
        final_response = None
        outbound_findings: list[PrivacyFinding] = []
        cross_ref_warnings: list[CrossReferenceWarning] = []

        if not blocked:
            decision_state = self.policy.to_decision_state(
                safe_draft,
                techniques_applied,
                utility_preservation,
                [],  # residual_risks는 audit에서 설정
            )
            external_payload = self.policy.to_external_payload(decision_state)
            external_response = self.external_llm.complete(case.usecase, external_payload)

            # Outbound 필터: 외부 LLM 응답에 민감정보 포함 여부 검사
            outbound_findings = self.policy.inspect_string(case, external_response)
            if outbound_findings:
                external_response = self.policy.sanitize_string(case, external_response)

            final_response = self.rehydrator.rehydrate(external_response, case.rehydration_map)

            # 교차 참조 탐지: 누적 의미 차원 추적
            exposed_dims = list(utility_preservation.get("preserved", []))
            cross_ref_warnings = self.crossref.check_and_register(case.usecase, exposed_dims)

        # --- Phase 4: 감사 로그 생성 (모든 findings 포함) ---
        audit = self.policy.build_audit(
            case,
            findings_for_audit,
            repaired=repaired,
            blocked=blocked,
            techniques_applied=techniques_applied,
            utility_preservation=utility_preservation,
            outbound_findings=outbound_findings,
            cross_reference_warnings=cross_ref_warnings,
            external_called=not blocked,
        )
        # residual_risks를 decision_state에 반영
        if decision_state is not None:
            decision_state.residual_risks = audit.residual_risks

        result = PipelineResult(
            case=case,
            qwen_draft=draft,
            policy_audit=audit,
            decision_state=decision_state,
            external_payload=external_payload,
            external_response=external_response,
            final_response=final_response,
            repaired=repaired,
            runtime=runtime,
        )
        self.save_last_run(result)
        return result

    def save_last_run(self, result: PipelineResult) -> None:
        LAST_RUN_PATH.parent.mkdir(parents=True, exist_ok=True)
        LAST_RUN_PATH.write_text(
            json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
