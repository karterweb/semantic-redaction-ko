from __future__ import annotations

import json
from pathlib import Path

from semantic_redaction.cases import get_case
from semantic_redaction.external import MockExternalLLM, SafeRehydrator
from semantic_redaction.models import PipelineResult, UseCase
from semantic_redaction.policy import PrivacyPolicyGate
from semantic_redaction.redactor import SemanticRedactor


LAST_RUN_PATH = Path(".semantic-redaction/last-run.json")


class PipelineRunner:
    def __init__(self, model: str = "qwen3:30b-a3b", runtime: str = "auto") -> None:
        self.redactor = SemanticRedactor(model=model, runtime=runtime)
        self.policy = PrivacyPolicyGate()
        self.external_llm = MockExternalLLM()
        self.rehydrator = SafeRehydrator()

    def run(self, usecase: UseCase) -> PipelineResult:
        case = get_case(usecase)
        draft, runtime = self.redactor.draft(case)
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

        techniques_applied: list[str] = []
        utility_preservation: dict[str, object] = {}
        if not blocked:
            safe_draft, techniques_applied, utility_preservation = self.policy.enrich(case, safe_draft)
            post_enrichment_findings = self.policy.inspect(case, safe_draft)
            if post_enrichment_findings:
                blocked = True
                findings_for_audit = [*findings_for_audit, *post_enrichment_findings]

        audit = self.policy.build_audit(
            case,
            findings_for_audit,
            repaired=repaired,
            blocked=blocked,
            techniques_applied=techniques_applied,
            utility_preservation=utility_preservation,
        )

        decision_state = None
        external_payload = None
        external_response = None
        final_response = None
        if not blocked:
            decision_state = self.policy.to_decision_state(
                safe_draft,
                techniques_applied,
                utility_preservation,
                audit.residual_risks,
            )
            external_payload = self.policy.to_external_payload(decision_state)
            external_response = self.external_llm.complete(case.usecase, external_payload)
            final_response = self.rehydrator.rehydrate(external_response, case.rehydration_map)

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
