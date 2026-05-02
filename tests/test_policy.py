from semantic_redaction.cases import get_case
from semantic_redaction.pipeline import PipelineRunner
from semantic_redaction.policy import PrivacyPolicyGate, payload_contains_sensitive_data
from semantic_redaction.redactor import SemanticRedactor


def test_policy_detects_sensitive_terms_in_qwen_draft() -> None:
    case = get_case("insurance")
    draft, _ = SemanticRedactor(runtime="mock").draft(case)
    findings = PrivacyPolicyGate().inspect(case, draft)
    assert any(f.value == "서울아산병원" for f in findings)


def test_policy_sanitizes_sensitive_terms() -> None:
    case = get_case("debt")
    draft, _ = SemanticRedactor(runtime="mock").draft(case)
    gate = PrivacyPolicyGate()
    safe = gate.sanitize(case, draft)
    findings = gate.inspect(case, safe)
    assert findings == []


def test_card_pipeline_builds_safe_external_payload() -> None:
    result = PipelineRunner(runtime="mock").run("card")
    assert result.external_payload is not None
    assert not payload_contains_sensitive_data(result.case, result.external_payload)
    assert "temporal_relation_encoding" in result.external_payload.techniques_applied
    assert result.external_payload.facts["temporal_relation"] == "near_time_duplicate_within_2_minutes"
    assert result.final_response is not None
    assert "커피전문점 승인 거래" in result.final_response


def test_all_scenarios_have_uncertainty_and_confidence() -> None:
    for usecase in ("card", "insurance", "debt"):
        result = PipelineRunner(runtime="mock").run(usecase)  # type: ignore[arg-type]
        assert result.decision_state is not None
        assert result.decision_state.uncertainty
        assert result.decision_state.confidence > 0


def test_insurance_preserves_meaning_without_raw_hospital() -> None:
    result = PipelineRunner(runtime="mock").run("insurance")
    assert result.external_payload is not None
    assert result.external_payload.facts["provider_taxonomy"] == "large_general_hospital"
    assert result.external_payload.facts["treatment_taxonomy"] == "diagnostic_imaging_mri"
    assert not payload_contains_sensitive_data(result.case, result.external_payload)


def test_debt_preserves_relative_priority_without_institutions() -> None:
    result = PipelineRunner(runtime="mock").run("debt")
    assert result.external_payload is not None
    assert result.external_payload.facts["repayment_strategy"] == "debt_avalanche_high_interest_first"
    assert "relative_priority_encoding" in result.external_payload.techniques_applied
    assert not payload_contains_sensitive_data(result.case, result.external_payload)
