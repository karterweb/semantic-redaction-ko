import re

from semantic_redaction.cases import get_case
from semantic_redaction.crossref import CrossReferenceDetector
from semantic_redaction.models import PrivateCase, PrivacyFinding, QwenDraft
from semantic_redaction.pipeline import PipelineRunner
from semantic_redaction.policy import FORBIDDEN_PATTERNS, PrivacyPolicyGate, payload_contains_sensitive_data
from semantic_redaction.redactor import SemanticRedactor


# ------------------------------------------------------------------ 기존 테스트

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


# -------------------------------------------------------- Phase 1: 새 FORBIDDEN_PATTERNS

def _find_pattern(reason: str) -> re.Pattern[str]:
    for pat, r in FORBIDDEN_PATTERNS:
        if r == reason:
            return pat
    raise KeyError(reason)


def test_forbidden_pattern_resident_registration_number() -> None:
    pat = _find_pattern("resident_registration_number")
    assert pat.search("주민번호: 901231-1234567")
    assert not pat.search("123456789")  # 대시 없음


def test_forbidden_pattern_card_number() -> None:
    pat = _find_pattern("card_number")
    assert pat.search("1234-5678-9012-3456")
    assert pat.search("1234 5678 9012 3456")
    assert not pat.search("1234567890123456")  # 구분자 없음


def test_forbidden_pattern_business_registration_number() -> None:
    pat = _find_pattern("business_registration_number")
    assert pat.search("사업자: 123-45-67890")
    assert not pat.search("12345-67890")


def test_forbidden_pattern_email() -> None:
    pat = _find_pattern("email_address")
    assert pat.search("user@example.com")
    assert pat.search("hong.gildong+finance@company.co.kr")
    assert not pat.search("notanemail")


def test_forbidden_pattern_financial_institution() -> None:
    pat = _find_pattern("raw_financial_institution")
    assert pat.search("KB국민카드")
    assert pat.search("삼성생명")
    assert pat.search("현대캐피탈")
    assert pat.search("NH투자증권")
    assert pat.search("동양저축은행")


def test_forbidden_pattern_medical_institution() -> None:
    pat = _find_pattern("raw_medical_institution")
    assert pat.search("서울아산병원")
    assert pat.search("강남세브란스병원")
    assert pat.search("연세의원")


def test_forbidden_pattern_korean_unit_amount() -> None:
    pat = _find_pattern("exact_amount_korean_unit")
    assert pat.search("420만원")
    assert pat.search("1억원")
    assert pat.search("50천원")
    assert not pat.search("420달러")


# ------------------------------------------------- Phase 1: dict key 스캔

def test_scan_detects_sensitive_term_in_dict_key() -> None:
    case = get_case("insurance")
    gate = PrivacyPolicyGate()
    draft = QwenDraft(
        intent="test",
        summary="test",
        candidates=[],
        resolved_facts={"서울아산병원": "some_value"},  # 민감정보가 key에 있음
        uncertainty="test",
        confidence=0.9,
        required_action="test",
    )
    findings = gate.inspect(case, draft)
    assert any("서울아산병원" in f.value for f in findings)


# -------------------------------------------- Phase 1: case-insensitive 탐지

def test_scan_detects_sensitive_term_case_insensitive() -> None:
    case = get_case("card")
    gate = PrivacyPolicyGate()
    # "STARBUCKS"는 sensitive_terms에 있음. 소문자 변형도 탐지되어야 함
    draft = QwenDraft(
        intent="test",
        summary="starbucks gangnam",  # 소문자
        candidates=[],
        resolved_facts={},
        uncertainty="test",
        confidence=0.9,
        required_action="test",
    )
    findings = gate.inspect(case, draft)
    assert any("STARBUCKS" in f.value or "starbucks" in f.value.lower() for f in findings)


def test_sanitize_is_case_insensitive() -> None:
    case = get_case("card")
    gate = PrivacyPolicyGate()
    # 소문자 "starbucks"도 redaction_map의 "STARBUCKS" 키로 교체되어야 함
    result = gate.sanitize_string(case, "visited starbucks gangnam yesterday")
    assert "starbucks" not in result.lower()
    assert "coffee_chain" in result


# ----------------------------------------------- Phase 1: outbound filter

def test_outbound_filter_detects_sensitive_term_in_external_response() -> None:
    case = get_case("insurance")
    gate = PrivacyPolicyGate()
    response_with_leak = "서울아산병원에서 MRI 검사를 받으셨군요."
    findings = gate.inspect_string(case, response_with_leak)
    assert any("서울아산병원" in f.value for f in findings)


def test_outbound_filter_sanitizes_external_response() -> None:
    case = get_case("insurance")
    gate = PrivacyPolicyGate()
    leaked = "서울아산병원에서 MRI를 받은 경우 실손 청구가 가능합니다."
    sanitized = gate.sanitize_string(case, leaked)
    assert "서울아산병원" not in sanitized
    assert "large_general_hospital" in sanitized


def test_pipeline_outbound_findings_are_empty_for_clean_mock_response() -> None:
    # 현재 mock external LLM은 토큰만 사용하므로 outbound findings 없어야 함
    result = PipelineRunner(runtime="mock").run("card")
    assert result.policy_audit.outbound_findings == []


# -------------------------------------------- Phase 2: 데이터 기반 enrichment

def test_insurance_enricher_reads_treatment_from_private_records() -> None:
    result = PipelineRunner(runtime="mock").run("insurance")
    facts = result.external_payload.facts  # type: ignore[union-attr]
    # "무릎 MRI"가 private_records에 있으므로 taxonomy가 MRI여야 함
    assert facts["treatment_taxonomy"] == "diagnostic_imaging_mri"
    assert "knee" in facts["body_part_taxonomy"]


def test_debt_enricher_reads_rates_from_private_records() -> None:
    result = PipelineRunner(runtime="mock").run("debt")
    facts = result.external_payload.facts  # type: ignore[union-attr]
    # 카드론이 14.9%로 가장 높으므로 debt_a (첫 번째, 최고금리)가 card_loan이어야 함
    # 14.9% → high_rate (very_high_rate는 15% 이상)
    assert "card_loan" in facts["debt_a_profile"]
    assert "high_rate" in facts["debt_a_profile"]


def test_utility_score_is_dynamically_computed() -> None:
    for usecase in ("card", "insurance", "debt"):
        result = PipelineRunner(runtime="mock").run(usecase)  # type: ignore[arg-type]
        score = result.policy_audit.utility_score
        # 하드코딩된 0.9/0.86/0.88 대신 실제 계산값 (0 < score < 1)
        assert 0.0 < score < 1.0


def test_query_relevance_filter_technique_applied() -> None:
    for usecase in ("card", "insurance", "debt"):
        result = PipelineRunner(runtime="mock").run(usecase)  # type: ignore[arg-type]
        assert "query_relevance_filter" in result.external_payload.techniques_applied  # type: ignore[union-attr]


# -------------------------------------------- Phase 3: 교차 참조 탐지

def test_crossref_no_warning_on_first_query(tmp_path) -> None:  # type: ignore[no-untyped-def]
    detector = CrossReferenceDetector(session_path=tmp_path / "crossref.json")
    warnings = detector.check_and_register("card", ["merchant_category", "same_amount_relation"])
    assert warnings == []


def test_crossref_medium_warning_on_overlapping_queries(tmp_path) -> None:  # type: ignore[no-untyped-def]
    detector = CrossReferenceDetector(session_path=tmp_path / "crossref.json")
    detector.check_and_register("card", ["merchant_category", "same_amount_relation"])
    # 두 번째 쿼리에서 겹치는 차원 + 새 차원 추가 → medium 경고
    warnings = detector.check_and_register(
        "card", ["merchant_category", "near_time_duplicate", "approved_cancelled_status"]
    )
    assert any(w.level == "medium" for w in warnings)


def test_crossref_high_warning_on_many_dimensions(tmp_path) -> None:  # type: ignore[no-untyped-def]
    detector = CrossReferenceDetector(session_path=tmp_path / "crossref.json")
    detector.check_and_register("card", ["a", "b", "c"])
    warnings = detector.check_and_register("card", ["c", "d", "e"])  # 누적 5개 → high
    assert any(w.level == "high" for w in warnings)


def test_crossref_separate_per_usecase(tmp_path) -> None:  # type: ignore[no-untyped-def]
    detector = CrossReferenceDetector(session_path=tmp_path / "crossref.json")
    detector.check_and_register("card", ["a", "b", "c", "d"])
    # 다른 usecase는 독립적으로 추적
    warnings = detector.check_and_register("insurance", ["a", "b"])
    assert warnings == []


# --------------------------------------------- Phase 4: 2026 위험 등급 평가

def test_risk_tier_assessment_is_high_for_external_llm_call() -> None:
    result = PipelineRunner(runtime="mock").run("card")
    assessment = result.policy_audit.risk_tier_assessment
    assert assessment.tier == "high"
    assert assessment.reviewer_count_required == 3
    assert "2026" in assessment.guideline_reference


def test_all_scenarios_have_risk_tier_assessment() -> None:
    for usecase in ("card", "insurance", "debt"):
        result = PipelineRunner(runtime="mock").run(usecase)  # type: ignore[arg-type]
        assert result.policy_audit.risk_tier_assessment is not None
        assert result.policy_audit.risk_tier_assessment.tier in ("low", "medium", "high")
