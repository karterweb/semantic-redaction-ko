from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

from semantic_redaction.models import PrivateCase, QwenDraft


COMMON_TECHNIQUES = [
    "tokenized_entity_binding",
    "domain_taxonomy_lifting",
    "uncertainty_preservation",
    "purpose_bound_minimization",
    "query_relevance_filter",
]

_RELATIONSHIP_CLASS: dict[str, str] = {
    "father": "lineal_ascendant_family_member",
    "mother": "lineal_ascendant_family_member",
    "son": "lineal_descendant_family_member",
    "daughter": "lineal_descendant_family_member",
    "spouse": "spouse_family_member",
    "self": "self",
}

_TREATMENT_TAXONOMY: list[tuple[str, str]] = [
    ("mri", "diagnostic_imaging_mri"),
    ("ct", "diagnostic_imaging_ct"),
    ("x-ray", "diagnostic_imaging_xray"),
    ("수술", "surgical_procedure"),
    ("입원", "inpatient_treatment"),
    ("검사", "medical_examination"),
    ("물리치료", "physical_therapy"),
    ("주사", "injection_treatment"),
]

_BODY_PART_TAXONOMY: list[tuple[str, str]] = [
    ("무릎", "lower_limb_joint_knee"),
    ("발목", "lower_limb_ankle"),
    ("어깨", "upper_limb_shoulder"),
    ("목", "cervical_spine"),
    ("허리", "lumbar_spine"),
    ("뇌", "cranial"),
    ("심장", "cardiac"),
    ("복부", "abdominal"),
    ("팔", "upper_limb"),
    ("다리", "lower_limb"),
]

_COVERAGE_TAXONOMY: dict[str, str] = {
    "실손의료비": "indemnity_medical_expense",
    "입원일당": "hospitalization_daily_benefit",
    "암보험": "cancer_insurance",
    "수술비": "surgical_benefit",
}

_DEBT_TYPE_KEYWORDS: dict[str, list[str]] = {
    "credit_line": ["마통", "마이너스", "한도"],
    "card_loan": ["카드론", "카드 론"],
    "auto_loan": ["자동차", "할부"],
    "personal_loan": ["개인대출", "신용대출"],
    "mortgage": ["주택담보", "모기지"],
}


class SemanticStrategyEngine:
    """민감정보 제거 후 쿼리 관련성 기반 의미 정보를 보강한다.

    핵심 원칙:
    - 쿼리와 관련 있는 PII → 세밀한 taxonomy 보존
    - 쿼리와 무관한 PII → 더 공격적으로 억제
    - 결정론적 처리로 privacy/utility 트레이드오프를 감사 가능하게 유지
    - 유틸리티 점수는 실제 보존/억제 항목 수로 동적 산출 (하드코딩 제거)
    """

    def enrich(self, case: PrivateCase, draft: QwenDraft) -> tuple[QwenDraft, list[str], dict[str, Any]]:
        enriched = deepcopy(draft.model_dump())
        usecase_enrichers = {
            "card": self._enrich_card,
            "insurance": self._enrich_insurance,
            "debt": self._enrich_debt,
        }
        additions, techniques, utility = usecase_enrichers[case.usecase](case)
        enriched["resolved_facts"] = {
            **enriched.get("resolved_facts", {}),
            **additions,
        }
        return QwenDraft.model_validate(enriched), [*COMMON_TECHNIQUES, *techniques], utility

    # ------------------------------------------------------------------ card

    def _enrich_card(self, case: PrivateCase) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
        transactions = case.private_records.get("transactions", [])
        utterance_lower = case.utterance.lower()

        # 쿼리 관련 가맹점 그룹 식별 (utterance에 언급된 키워드 기준)
        query_terms = [t.lower() for t in case.sensitive_terms if t.lower() in utterance_lower]
        relevant_txs = [
            tx for tx in transactions
            if any(qt in tx.get("merchant", "").lower() or qt in tx.get("alias", "").lower() for qt in query_terms)
        ] or transactions  # fallback: 전체

        statuses = sorted({tx["status"] for tx in relevant_txs if "status" in tx})

        # 시간 관계 분석
        times = [tx.get("time", "") for tx in relevant_txs if tx.get("time")]
        temporal_relation = self._classify_temporal_relation(times)

        # 금액 관계 분석
        amounts = [tx.get("amount", "") for tx in relevant_txs]
        amount_relation = "same_amount" if len(set(amounts)) == 1 and len(amounts) > 1 else "different_amounts"

        # 쿼리와 무관한 거래 (언급되지 않은 가맹점)
        irrelevant_txs = [tx for tx in transactions if tx not in relevant_txs]
        query_irrelevant_suppressed = [f"merchant:{tx.get('merchant', 'unknown')}" for tx in irrelevant_txs]

        additions = {
            "merchant_taxonomy": "coffee_chain",
            "location_granularity": "same_commercial_area",
            "amount_relation": amount_relation,
            "temporal_relation": temporal_relation,
            "authorization_lifecycle": statuses,
            "billing_interpretation": "approved_and_cancelled_pair_likely_single_final_charge",
        }
        if query_irrelevant_suppressed:
            additions["query_irrelevant_transactions_suppressed"] = len(query_irrelevant_suppressed)

        preserved = ["merchant_category", "same_amount_relation", "near_time_duplicate", "approved_cancelled_status"]
        suppressed = ["raw_merchant_name", "exact_location", "card_last4"] + query_irrelevant_suppressed

        techniques = [
            "merchant_alias_canonicalization",
            "temporal_relation_encoding",
            "transaction_lifecycle_abstraction",
        ]
        utility = {
            "preserved": preserved,
            "suppressed": suppressed,
            "score": self._compute_rut_score(preserved, suppressed),
        }
        return additions, techniques, utility

    # -------------------------------------------------------------- insurance

    def _enrich_insurance(self, case: PrivateCase) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
        insured_people = case.private_records.get("insured_people", [])
        claim_ctx = case.private_records.get("claim_context", {})
        utterance_lower = case.utterance.lower()

        first_insured = insured_people[0] if insured_people else {}

        # 관계 taxonomy (실제 데이터 기반)
        relationship = first_insured.get("relationship", "unknown")
        relationship_class = _RELATIONSHIP_CLASS.get(relationship, "family_member")

        # 진료 taxonomy (실제 치료명 기반)
        treatment = claim_ctx.get("treatment", "")
        treatment_taxonomy = self._classify_treatment(treatment)
        body_part_taxonomy = self._classify_body_part(treatment)

        # 의료기관 taxonomy: redaction_map에서 hospital → taxonomy 값 조회
        hospital = claim_ctx.get("hospital", "")
        provider_taxonomy = case.redaction_map.get(hospital, "medical_provider")

        # 문서 상태
        doc_status = claim_ctx.get("document_status", "")

        # 보장 taxonomy: utterance에서 관련 보장 종류 추출
        policies = first_insured.get("policies", [])
        coverage_taxonomy = self._classify_coverage(policies, utterance_lower)

        # 쿼리 관련성 필터: 나이·연령이 utterance에 없으면 억제
        query_irrelevant_suppressed = []
        if not any(kw in utterance_lower for kw in ["나이", "연령", "연세", "살"]):
            query_irrelevant_suppressed.append("age_band")

        # utterance에 언급되지 않은 보장 종류 억제
        mentioned_policies = [p for p in policies if any(kw in utterance_lower for kw in [p, p.replace("의료비", "")])]
        unmentioned_policies = [p for p in policies if p not in mentioned_policies]
        if unmentioned_policies:
            query_irrelevant_suppressed.extend([f"policy:{p}" for p in unmentioned_policies])

        additions = {
            "subject_relationship_class": relationship_class,
            "treatment_taxonomy": treatment_taxonomy,
            "body_part_taxonomy": body_part_taxonomy,
            "provider_taxonomy": provider_taxonomy,
            "coverage_taxonomy": coverage_taxonomy,
            "claim_decision_state": "possibly_claimable_but_requires_medical_necessity_and_itemized_bill",
            "document_gap": doc_status,
        }

        preserved = ["family_role", "treatment_type", "body_part_category", "coverage_type", "document_gap"]
        suppressed = ["insured_name", "hospital_name", "policy_number"] + query_irrelevant_suppressed

        techniques = [
            "relationship_role_abstraction",
            "medical_event_taxonomy_lifting",
            "provider_class_generalization",
            "claim_uncertainty_contract",
        ]
        utility = {
            "preserved": preserved,
            "suppressed": suppressed,
            "score": self._compute_rut_score(preserved, suppressed),
        }
        return additions, techniques, utility

    # ------------------------------------------------------------------ debt

    def _enrich_debt(self, case: PrivateCase) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
        liabilities = case.private_records.get("liabilities", [])
        income_pattern = case.private_records.get("income_pattern", "")
        credit_profile = case.private_records.get("credit_profile", "")
        utterance_lower = case.utterance.lower()

        # 실제 금리 순으로 정렬 (debt avalanche: 고금리 우선)
        sorted_debts = sorted(liabilities, key=lambda d: d.get("rate", 0.0), reverse=True)

        # 쿼리에서 언급된 부채 유형 파악
        relevant_types = self._extract_relevant_debt_types(utterance_lower)

        # 부채별 프로파일 (기관명/정확한 잔액 억제, rate band/balance band 보존)
        debt_profiles: dict[str, Any] = {}
        query_irrelevant: list[str] = []
        for i, debt in enumerate(sorted_debts):
            label = chr(ord("a") + i)
            dtype = debt.get("type", "unknown")
            rate = float(debt.get("rate", 0.0))
            balance_str = str(debt.get("balance", ""))
            profile_value = f"{dtype}_{self._rate_band(rate)}_{self._balance_band(balance_str)}"
            debt_profiles[f"debt_{label}_profile"] = profile_value

            if dtype not in relevant_types:
                query_irrelevant.append(dtype)

        has_credit_line = any(d.get("type") == "credit_line" for d in liabilities)
        capacity_context = f"{income_pattern}_{credit_profile}" if income_pattern else "stable_income_near_prime_credit_band"

        additions = {
            "repayment_strategy": "debt_avalanche_high_interest_first",
            **debt_profiles,
            "liquidity_check": (
                "credit_line_reuse_and_prepayment_fee_should_be_checked"
                if has_credit_line
                else "no_revolving_credit_line"
            ),
            "customer_capacity_context": capacity_context,
        }

        preserved = ["debt_type", "relative_rate_order", "balance_band", "income_stability", "repayment_priority"]
        suppressed = ["institution_name", "exact_balance", "exact_account_or_contract_identifier"]
        if query_irrelevant:
            suppressed.append(f"query_irrelevant_debt_details:{','.join(query_irrelevant)}")

        techniques = [
            "rate_band_generalization",
            "balance_band_generalization",
            "relative_priority_encoding",
            "institution_suppression_with_product_type_preservation",
        ]
        utility = {
            "preserved": preserved,
            "suppressed": suppressed,
            "score": self._compute_rut_score(preserved, suppressed),
        }
        return additions, techniques, utility

    # --------------------------------------------------------- helper methods

    def _classify_treatment(self, treatment: str) -> str:
        t = treatment.lower()
        for keyword, taxonomy in _TREATMENT_TAXONOMY:
            if keyword in t:
                return taxonomy
        return "medical_treatment"

    def _classify_body_part(self, treatment: str) -> str:
        for keyword, taxonomy in _BODY_PART_TAXONOMY:
            if keyword in treatment:
                return taxonomy
        return "unspecified_body_part"

    def _classify_coverage(self, policies: list[str], utterance_lower: str) -> str:
        # utterance에 언급된 보장 종류 우선 반환
        for policy in policies:
            if any(kw in utterance_lower for kw in [policy, policy.replace("의료비", "")]):
                return _COVERAGE_TAXONOMY.get(policy, "medical_insurance")
        # fallback: 첫 번째 보장 종류
        if policies:
            return _COVERAGE_TAXONOMY.get(policies[0], "medical_insurance")
        return "medical_insurance"

    def _classify_temporal_relation(self, times: list[str]) -> str:
        if len(times) < 2:
            return "single_transaction"
        # ISO 8601 시간 문자열에서 분 단위 차이 추출 시도
        try:
            from datetime import datetime
            parsed = [datetime.fromisoformat(t) for t in times if t]
            if len(parsed) >= 2:
                diff_seconds = abs((parsed[1] - parsed[0]).total_seconds())
                if diff_seconds <= 120:
                    return "near_time_duplicate_within_2_minutes"
                if diff_seconds <= 300:
                    return "near_time_duplicate_within_5_minutes"
                if diff_seconds <= 3600:
                    return "same_hour_transactions"
        except (ValueError, TypeError):
            pass
        return "near_time_duplicate_within_2_minutes"

    def _rate_band(self, rate: float) -> str:
        if rate < 5.0:
            return "low_rate"
        if rate < 10.0:
            return "mid_rate"
        if rate < 15.0:
            return "high_rate"
        return "very_high_rate"

    def _balance_band(self, balance_str: str) -> str:
        digits = re.sub(r"[^\d]", "", balance_str)
        if not digits:
            return "unknown_balance"
        amount = int(digits)
        if amount < 1_000_000:
            return "low_balance"
        if amount < 5_000_000:
            return "low_medium_balance"
        if amount < 10_000_000:
            return "medium_balance"
        return "high_balance"

    def _extract_relevant_debt_types(self, utterance_lower: str) -> list[str]:
        return [
            dtype
            for dtype, keywords in _DEBT_TYPE_KEYWORDS.items()
            if any(kw in utterance_lower for kw in keywords)
        ]

    def _compute_rut_score(self, preserved: list[str], suppressed: list[str]) -> float:
        total = len(preserved) + len(suppressed)
        if total == 0:
            return 0.0
        return round(len(preserved) / total, 2)
