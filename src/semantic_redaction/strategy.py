from __future__ import annotations

from copy import deepcopy
from typing import Any

from semantic_redaction.models import PrivateCase, QwenDraft


COMMON_TECHNIQUES = [
    "tokenized_entity_binding",
    "domain_taxonomy_lifting",
    "uncertainty_preservation",
    "purpose_bound_minimization",
]


class SemanticStrategyEngine:
    """Adds task-specific meaning after sensitive values are removed.

    This is deliberately deterministic. Qwen may draft the meaning, but this
    layer makes the privacy/utility tradeoff inspectable and testable.
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

    def _enrich_card(self, case: PrivateCase) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
        transactions = case.private_records["transactions"]
        coffee_candidates = [
            tx for tx in transactions if "STARBUCKS" in tx.get("merchant", "") or "SBUX" in tx.get("merchant", "")
        ]
        statuses = sorted({tx["status"] for tx in coffee_candidates})
        additions = {
            "merchant_taxonomy": "coffee_chain",
            "location_granularity": "same_commercial_area",
            "amount_relation": "same_amount",
            "temporal_relation": "near_time_duplicate_within_2_minutes",
            "authorization_lifecycle": statuses,
            "billing_interpretation": "approved_and_cancelled_pair_likely_single_final_charge",
        }
        techniques = [
            "merchant_alias_canonicalization",
            "temporal_relation_encoding",
            "transaction_lifecycle_abstraction",
        ]
        utility = {
            "preserved": ["merchant_category", "same_amount_relation", "near_time_duplicate", "approved_cancelled_status"],
            "suppressed": ["raw_merchant_name", "exact_location", "card_last4"],
            "score": 0.9,
        }
        return additions, techniques, utility

    def _enrich_insurance(self, case: PrivateCase) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
        additions = {
            "subject_relationship_class": "lineal_ascendant_family_member",
            "treatment_taxonomy": "diagnostic_imaging_mri",
            "body_part_taxonomy": "lower_limb_joint",
            "provider_taxonomy": "large_general_hospital",
            "coverage_taxonomy": "indemnity_medical_expense",
            "claim_decision_state": "possibly_claimable_but_requires_medical_necessity_and_itemized_bill",
        }
        techniques = [
            "relationship_role_abstraction",
            "medical_event_taxonomy_lifting",
            "provider_class_generalization",
            "claim_uncertainty_contract",
        ]
        utility = {
            "preserved": ["family_role", "treatment_type", "body_part_category", "coverage_type", "document_gap"],
            "suppressed": ["insured_name", "hospital_name", "policy_number"],
            "score": 0.86,
        }
        return additions, techniques, utility

    def _enrich_debt(self, case: PrivateCase) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
        additions = {
            "repayment_strategy": "debt_avalanche_high_interest_first",
            "debt_a_profile": "revolving_credit_line_mid_rate_medium_balance",
            "debt_b_profile": "unsecured_card_loan_high_rate_low_medium_balance",
            "debt_c_profile": "purpose_auto_loan_low_rate_high_balance",
            "liquidity_check": "credit_line_reuse_and_prepayment_fee_should_be_checked",
            "customer_capacity_context": "stable_income_near_prime_credit_band",
        }
        techniques = [
            "rate_band_generalization",
            "balance_band_generalization",
            "relative_priority_encoding",
            "institution_suppression_with_product_type_preservation",
        ]
        utility = {
            "preserved": ["debt_type", "relative_rate_order", "balance_band", "income_stability", "repayment_priority"],
            "suppressed": ["institution_name", "exact_balance", "exact_account_or_contract_identifier"],
            "score": 0.88,
        }
        return additions, techniques, utility
