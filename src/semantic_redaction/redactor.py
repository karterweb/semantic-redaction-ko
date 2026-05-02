from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from pydantic import ValidationError

from semantic_redaction.models import PrivateCase, QwenDraft
from semantic_redaction.prompts import build_prompt


class SemanticRedactor:
    def __init__(self, model: str = "qwen3:30b-a3b", runtime: str = "auto") -> None:
        self.model = model
        self.runtime = runtime

    def draft(self, case: PrivateCase) -> tuple[QwenDraft, str]:
        if self.runtime == "openai-compatible":
            return self._draft_with_openai_compatible(case), "openai-compatible"
        if self.runtime in {"auto", "ollama"}:
            try:
                return self._draft_with_ollama(case), "ollama"
            except (OSError, TimeoutError, urllib.error.URLError, ValidationError, json.JSONDecodeError):
                if self.runtime == "ollama":
                    raise
        return self._mock_draft(case), "mock"

    def _draft_with_ollama(self, case: PrivateCase) -> QwenDraft:
        request = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=json.dumps(
                {
                    "model": self.model,
                    "prompt": build_prompt(case),
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.1},
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            body = json.loads(response.read().decode("utf-8"))
        raw = body.get("response", "{}")
        return QwenDraft.model_validate_json(raw)

    def _draft_with_openai_compatible(self, case: PrivateCase) -> QwenDraft:
        base_url = os.getenv("OPENAI_COMPATIBLE_BASE_URL", "http://localhost:8000/v1").rstrip("/")
        api_key = os.getenv("OPENAI_COMPATIBLE_API_KEY", "local")
        request = urllib.request.Request(
            f"{base_url}/chat/completions",
            data=json.dumps(
                {
                    "model": self.model,
                    "messages": [{"role": "user", "content": build_prompt(case)}],
                    "temperature": 0.1,
                    "response_format": {"type": "json_object"},
                }
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.loads(response.read().decode("utf-8"))
        raw = body["choices"][0]["message"]["content"]
        return QwenDraft.model_validate_json(raw)

    def _mock_draft(self, case: PrivateCase) -> QwenDraft:
        drafts: dict[str, dict[str, Any]] = {
            "card": {
                "intent": "explain_card_transactions",
                "summary": "사용자가 지난주 강남 스벅 중복 결제와 취소 여부를 묻고 있음",
                "candidates": [
                    {
                        "token": "TX_A",
                        "category": "transaction",
                        "confidence": 0.91,
                        "reasons": ["merchant_alias_match", "same_amount", "near_time_duplicate"],
                        "conflicts": [],
                        "facts": {"status": "approved", "merchant_hint": "STARBUCKS GANGNAM 2"},
                    },
                    {
                        "token": "TX_B",
                        "category": "transaction",
                        "confidence": 0.88,
                        "reasons": ["merchant_alias_match", "same_amount", "cancelled_candidate"],
                        "conflicts": [],
                        "facts": {"status": "cancelled", "merchant_hint": "SBUX GANGNAM STN"},
                    },
                ],
                "resolved_facts": {
                    "merchant_category": "coffee_chain",
                    "area_hint": "강남",
                    "duplicate_pattern": "two same-amount authorizations within two minutes",
                },
                "uncertainty": "카드사 전표 확정 전에는 최종 청구 여부가 바뀔 수 있음",
                "confidence": 0.89,
                "required_action": "explain_transactions_without_raw_merchant_names",
            },
            "insurance": {
                "intent": "insurance_claim_guidance",
                "summary": "아버지의 서울아산병원 무릎 MRI 실손 청구 가능성 문의",
                "candidates": [
                    {
                        "token": "CLAIM_A",
                        "category": "claim",
                        "confidence": 0.82,
                        "reasons": ["family_member_context", "diagnostic_imaging", "indemnity_medical_present"],
                        "conflicts": ["medical_necessity_documents_required"],
                        "facts": {"hospital": "서울아산병원", "treatment_category": "diagnostic_imaging"},
                    }
                ],
                "resolved_facts": {
                    "subject": "아버지",
                    "hospital_type": "서울아산병원",
                    "body_part_category": "joint_lower_limb",
                    "coverage_context": "has_indemnity_medical",
                },
                "uncertainty": "의사 소견과 진료비 세부내역서에 따라 보상 여부가 달라질 수 있음",
                "confidence": 0.82,
                "required_action": "generate_claim_guidance_with_uncertainty",
            },
            "debt": {
                "intent": "debt_optimization_advice",
                "summary": "신한 마통, 카드론, 자동차 할부 중 상환 우선순위 문의",
                "candidates": [
                    {
                        "token": "DEBT_A",
                        "category": "debt",
                        "confidence": 0.86,
                        "reasons": ["credit_line_alias", "mid_rate"],
                        "conflicts": [],
                        "facts": {"type": "credit_line", "institution": "신한은행", "balance": "4,200,000원"},
                    },
                    {
                        "token": "DEBT_B",
                        "category": "debt",
                        "confidence": 0.94,
                        "reasons": ["high_rate", "smallest_balance"],
                        "conflicts": [],
                        "facts": {"type": "card_loan", "balance": "1,800,000원"},
                    },
                    {
                        "token": "DEBT_C",
                        "category": "debt",
                        "confidence": 0.9,
                        "reasons": ["low_rate", "secured_or_purpose_loan"],
                        "conflicts": [],
                        "facts": {"type": "auto_loan", "balance": "9,000,000원"},
                    },
                ],
                "resolved_facts": {
                    "priority_signal": "higher_rate_first",
                    "income_stability": "stable_monthly_salary",
                    "credit_profile": "near_prime",
                },
                "uncertainty": "중도상환수수료와 한도 재사용 가능 여부 확인 필요",
                "confidence": 0.9,
                "required_action": "explain_repayment_priority_without_original_institutions",
            },
        }
        return QwenDraft.model_validate(drafts[case.usecase])
