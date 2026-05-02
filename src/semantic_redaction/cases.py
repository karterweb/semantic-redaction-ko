from __future__ import annotations

from semantic_redaction.models import PrivateCase, UseCase


CASES: dict[UseCase, PrivateCase] = {
    "card": PrivateCase(
        id="card-transaction-mystery",
        usecase="card",
        title="Card Transaction Mystery",
        utterance="지난주 강남 스벅 두 번 긁힌 거 뭐야? 하나는 취소된 거 아냐?",
        private_records={
            "transactions": [
                {
                    "merchant": "STARBUCKS GANGNAM 2",
                    "alias": "스벅 강남2호점",
                    "amount": "6,800원",
                    "time": "2026-04-23T08:41:00+09:00",
                    "status": "approved",
                    "card_last4": "4491",
                },
                {
                    "merchant": "SBUX GANGNAM STN",
                    "alias": "스타벅스 강남역점",
                    "amount": "6,800원",
                    "time": "2026-04-23T08:43:00+09:00",
                    "status": "cancelled",
                    "card_last4": "4491",
                },
                {
                    "merchant": "NETFLIX.COM",
                    "amount": "17,000원",
                    "time": "2026-04-24T02:10:00+09:00",
                    "status": "approved",
                    "recurring": True,
                },
            ]
        },
        sensitive_terms=[
            "강남",
            "스벅",
            "스타벅스",
            "STARBUCKS",
            "SBUX",
            "GANGNAM",
            "4491",
        ],
        redaction_map={
            "강남": "same_commercial_area",
            "스벅": "coffee_chain",
            "스타벅스": "coffee_chain",
            "STARBUCKS": "coffee_chain",
            "SBUX": "coffee_chain",
            "GANGNAM": "same_commercial_area",
            "4491": "CARD_TOKEN_A",
        },
        rehydration_map={
            "TX_A": "4월 23일 08:41 커피전문점 승인 거래",
            "TX_B": "4월 23일 08:43 커피전문점 취소 거래",
        },
    ),
    "insurance": PrivateCase(
        id="insurance-claim-guidance",
        usecase="insurance",
        title="Insurance Claim Guidance",
        utterance="아버지 무릎 MRI 찍은 거 서울아산병원에서 한 건 실손 청구돼?",
        private_records={
            "insured_people": [
                {
                    "name": "김영호",
                    "relationship": "father",
                    "age_band": "70s",
                    "policies": ["실손의료비", "입원일당"],
                }
            ],
            "claim_context": {
                "hospital": "서울아산병원",
                "treatment": "무릎 MRI",
                "document_status": "receipt_only",
            },
            "policy_no": "LIFE-2020-889172",
        },
        sensitive_terms=[
            "김영호",
            "아버지",
            "서울아산병원",
            "LIFE-2020-889172",
        ],
        redaction_map={
            "김영호": "FAMILY_MEMBER_A",
            "아버지": "FAMILY_MEMBER_A",
            "서울아산병원": "large_general_hospital",
            "LIFE-2020-889172": "POLICY_TOKEN_A",
        },
        rehydration_map={
            "FAMILY_MEMBER_A": "가족 구성원",
            "CLAIM_A": "무릎 MRI 관련 실손 청구 건",
        },
    ),
    "debt": PrivateCase(
        id="debt-optimization",
        usecase="debt",
        title="Debt Optimization",
        utterance="신한 마통보다 카드론 먼저 갚는 게 나아, 자동차 할부 먼저 갚는 게 나아?",
        private_records={
            "liabilities": [
                {
                    "institution": "신한은행",
                    "type": "credit_line",
                    "nickname": "마통",
                    "rate": 6.8,
                    "balance": "4,200,000원",
                },
                {
                    "institution": "KB국민카드",
                    "type": "card_loan",
                    "rate": 14.9,
                    "balance": "1,800,000원",
                },
                {
                    "institution": "현대캐피탈",
                    "type": "auto_loan",
                    "rate": 5.2,
                    "balance": "9,000,000원",
                },
            ],
            "income_pattern": "stable_monthly_salary",
            "credit_profile": "near_prime",
        },
        sensitive_terms=[
            "신한",
            "신한은행",
            "KB국민카드",
            "현대캐피탈",
            "4,200,000원",
            "1,800,000원",
            "9,000,000원",
        ],
        redaction_map={
            "신한은행": "BANK_TOKEN_A",
            "신한": "BANK_TOKEN_A",
            "KB국민카드": "CARD_ISSUER_TOKEN_A",
            "현대캐피탈": "LENDER_TOKEN_A",
            "4,200,000원": "medium_balance",
            "1,800,000원": "low_medium_balance",
            "9,000,000원": "high_balance",
        },
        rehydration_map={
            "DEBT_A": "마이너스통장",
            "DEBT_B": "카드론",
            "DEBT_C": "자동차 할부",
        },
    ),
}


def get_case(usecase: UseCase) -> PrivateCase:
    return CASES[usecase]
