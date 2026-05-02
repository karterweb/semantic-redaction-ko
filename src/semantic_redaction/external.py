from __future__ import annotations

from semantic_redaction.models import ExternalPayload, UseCase


class MockExternalLLM:
    def complete(self, usecase: UseCase, payload: ExternalPayload) -> str:
        if usecase == "card":
            return (
                "TX_A와 TX_B는 같은 금액의 근접 시간 거래입니다. "
                "TX_B는 취소 후보로 표시되어 최종 청구는 TX_A만 남을 가능성이 큽니다."
            )
        if usecase == "insurance":
            return (
                "CLAIM_A의 경우 실손 청구 가능성이 있지만, 진료비 세부내역서와 의학적 필요성 확인이 필요합니다. "
                "필요 서류를 준비한 뒤 접수 가능 여부를 확인하세요."
            )
        return (
            "금리 부담 기준으로는 DEBT_B부터 우선 검토하고, DEBT_A의 경우 한도 재사용 가능성과 수수료를 확인하세요. "
            "DEBT_C는 상대적으로 낮은 금리라 후순위 검토 대상입니다."
        )


class SafeRehydrator:
    def rehydrate(self, response: str, allowed_map: dict[str, str]) -> str:
        hydrated = response
        for token, label in allowed_map.items():
            hydrated = hydrated.replace(token, label)
        return hydrated
