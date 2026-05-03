from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from semantic_redaction.models import CrossReferenceWarning, UseCase


SESSION_PATH = Path(".semantic-redaction/session-crossref.json")

# 누적 노출 의미 차원 수 기준
_MEDIUM_THRESHOLD = 3
_HIGH_THRESHOLD = 5


class CrossReferenceDetector:
    """세션 내 동일 유스케이스에 대한 반복 쿼리에서 의미 차원 누적을 추적해
    교차 참조를 통한 재식별 위험을 탐지한다.

    탐지 방식: 각 쿼리가 외부에 노출하는 의미 차원(utility_preservation.preserved)을
    누적 관리하고, 임계값 초과 시 경고를 발생시킨다.
    차단이 아닌 탐지·경고로만 작동해 유틸리티를 유지한다.
    """

    def __init__(self, session_path: Path = SESSION_PATH) -> None:
        self._path = session_path

    def check_and_register(
        self, usecase: UseCase, exposed_dimensions: list[str]
    ) -> list[CrossReferenceWarning]:
        session = self._load()
        prior: dict[str, Any] = session.get(usecase, {"query_count": 0, "cumulative_dimensions": []})

        prior_dims: list[str] = prior["cumulative_dimensions"]
        overlapping = [d for d in exposed_dimensions if d in prior_dims]
        # 순서 유지 중복 제거
        all_dims: list[str] = list(dict.fromkeys(prior_dims + exposed_dimensions))

        warnings = self._evaluate(usecase, all_dims, overlapping)

        session[usecase] = {
            "query_count": prior["query_count"] + 1,
            "cumulative_dimensions": all_dims,
        }
        self._save(session)
        return warnings

    def reset(self, usecase: UseCase | None = None) -> None:
        session = self._load()
        if usecase:
            session.pop(usecase, None)
        else:
            session = {}
        self._save(session)

    def _evaluate(
        self,
        usecase: UseCase,
        all_dims: list[str],
        overlapping: list[str],
    ) -> list[CrossReferenceWarning]:
        count = len(all_dims)
        if count >= _HIGH_THRESHOLD:
            return [
                CrossReferenceWarning(
                    usecase=usecase,
                    level="high",
                    cumulative_dimension_count=count,
                    overlapping_dimensions=overlapping,
                    description=(
                        f"누적 {count}개 의미 차원이 외부에 노출됨. "
                        "복수 쿼리 조합 시 재식별 위험이 높습니다. "
                        "세션 격리 또는 맥락 초기화를 권장합니다."
                    ),
                )
            ]
        if count >= _MEDIUM_THRESHOLD and overlapping:
            return [
                CrossReferenceWarning(
                    usecase=usecase,
                    level="medium",
                    cumulative_dimension_count=count,
                    overlapping_dimensions=overlapping,
                    description=(
                        f"이전 쿼리와 {len(overlapping)}개 의미 차원이 중복 노출됨 "
                        f"(누적 {count}개). "
                        "교차 참조를 통한 재식별 위험이 증가하고 있습니다."
                    ),
                )
            ]
        return []

    def _load(self) -> dict[str, Any]:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _save(self, session: dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(session, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
