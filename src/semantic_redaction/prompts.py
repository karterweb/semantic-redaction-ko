from __future__ import annotations

import json

from semantic_redaction.models import PrivateCase


SYSTEM_PROMPT = """You are a semantic redaction model running inside a Korean financial company's private network.
Your job is to transform private financial context into a JSON draft for pseudonymized LLM use.
You are not the final privacy control. A deterministic policy gate will validate your output.
Return JSON only. Do not include markdown."""


def build_prompt(case: PrivateCase) -> str:
    schema_hint = {
        "intent": "short_snake_case_intent",
        "summary": "short Korean summary for private audit only",
        "candidates": [
            {
                "token": "TX_A | CLAIM_A | DEBT_A",
                "category": "transaction | claim | debt",
                "confidence": 0.0,
                "reasons": ["reason_code"],
                "conflicts": ["optional_conflict"],
                "facts": {"safe_key": "safe_value"},
            }
        ],
        "resolved_facts": {"safe_fact": "safe_value"},
        "uncertainty": "what remains uncertain",
        "confidence": 0.0,
        "required_action": "what the external LLM should do",
    }
    return "\n".join(
        [
            SYSTEM_PROMPT,
            "Usecase: " + case.usecase,
            "User utterance:",
            case.utterance,
            "Private records:",
            json.dumps(case.private_records, ensure_ascii=False, indent=2),
            "Target JSON schema:",
            json.dumps(schema_hint, ensure_ascii=False, indent=2),
            "Important: preserve meaning, but avoid direct personal names, raw merchant names, hospital names, account numbers, card numbers, exact balances, phone numbers, and detailed addresses.",
        ]
    )
