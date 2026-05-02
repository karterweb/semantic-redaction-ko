from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from semantic_redaction.pipeline import LAST_RUN_PATH


def load_last_run(path: Path = LAST_RUN_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def audit_to_markdown(data: dict[str, Any]) -> str:
    audit = data["policy_audit"]
    lines = [
        f"# Privacy Audit: {data['case']['title']}",
        "",
        f"- Case: `{audit['case_id']}`",
        f"- Usecase: `{audit['usecase']}`",
        f"- Status: `{audit['status']}`",
        f"- Risk level: `{audit['risk_level']}`",
        f"- Runtime: `{data['runtime']}`",
        "",
        "## Findings",
    ]
    if audit["findings"]:
        for finding in audit["findings"]:
            lines.append(
                f"- `{finding['severity']}` `{finding['reason']}` at `{finding['path']}`: `{finding['value']}`"
            )
    else:
        lines.append("- No sensitive terms detected in Qwen draft.")
    lines.extend(["", "## Guideline Controls"])
    lines.extend(f"- {control}" for control in audit["guideline_controls"])
    lines.extend(["", "## Meaning-Preserving Techniques"])
    if audit["techniques_applied"]:
        lines.extend(f"- {technique}" for technique in audit["techniques_applied"])
    else:
        lines.append("- None")
    lines.extend(["", "## Utility Preservation"])
    if audit["utility_preservation"]:
        for key, value in audit["utility_preservation"].items():
            lines.append(f"- `{key}`: `{value}`")
    else:
        lines.append("- Not measured")
    lines.extend(["", "## Residual Risks"])
    lines.extend(f"- {risk}" for risk in audit["residual_risks"])
    return "\n".join(lines)
