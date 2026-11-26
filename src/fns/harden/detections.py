"""Detection rules as code (M4 K3): load, lint, check coverage, export for Sentinel.

One YAML file per rule in ``detections/``. Linting is structural; it needs no
workspace: tables, brackets and quotes, parameters, banned operators, projected
entity columns, schedule. Deployment and detection results are M4 K4 (live).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import Field, ValidationError

from fns.models.base import FnsModel
from fns.yamlio import YamlError, loads_yaml

Severity = Literal["Informational", "Low", "Medium", "High"]
Tactic = Literal[
    "InitialAccess",
    "Execution",
    "Persistence",
    "PrivilegeEscalation",
    "DefenseEvasion",
    "CredentialAccess",
    "Discovery",
    "Collection",
    "Exfiltration",
    "Impact",
]
EntityType = Literal["Account", "AzureResource"]
ENTITY_IDENTIFIER: Final[dict[str, str]] = {"Account": "AadUserId", "AzureResource": "ResourceId"}
KNOWN_TABLES: Final = frozenset(
    {
        "AuditLogs",
        "AzureActivity",
        "AzureDiagnostics",
        "StorageBlobLogs",
        "SigninLogs",
        "AADServicePrincipalSignInLogs",
    }
)
_PARAM: Final = re.compile(r"\{\{\s*([a-z_][a-z0-9_]*)\s*\}\}")
_DURATION: Final = re.compile(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?)?$")


class DetectionRule(FnsModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    title: str = Field(min_length=5, max_length=120)
    description: str = Field(min_length=10)
    severity: Severity
    tactics: tuple[Tactic, ...] = Field(min_length=1)
    covers: tuple[str, ...] = Field(min_length=1)
    """``rule:<escalation rule>``, ``op:<target kind>:<operation>``, or ``way:<final way>``."""
    tables: tuple[str, ...] = Field(min_length=1)
    query: str = Field(min_length=10)
    query_frequency: str
    query_period: str
    entities: dict[EntityType, str] = Field(min_length=1)
    """Entity type -> column the query projects."""
    parameters: dict[str, str] = Field(default_factory=dict)
    """Parameter name -> description; used in the query as ``{{name}}``."""


def minutes(duration: str) -> int:
    m = _DURATION.match(duration)
    if not m or duration in {"P", "PT"}:
        raise ValueError(f"not an ISO 8601 duration in days/hours/minutes: {duration!r}")
    d, h, mi = (int(x) if x else 0 for x in m.groups())
    return d * 1440 + h * 60 + mi


def load_rules(directory: Path) -> tuple[list[DetectionRule], list[str]]:
    rules: list[DetectionRule] = []
    errors: list[str] = []
    for path in sorted(directory.glob("*.yaml")):
        if path.name == "EXEMPT.yaml":
            continue
        try:
            rules.append(DetectionRule.model_validate(loads_yaml(path.read_text(encoding="utf-8"))))
        except (ValidationError, YamlError) as exc:
            errors.append(f"{path.name}: invalid: {exc}")
            continue
        if rules[-1].id != path.stem:
            errors.append(f"{path.name}: id {rules[-1].id!r} does not match the file name")
    return rules, errors


def load_exempt(directory: Path) -> dict[str, str]:
    path = directory / "EXEMPT.yaml"
    if not path.exists():
        return {}
    data = loads_yaml(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not all(
        isinstance(k, str) and isinstance(v, str) and v.strip() for k, v in data.items()
    ):
        raise ValueError("EXEMPT.yaml must map coverage keys to non-empty reasons")
    return dict(data)


def _strip_strings(query: str) -> tuple[str, list[str]]:
    """Remove string literals and comments; report unterminated strings."""
    out: list[str] = []
    problems: list[str] = []
    i = 0
    while i < len(query):
        c = query[i]
        if query.startswith("//", i):
            j = query.find("\n", i)
            i = len(query) if j < 0 else j
            continue
        if c in "\"'":
            j = i + 1
            while j < len(query) and query[j] != c:
                j += 2 if query[j] == "\\" else 1
            if j >= len(query):
                problems.append("unterminated string literal")
                break
            out.append(" ")
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out), problems


def lint(rule: DetectionRule) -> list[str]:
    problems: list[str] = []
    code, string_problems = _strip_strings(rule.query)
    problems.extend(string_problems)
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    for c in _PARAM.sub("x", code):
        if c in "([{":
            stack.append(c)
        elif c in pairs:
            top = stack.pop() if stack else None
            if top != pairs[c]:
                problems.append(f"unbalanced {c!r}")
                break
    if stack:
        problems.append("unclosed bracket")
    unknown = sorted(set(rule.tables) - KNOWN_TABLES)
    if unknown:
        problems.append(f"unknown table(s) {unknown}")
    statements = [s.strip() for s in code.split(";") if s.strip()]
    tabular = [s for s in statements if not s.startswith("let ")]
    if not tabular:
        problems.append("no tabular expression")
    else:
        first = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)", tabular[-1])
        if not first or first.group(1) not in rule.tables:
            problems.append("the query must start from one of its declared tables")
    if re.search(r"\b(search|union)\s+\*", code):
        problems.append("search * / union * are not allowed")
    used = set(_PARAM.findall(rule.query))
    declared = set(rule.parameters)
    if used - declared:
        problems.append(f"undeclared parameter(s) {sorted(used - declared)}")
    if declared - used:
        problems.append(f"unused parameter(s) {sorted(declared - used)}")
    if "| project" not in code:
        problems.append("the query must end in a projection of its entity columns")
    else:
        projected = code[code.rindex("| project") :]
        for etype, column in sorted(rule.entities.items()):
            if not re.search(rf"\b{re.escape(column)}\b", projected):
                problems.append(f"entity column {column} ({etype}) is not projected")
    try:
        if minutes(rule.query_frequency) > minutes(rule.query_period):
            problems.append("query_frequency must not exceed query_period")
        if minutes(rule.query_frequency) < 5:
            problems.append("query_frequency below 5 minutes")
    except ValueError as exc:
        problems.append(str(exc))
    return problems


def render_query(rule: DetectionRule, params: dict[str, str]) -> str:
    missing = sorted(set(rule.parameters) - set(params))
    if missing:
        raise ValueError(f"{rule.id}: missing parameter(s) {missing}")
    return _PARAM.sub(lambda m: params[m.group(1)], rule.query)


def sentinel_rule(rule: DetectionRule, params: dict[str, str]) -> dict[str, Any]:
    """Body for ``Microsoft.SecurityInsights/alertRules`` (kind ``Scheduled``)."""
    return {
        "kind": "Scheduled",
        "properties": {
            "displayName": f"fns: {rule.title}",
            "description": rule.description,
            "severity": rule.severity,
            "enabled": True,
            "query": render_query(rule, params),
            "queryFrequency": rule.query_frequency,
            "queryPeriod": rule.query_period,
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "suppressionDuration": "PT1H",
            "suppressionEnabled": False,
            "tactics": list(rule.tactics),
            "entityMappings": [
                {
                    "entityType": etype,
                    "fieldMappings": [
                        {"identifier": ENTITY_IDENTIFIER[etype], "columnName": column}
                    ],
                }
                for etype, column in sorted(rule.entities.items())
            ],
        },
    }
