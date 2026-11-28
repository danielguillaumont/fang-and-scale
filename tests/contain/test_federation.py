"""Who can satisfy a federated identity credential (queue item 2, pending review)."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from fns.contain import federation as fed
from tests.factories import TENANT, pid

AUD = (fed.TOKEN_EXCHANGE_AUDIENCE,)
GH = fed.GITHUB_ISSUER


@pytest.mark.parametrize(
    ("subject", "kind", "severity"),
    [
        ("repo:org/app:pull_request", "github-pull-request", "high"),
        ("repo:org/app:ref:refs/heads/main", "github-branch", "medium"),
        ("repo:org/app:ref:refs/tags/v1", "github-tag", "medium"),
        ("repo:org/app:environment:prod", "github-environment", "medium"),
        ("repo:org@1/app@2:ref:refs/heads/main", "github-branch", "medium"),
        ("repo:org/app:pull-request", "github-other", "unknown"),
        (
            "repo:org/app:job_workflow_ref:org/app/.github/workflows/x.yml@refs/heads/main",
            "github-other",
            "unknown",
        ),
        ("org/app", "github-other", "unknown"),
    ],
)
def test_github_subjects(subject: str, kind: str, severity: str) -> None:
    t = fed.classify(GH, subject, AUD, str(TENANT))
    assert (t.kind, t.severity) == (kind, severity)
    assert t.reasons and t.sources
    assert all(s.startswith("https://") for s in t.sources)


def test_a_managed_identity_in_this_tenant_is_a_principal_not_an_outsider() -> None:
    issuer = f"https://login.microsoftonline.com/{TENANT}/v2.0"
    t = fed.classify(issuer, pid(105).upper(), AUD, str(TENANT))
    assert t.kind == "entra-principal" and t.principal == pid(105)


def test_another_tenant_or_a_non_guid_subject_is_unknown() -> None:
    other = f"https://login.microsoftonline.com/{pid(2)}/v2.0"
    assert fed.classify(other, pid(105), AUD, str(TENANT)).kind == "external-issuer"
    mine = f"https://login.microsoftonline.com/{TENANT}/v2.0"
    assert fed.classify(mine, "someone", AUD, str(TENANT)).principal is None


def test_a_null_subject_is_a_claims_expression_and_never_safe() -> None:
    t = fed.classify(GH, None, AUD, str(TENANT))
    assert (t.kind, t.severity) == ("flexible-expression", "unknown")


def test_an_unknown_issuer_is_unknown() -> None:
    t = fed.classify(
        "https://gitlab.com", "project_path:g/p:ref_type:branch:ref:main", AUD, str(TENANT)
    )
    assert (t.kind, t.severity) == ("external-issuer", "unknown")


@given(st.text(max_size=200), st.one_of(st.none(), st.text(max_size=200)))
def test_classify_never_raises_and_never_says_safe(issuer: str, subject: str | None) -> None:
    t = fed.classify(issuer, subject, AUD, str(TENANT))
    assert t.severity in {"high", "medium", "unknown"}
    assert t.party and t.reasons
