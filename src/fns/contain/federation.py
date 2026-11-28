"""Who can satisfy a federated identity credential (queue item 2, pending review).

A federated identity credential (FIC) on an application lets whoever presents a
token from ``issuer`` with this ``subject`` and one of the ``audiences`` sign in
as the application's service principal. The values must match the token exactly
and case-sensitively, and wildcards are not supported (Microsoft Learn,
"Workload identity federation" and "Configure an app to trust an external
identity provider", read 2026-11-28).

:func:`classify` names that party and how wide it is. Nothing is inferred beyond
the subject's documented shape: an issuer or subject form not listed here is
``unknown``, which the report says, never "safe".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Literal

from fns.models.armid import GUID_RE

GITHUB_ISSUER: Final = "https://token.actions.githubusercontent.com"
TOKEN_EXCHANGE_AUDIENCE: Final = "api://AzureADTokenExchange"  # noqa: S105 - an audience URI
ENTRA_ISSUER: Final = re.compile(
    r"^https://login\.microsoftonline\.com/(?P<tenant>[0-9a-f-]{36})/v2\.0$"
)

LEARN_FEDERATION: Final = (
    "https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation"
)
LEARN_CREATE_TRUST: Final = (
    "https://learn.microsoft.com/en-us/entra/workload-id/"
    "workload-identity-federation-create-trust?pivots=identity-wif-apps-methods-azp"
)
LEARN_FLEXIBLE: Final = (
    "https://learn.microsoft.com/en-us/entra/workload-id/"
    "workload-identities-flexible-federated-identity-credentials"
)
LEARN_MI_TRUST: Final = (
    "https://learn.microsoft.com/en-us/entra/workload-id/"
    "workload-identity-federation-config-app-trust-managed-identity"
)
GITHUB_OIDC: Final = "https://docs.github.com/en/actions/reference/security/oidc"
GITHUB_SYNTAX: Final = (
    "https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions"
)

Kind = Literal[
    "entra-principal",
    "github-pull-request",
    "github-branch",
    "github-tag",
    "github-environment",
    "github-other",
    "flexible-expression",
    "external-issuer",
]
Severity = Literal["high", "medium", "unknown"]

_GITHUB_SUB: Final = re.compile(r"^repo:(?P<repo>[^:]+):(?P<rest>.+)$")


@dataclass(frozen=True, slots=True)
class Trust:
    kind: Kind
    severity: Severity
    party: str
    """Who can present a matching token, in words."""
    reasons: tuple[str, ...]
    sources: tuple[str, ...]
    principal: str | None = None
    """For ``entra-principal``: the object ID that can sign in as the application."""


def classify(issuer: str, subject: str | None, audiences: tuple[str, ...], tenant: str) -> Trust:
    aud = ", ".join(audiences) or "none"
    entra = ENTRA_ISSUER.fullmatch(issuer)
    if subject is None:
        return Trust(
            "flexible-expression",
            "unknown",
            f"tokens from {issuer} matching a claims expression",
            (
                "the subject is null, so the credential matches a claims expression "
                "(flexible federated identity credential, preview), which Graph v1.0 does "
                "not return; it can use * and ? wildcards on the subject",
            ),
            (LEARN_FLEXIBLE,),
        )
    if entra is not None:
        if entra["tenant"].lower() == tenant.lower() and GUID_RE.fullmatch(subject):
            return Trust(
                "entra-principal",
                "medium",
                f"whoever controls the managed identity {subject.lower()}",
                (
                    "issuer is this tenant and subject is a managed identity's object ID: "
                    "that identity exchanges its token for one of this application",
                    f"audiences: {aud}",
                ),
                (LEARN_MI_TRUST,),
                principal=subject.lower(),
            )
        return Trust(
            "external-issuer",
            "unknown",
            f"identities of tenant {entra['tenant']} with subject {subject}",
            ("issuer is another Entra tenant, or the subject is not an object ID",),
            (LEARN_FEDERATION,),
        )
    if issuer != GITHUB_ISSUER:
        return Trust(
            "external-issuer",
            "unknown",
            f"anyone who can get a token from {issuer} with subject {subject}",
            (
                "an issuer the model does not know: who can obtain a matching token "
                "depends on that provider",
            ),
            (LEARN_FEDERATION,),
        )
    m = _GITHUB_SUB.fullmatch(subject)
    if m is None:
        return Trust(
            "github-other",
            "unknown",
            f"GitHub Actions runs with subject {subject}",
            ("not one of GitHub's default subject formats (a customised subject claim)",),
            (GITHUB_OIDC,),
        )
    repo, rest = m["repo"], m["rest"]
    if rest == "pull_request":
        return Trust(
            "github-pull-request",
            "high",
            f"any workflow run for a pull request in {repo}",
            (
                "GitHub puts pull_request in the subject of every run triggered by a "
                "pull request event: whoever can open a pull request that runs a workflow "
                "can sign in, whatever its branch or review state",
                "branch protection and environment approvals do not apply to this subject",
            ),
            (GITHUB_OIDC, LEARN_CREATE_TRUST),
        )
    if rest == "pull-request":
        return Trust(
            "github-other",
            "unknown",
            f"GitHub Actions runs with subject {subject}",
            (
                "the subject uses pull-request (hyphen), the form Microsoft Learn shows; "
                "GitHub documents pull_request (underscore), so this may match no token "
                "(FINDINGS 2026-11-28, not validated live)",
            ),
            (GITHUB_OIDC, LEARN_CREATE_TRUST),
        )
    if rest.startswith("ref:refs/heads/"):
        branch = rest.removeprefix("ref:refs/heads/")
        return Trust(
            "github-branch",
            "medium",
            f"any workflow run on branch {branch} of {repo} without an environment",
            (
                "whoever can push to (or merge into) the branch can sign in; branch "
                "protection is GitHub configuration the snapshot does not hold",
                "a pull_request_target run uses the base branch and gets a read/write "
                "token even from a public fork",
            ),
            (GITHUB_OIDC, GITHUB_SYNTAX),
        )
    if rest.startswith("ref:refs/tags/"):
        return Trust(
            "github-tag",
            "medium",
            f"any workflow run for tag {rest.removeprefix('ref:refs/tags/')} of {repo}",
            ("whoever can push that tag can sign in; tag protection is not in the snapshot",),
            (GITHUB_OIDC,),
        )
    if rest.startswith("environment:"):
        return Trust(
            "github-environment",
            "medium",
            f"any job in {repo} that references environment {rest.removeprefix('environment:')}",
            (
                "environment protection rules (reviewers, branch filters) decide who; they "
                "are GitHub configuration the snapshot does not hold",
            ),
            (GITHUB_OIDC,),
        )
    return Trust(
        "github-other",
        "unknown",
        f"GitHub Actions runs in {repo} with subject {subject}",
        ("not one of GitHub's default subject formats",),
        (GITHUB_OIDC,),
    )
