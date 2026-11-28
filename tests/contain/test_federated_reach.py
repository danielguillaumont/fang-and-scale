"""Federated identity credentials in the reach model (queue item 2, pending review).

- A credential that trusts a managed identity of this tenant is reach: whoever
  controls the managed identity signs in as the application (closure rule).
- A credential an outside party can satisfy (GitHub, another issuer, a claims
  expression) is a *front door*: it is reported, and changes no verdict.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from io import StringIO
from typing import Any

from rich.console import Console

from fns.console import THEME
from fns.contain import federation as fed
from fns.contain.closure import Closure, SnapshotIndex, controls
from fns.contain.evaluate import evaluate
from fns.contain.report import build_report
from fns.report.contain_text import render_contain
from tests.contain.helpers import KV, RG, VM, Snap, contract
from tests.factories import TENANT, pid

AGENT, TARGET_SP, TARGET_APP, MI = pid(100), pid(101), pid(102), pid(104)
ENTRA = f"https://login.microsoftonline.com/{TENANT}/v2.0"
SECRET_GET = {"resource": "kv-crown", "operations": ["secrets/get"]}


def _base() -> Snap:
    s = Snap()
    s.sp(100, "sp-agent")
    s.app(110, "sp-agent", sp=AGENT)
    s.sp(101, "app-target")
    s.app(102, "app-target", sp=TARGET_SP)
    return s


def _mi_reachable(s: Snap) -> Snap:
    """The agent runs code on a VM and so acts as its managed identity."""
    s.resource(VM, "Microsoft.Compute/virtualMachines")
    s.entity(MI, "managedIdentity", "mi-batch")
    s.edge("hasIdentity", VM, MI)
    return s.rbac(AGENT, "Virtual Machine Contributor", RG)


def _closure(s: Snap) -> Closure:
    return Closure(SnapshotIndex(s.build()), AGENT)


# --- the closure rule -----------------------------------------------------------------------


def test_a_trusted_managed_identity_signs_in_as_the_application() -> None:
    s = _mi_reachable(_base()).fic(TARGET_APP, ENTRA, MI, name="trust-batch")
    c = _closure(s)
    assert c.has(controls(TARGET_SP))
    d = c.derivations[controls(TARGET_SP)]
    assert d.rule == "federated-credential"
    assert "trust-batch" in d.text and "signs in as app-target" in d.text
    assert any(src.startswith("federatedIdentityCredential: trust-batch") for src in d.sources)


def test_no_reach_without_control_of_the_managed_identity() -> None:
    s = _base()
    s.entity(MI, "managedIdentity", "mi-batch")
    assert not _closure(s.fic(TARGET_APP, ENTRA, MI)).has(controls(TARGET_SP))


def test_a_subject_that_is_not_a_managed_identity_adds_nothing() -> None:
    """Only user-assigned managed identities can be a credential (Learn)."""
    s = _base().fic(TARGET_APP, ENTRA, AGENT)
    assert not _closure(s).has(controls(TARGET_SP))


def test_another_tenant_issuer_adds_no_reach() -> None:
    other = f"https://login.microsoftonline.com/{pid(2)}/v2.0"
    s = _mi_reachable(_base()).fic(TARGET_APP, other, MI)
    assert not _closure(s).has(controls(TARGET_SP))


def test_another_audience_is_left_open_not_assumed() -> None:
    s = _mi_reachable(_base()).fic(TARGET_APP, ENTRA, MI, audiences=("api://other",))
    c = _closure(s)
    assert not c.has(controls(TARGET_SP))
    assert any("api://other" in u and "not modeled" in u for u in c.uncertain)


def test_reach_through_a_federated_credential_fails_the_contract() -> None:
    s = _mi_reachable(_base()).fic(TARGET_APP, ENTRA, MI)
    s.kv(enableRbacAuthorization=True)
    s.rbac(TARGET_SP, "Key Vault Secrets Officer", KV)
    ev = evaluate(contract([SECRET_GET]), s.build())
    (outcome,) = ev.outcomes
    assert outcome.finding.verdict == "fail"
    rules = [step.rule for step in outcome.paths[0].steps]
    assert "managed-identity" in rules and "federated-credential" in rules


# --- front doors ----------------------------------------------------------------------------


def _report(s: Snap) -> tuple[str, dict[str, Any]]:
    s.kv(enableRbacAuthorization=True)
    r = build_report(
        evaluate(contract([SECRET_GET]), s.build()),
        generated_at=datetime(2026, 11, 28, tzinfo=UTC),
        tool_version="test",
    )
    buf = StringIO()
    render_contain(r, Console(file=buf, width=240, color_system=None, theme=THEME))
    return buf.getvalue(), json.loads(r.canonical_json())


def test_an_outside_party_on_the_compromised_identity_is_a_front_door() -> None:
    s = _base().fic(pid(110), fed.GITHUB_ISSUER, "repo:org/agent:pull_request", name="gh-pr")
    text, doc = _report(s)
    (door,) = doc["front_doors"]
    assert door["severity"] == "high" and door["kind"] == "github-pull-request"
    assert door["identity"] == AGENT and door["credential"] == "gh-pr"
    assert "Front doors" in text and "any workflow run for a pull request in org/agent" in text


def test_front_doors_cover_identities_the_attacker_reaches() -> None:
    s = _base().edge("owns", AGENT, TARGET_APP).graph_perm(AGENT, "Application.ReadWrite.OwnedBy")
    s.fic(TARGET_APP, fed.GITHUB_ISSUER, "repo:org/target:environment:prod")
    _, doc = _report(s)
    (door,) = doc["front_doors"]
    assert door["identity"] == TARGET_SP and door["severity"] == "medium"


def test_front_doors_change_no_verdict_and_are_omitted_when_empty() -> None:
    plain = _base()
    with_door = _base().fic(pid(110), fed.GITHUB_ISSUER, "repo:org/agent:pull_request")
    _, a = _report(plain)
    _, b = _report(with_door)
    assert "front_doors" not in a
    assert a["findings"] == b["findings"] and a["summary"] == b["summary"]


def test_an_unreached_identity_is_not_a_front_door() -> None:
    s = _base().fic(TARGET_APP, fed.GITHUB_ISSUER, "repo:org/target:pull_request")
    _, doc = _report(s)
    assert "front_doors" not in doc


def test_a_trusted_managed_identity_is_not_listed_as_an_outsider() -> None:
    s = _mi_reachable(_base()).fic(pid(110), ENTRA, MI)
    _, doc = _report(s)
    assert "front_doors" not in doc
