"""Contract version 2: must_not_reach on one application or service principal."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from fns.contain import semantics as sem
from fns.contain.evaluate import evaluate
from fns.fixtures import wellknown as wk
from fns.models.contract import Contract
from tests.contain.helpers import Snap, contract
from tests.factories import pid

AGENT = pid(100)
CREDS = "credentials/update"


def _one(snap: Snap, item: dict[str, object]) -> tuple[str, tuple[str, ...], str | None]:
    (o,) = evaluate(contract([item]), snap.build()).outcomes
    rule = o.paths[0].steps[-1].rule if o.paths else None
    return o.finding.verdict, o.finding.reasons, rule


def _world() -> tuple[Snap, str, str]:
    snap = Snap()
    snap.sp(100, "sp-agent")
    verifier_sp = snap.sp(110, "id-verifier")
    verifier_app = snap.app(111, "id-verifier", sp=verifier_sp)
    return snap, verifier_app, verifier_sp


def test_version_1_cannot_name_an_application() -> None:
    data = {
        "version": 1,
        "contract": "t",
        "assume_compromised": "sp:a",
        "must_not_reach": [{"application": "id-verifier", "operations": [CREDS]}],
    }
    with pytest.raises(ValidationError, match="need version: 2"):
        Contract.model_validate(data)
    assert Contract.model_validate({**data, "version": 2}).must_not_reach[0].target_key == (
        "application:id-verifier"
    )


def test_target_keys_keep_kinds_apart() -> None:
    c = contract(
        [
            {"application": "x", "operations": [CREDS]},
            {"service_principal": "x", "operations": [CREDS]},
        ]
    )
    assert [i.target_key for i in c.must_not_reach] == ["application:x", "service_principal:x"]


def test_ownership_without_a_graph_permission_is_not_reach_and_says_why() -> None:
    snap, app, _ = _world()
    snap.edge("owns", AGENT, app)
    verdict, reasons, _ = _one(snap, {"application": "id-verifier", "operations": [CREDS]})
    assert verdict == "inconclusive"
    assert any("owns id-verifier but holds neither" in r for r in reasons), reasons


def test_ownership_with_owned_by_reaches_that_object_only() -> None:
    snap, app, _ = _world()
    snap.app(120, "other-app")
    snap.edge("owns", AGENT, app).graph_perm(AGENT, sem.APP_READWRITE_OWNEDBY)
    assert _one(snap, {"application": "id-verifier", "operations": [CREDS]})[0] == "fail"
    assert _one(snap, {"application": "other-app", "operations": [CREDS]})[0] == "inconclusive"


def test_owning_the_application_covers_its_service_principal() -> None:
    snap, app, _ = _world()
    snap.edge("owns", AGENT, app).graph_perm(AGENT, sem.APP_READWRITE_OWNEDBY)
    verdict, _, rule = _one(snap, {"service_principal": "id-verifier", "operations": [CREDS]})
    assert (verdict, rule) == ("fail", "owned-object-permission")


def test_scoped_directory_role_counts_only_on_its_object() -> None:
    snap, _, _ = _world()
    other = snap.app(120, "other-app")
    snap.dir_role(AGENT, wk.APPLICATION_ADMINISTRATOR, scope=f"/{other}")
    assert _one(snap, {"application": "id-verifier", "operations": [CREDS]})[0] == "inconclusive"
    assert _one(snap, {"application": "other-app", "operations": [CREDS]})[0] == "fail"


def test_resolves_by_object_id_and_app_id() -> None:
    snap, app, _ = _world()
    snap.graph_perm(AGENT, sem.APP_READWRITE_ALL)
    assert _one(snap, {"application": app, "operations": [CREDS]})[0] == "fail"
    assert _one(snap, {"service_principal": pid(110 + 5000), "operations": [CREDS]})[0] == "fail"


def test_unresolved_or_ambiguous_target_is_not_assessed() -> None:
    snap, _, _ = _world()
    snap.app(130, "twin")
    snap.app(131, "twin")
    snap.graph_perm(AGENT, sem.APP_READWRITE_ALL)
    for name in ("twin", "no-such-app"):
        verdict, reasons, _ = _one(snap, {"application": name, "operations": [CREDS]})
        assert verdict == "inconclusive"
        assert any("ambiguous" in r or "not in the snapshot" in r for r in reasons), reasons


def test_unknown_operation_on_an_object_is_not_assessed() -> None:
    snap, _, _ = _world()
    verdict, reasons, _ = _one(snap, {"application": "id-verifier", "operations": ["delete"]})
    assert verdict == "inconclusive"
    assert any("unknown operation semantics" in r for r in reasons)
