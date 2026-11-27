"""The lab group (M4 D3): ``grp-<prefix>-billing`` with ``sp-billing-agent`` as its
only member and no roles. It gives ``/servicePrincipals/{id}/memberOf`` something
to return, and must not change what the agent can reach."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from fns.adapters.azure import graph
from fns.contain.evaluate import evaluate
from fns.inventory.builder import SnapshotBuilder
from fns.models.snapshot import Provenance, SnapshotCoverage
from tests.contain.helpers import RG, Snap, contract
from tests.factories import TENANT, pid

LAB = Path(__file__).resolve().parents[1] / "lab"
TF = {p.name: p.read_text(encoding="utf-8") for p in sorted(LAB.glob("*.tf"))}
ALL = "\n".join(TF.values())


def _group() -> str:
    m = re.search(r'resource "azuread_group" "billing" \{\n(.*?)^\}', TF["groups.tf"], re.M | re.S)
    assert m, "lab/groups.tf must define azuread_group.billing"
    return m[1]


def test_the_group_is_the_one_d3_asked_for() -> None:
    body = _group()
    assert re.search(r'display_name\s+= "grp-\$\{var\.prefix\}-billing"', body)
    assert re.search(r"security_enabled\s+= true", body)
    assert re.search(r"mail_enabled\s+= false", body)
    assert re.search(r"assignable_to_role = false", body)
    assert re.search(
        r"members\s+= \[azuread_service_principal\.billing_agent\.object_id\]", body
    ), "the agent is the only member"
    assert "project=fang-and-scale" in body and "purpose=lab" in body
    assert len(re.findall(r'^resource "azuread_group"', ALL, re.M)) == 1


def test_the_group_holds_no_roles() -> None:
    # Nothing outside groups.tf refers to the group: no RBAC, app role or directory role.
    for name, text in TF.items():
        if name != "groups.tf":
            assert "azuread_group.billing" not in text, name
    for kind in (
        "azuread_directory_role_assignment",
        "azuread_directory_role_member",
        "azuread_group_member",
        "azuread_group_role_management_policy",
        "azuread_privileged_access_group",
    ):
        assert kind not in ALL, kind


def test_the_scout_already_reads_member_of() -> None:
    assert f'"{graph.OP_SP_MEMBER_OF}",' in TF["scope.tf"]  # in the rendered scout operations


PROV = Provenance(source_api=graph.OP_SP_MEMBER_OF, observed_at=datetime(2026, 11, 27, tzinfo=UTC))


def test_a_lab_shaped_member_of_response_becomes_one_edge() -> None:
    b = SnapshotBuilder()
    agent, group = pid(100), pid(130)
    b.entity(agent, "servicePrincipal", display_name="sp-billing-agent")
    items = [
        {"@odata.type": "#microsoft.graph.group", "id": group, "displayName": "grp-fns-billing"}
    ]
    assert graph.parse_member_of(b, agent, items, PROV) == []
    snap = b.build(
        mode="FIXTURE",
        tenant_id=TENANT,
        collected_at=PROV.observed_at,
        collector_version="t",
        coverage=SnapshotCoverage(collectors=(), not_collected=()),
    )
    groups = [e for e in snap.entities if e.type == "group"]
    assert [(g.id, g.display_name) for g in groups] == [(group, "grp-fns-billing")]
    assert [(e.type, e.src, e.dst) for e in snap.edges] == [("memberOf", agent, group)]


def test_membership_of_a_group_with_no_roles_changes_no_verdict() -> None:
    def world(with_group: bool) -> Snap:
        s = Snap()
        s.sp(100, "sp-billing-agent")
        s.kv()
        s.rbac(pid(100), "Contributor", RG)
        if with_group:
            s.entity(pid(130), "group", "grp-fns-billing")
            s.edge("memberOf", pid(100), pid(130))
        return s

    c = contract([{"resource": "kv-crown", "operations": ["secrets/get", "secrets/list"]}])
    before = evaluate(c, world(False).build())
    after = evaluate(c, world(True).build())
    assert [o.finding.verdict for o in before.outcomes] == [
        o.finding.verdict for o in after.outcomes
    ]
    assert [o.finding.coverage for o in before.outcomes] == [
        o.finding.coverage for o in after.outcomes
    ]
