"""``lab/scope.tf`` with ``enable_strikes``: the strike block matches ``fns.strike``.

Terraform is not run here (``uv run poe lab-check`` validates it). These tests read
the ``.tf`` and template text, render the template the way Terraform would with
placeholder IDs, and load the result as a scope manifest.
"""

from __future__ import annotations

import re
from datetime import timedelta

from fns.models.operations import WRITE_FORM_OPERATIONS
from fns.models.scope import parse_scope
from fns.scope.writes import MARKER_DESCRIPTION, MARKER_NAME_PREFIX, MARKER_VALUE
from fns.strike.reader import OP_ASSIGNED_TO, OP_SERVICE_PRINCIPALS
from fns.strike.strikes import USED_FORMS, lab_targets
from tests.factories import NOW, SP_AGENT
from tests.scope.writekit import APP_ESC, APP_SCOUT, APP_VER, MARKER, PAYROLL, SP_ESC, VAULT
from tests.test_lab import LAB, STRIKE_IF, _render_template, _scope_tf_operations

STRIKE_OPS_BLOCK = "%{ for op in strike_operations ~}\n    - ${op}\n%{ endfor ~}\n"
ARM_BLOCK = "%{ for id in strike_arm_targets ~}\n    - kind: arm\n      id: ${id}\n%{ endfor ~}\n"
APP_BLOCK = (
    "%{ for app in strike_app_targets ~}\n"
    "    - kind: graph-application\n"
    "      id: ${app.id}\n"
    "      display_name: ${app.display_name}\n"
    "%{ endfor ~}\n"
)
SCOUT_BLOCK = "%{ for op in strike_scout_operations ~}\n    - ${op}\n%{ endfor ~}\n"
APPS = ((APP_ESC, "app-escalation-target"), (APP_VER, "id-verifier"), (APP_SCOUT, "sp-fns-scout"))
ESCALATION = {
    "service_principal": SP_ESC,
    "application": APP_ESC,
    "display_name": "app-escalation-target",
    "marker_role_id": MARKER["id"],
}


def _text(name: str) -> str:
    return (LAB / name).read_text(encoding="utf-8")


def _local_list(name: str) -> str:
    m = re.search(rf"^  {name} = \[\n(.*?)^  \]", _text("scope.tf"), re.M | re.S)
    assert m is not None, name
    return m[1]


def strike_operations() -> list[str]:
    return re.findall(r'"([^"]+)"', _local_list("strike_operations"))


def strike_scout_operations() -> list[str]:
    return re.findall(r'"([^"]+)"', _local_list("strike_scout_operations"))


def render_with_strikes() -> str:
    t = _text("scope.lab.yaml.tftpl")
    for block in (STRIKE_OPS_BLOCK, ARM_BLOCK, APP_BLOCK, SCOUT_BLOCK):
        assert block in t
    t = t.replace(STRIKE_OPS_BLOCK, "".join(f"    - {op}\n" for op in strike_operations()))
    t = t.replace(SCOUT_BLOCK, "".join(f"    - {op}\n" for op in strike_scout_operations()))
    for key, value in ESCALATION.items():
        t = t.replace("${strike_escalation." + key + "}", value)
    t = t.replace(ARM_BLOCK, "".join(f"    - kind: arm\n      id: {i}\n" for i in (PAYROLL, VAULT)))
    t = t.replace(
        APP_BLOCK,
        "".join(
            f"    - kind: graph-application\n      id: {i}\n      display_name: {n}\n"
            for i, n in APPS
        ),
    )
    t = re.sub(r"%\{ (if enable_strikes|endif) ~\}\n", "", t)
    t = t.replace("${strike_expires_at}", (NOW + timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    return _render_template(t, _scope_tf_operations())


def test_off_by_default() -> None:
    m = re.search(r'variable "enable_strikes" \{(.*?)\n\}', _text("variables.tf"), re.S)
    assert m is not None and "default     = false" in m[1]
    assert re.search(
        r'resource "time_offset" "strike_expiry" \{\n  count = var\.enable_strikes \? 1 : 0',
        _text("scope.tf"),
    )
    assert len(STRIKE_IF.findall(_text("scope.lab.yaml.tftpl"))) == 3
    assert re.search(
        r'resource "random_uuid" "strike_marker" \{\n  count = var\.enable_strikes \? 1 : 0',
        _text("identities.tf"),
    )


def test_the_rendered_operations_are_exactly_what_the_strikes_use() -> None:
    assert strike_operations() == list(USED_FORMS)
    assert set(USED_FORMS) <= set(WRITE_FORM_OPERATIONS)
    # The marker role is Terraform's (approved 2026-11-27): no strike patches app roles.
    assert set(WRITE_FORM_OPERATIONS) - set(USED_FORMS) == {"graph:PATCH /applications/{id}"}
    assert strike_scout_operations() == [OP_ASSIGNED_TO]
    assert OP_SERVICE_PRINCIPALS in _scope_tf_operations()


def test_targets_are_the_lab_objects_by_terraform_reference() -> None:
    arm = _local_list("strike_arm_targets")
    assert re.findall(r"(azurerm_\w+\.\w+)\.id", arm) == [
        "azurerm_storage_account.payroll",
        "azurerm_storage_account.invoices",  # D-7 (approved 2026-11-27)
        "azurerm_key_vault.crown_jewels",
    ]
    apps = _local_list("strike_app_targets")
    refs = re.findall(
        r"id = (azuread_application\.\w+)\.object_id, "
        r"display_name = (azuread_application\.\w+)\.display_name",
        apps,
    )
    assert refs == [
        ("azuread_application.escalation_target", "azuread_application.escalation_target"),
        ("azuread_application.verifier", "azuread_application.verifier"),
        ("azuread_application.scout", "azuread_application.scout"),
    ]
    assert "billing_agent" not in arm + apps  # never the agent itself
    assert "azuread_service_principal" not in apps  # the one SP target is S4's, below
    esc = re.search(r"^  strike_escalation = \{\n(.*?)^  \}", _text("scope.tf"), re.M | re.S)
    assert esc is not None
    assert re.findall(r"^    (\w+)\s+= (.+)$", esc[1], re.M) == [
        ("service_principal", "azuread_service_principal.escalation_target.object_id"),
        ("application", "azuread_application.escalation_target.object_id"),
        ("display_name", "azuread_application.escalation_target.display_name"),
        ("marker_role_id", 'var.enable_strikes ? random_uuid.strike_marker[0].result : ""'),
    ]


def test_the_marker_role_is_terraforms_and_grants_nothing() -> None:
    app = re.search(
        r'resource "azuread_application" "escalation_target" \{(.*?)\n\}',
        _text("identities.tf"),
        re.S,
    )
    assert app is not None
    role = re.search(
        r'dynamic "app_role" \{\n\s+for_each = random_uuid\.strike_marker\n(.*?)\n    \}',
        app[1],
        re.S,
    )
    assert role is not None
    fields = dict(re.findall(r"^\s+(\w+)\s+= (.+)$", role[1], re.M))
    assert fields == {
        "id": "app_role.value.result",
        "value": f'"{MARKER_VALUE}"',
        "display_name": f'"{MARKER_NAME_PREFIX}"',
        "description": f'"{MARKER_DESCRIPTION}"',
        "allowed_member_types": '["Application"]',
        "enabled": "true",
    }
    others = re.sub(r'dynamic "app_role" \{.*', "", _text("identities.tf"), flags=re.S)
    assert "app_role {" not in others  # no other app role anywhere in the lab


def test_rendered_with_strikes_is_a_valid_manifest_the_engine_accepts() -> None:
    m = parse_scope(render_with_strikes(), now=NOW)
    assert set(m.allowed_operations) == {"scout", "prove", "strike"}
    assert m.strike is not None and m.strike.expires_at == NOW + timedelta(hours=4)
    t = lab_targets(m)
    assert (t.agent, t.payroll, t.vault) == (SP_AGENT, PAYROLL, VAULT)
    assert (t.escalation_app, t.verifier_app, t.scout_app) == (APP_ESC, APP_VER, APP_SCOUT)
    assert t.escalation_sp is None  # S4's roles only when S4 is planned
    s4 = lab_targets(m, s4=True)
    assert (s4.escalation_sp, s4.marker_role) == (SP_ESC, MARKER["id"])
    assert m.strike.escalation is not None
    # the scout can make every read the strikes need with the same scope
    scout = set(m.allowed_operations["scout"])
    for op in (
        "arm:Microsoft.Storage/storageAccounts/read",
        "arm:Microsoft.KeyVault/vaults/read",
        "graph:GET /applications",
        "graph:GET /applications/{id}/owners",
        OP_SERVICE_PRINCIPALS,
        OP_ASSIGNED_TO,
    ):
        assert op in scout
