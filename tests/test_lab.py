"""The Terraform lab's rendered scope must stay in sync with the collector.

Terraform itself is validated in CI (``terraform validate``); these tests
check the contract between the two halves without needing Terraform.
"""

from __future__ import annotations

import re
from pathlib import Path

from fns.adapters.azure import arm, graph
from fns.models.scope import parse_scope
from tests.factories import NOW, RG, SP_AGENT, SUB, TENANT

LAB = Path(__file__).resolve().parents[1] / "lab"
FOR_BLOCK = "%{ for op in operations ~}\n    - ${op}\n%{ endfor ~}\n"


def _scope_tf_operations() -> list[str]:
    text = (LAB / "scope.tf").read_text(encoding="utf-8")
    block = re.search(r"scout_operations = \[(.*?)\]", text, re.S)
    assert block is not None
    return re.findall(r'"([^"]+)"', block.group(1))


def _render(operations: list[str]) -> str:
    template = (LAB / "scope.lab.yaml.tftpl").read_text(encoding="utf-8")
    assert FOR_BLOCK in template
    text = template.replace(FOR_BLOCK, "".join(f"    - {op}\n" for op in operations))
    values = {
        "tenant_id": TENANT,
        "subscription_id": SUB,
        "resource_group": RG,
        "agent_object_id": SP_AGENT,
        "expires_at": "2026-12-02T12:00:00Z",
    }
    for key, value in values.items():
        text = text.replace("${" + key + "}", value)
    assert "${" not in text and "%{" not in text
    return text


def test_lab_operations_match_the_collector_catalogue() -> None:
    assert _scope_tf_operations() == [*arm.ARM_OPERATIONS, *graph.GRAPH_OPERATIONS]


def test_rendered_scope_is_a_valid_read_only_manifest() -> None:
    manifest = parse_scope(_render(_scope_tf_operations()), now=NOW)
    assert set(manifest.allowed_operations) == {"scout"}
    assert [str(i.object_id) for i in manifest.test_identities] == [SP_AGENT]


def test_lab_never_creates_credentials() -> None:
    """Rule 6: no secrets. The scout signs in via the Azure CLI or GitHub OIDC."""
    text = "\n".join(p.read_text(encoding="utf-8") for p in sorted(LAB.glob("*.tf")))
    for resource in (
        "azuread_application_password",
        "azuread_service_principal_password",
        "azuread_application_certificate",
        "azuread_service_principal_certificate",
    ):
        assert resource not in text


def test_lab_pins_tenant_before_creating_anything() -> None:
    main = (LAB / "main.tf").read_text(encoding="utf-8")
    assert "data.azurerm_client_config.current.tenant_id) == lower(var.tenant_id)" in main
    assert "data.azuread_client_config.current.tenant_id) == lower(var.tenant_id)" in main


def test_everything_is_tagged() -> None:
    text = "\n".join(p.read_text(encoding="utf-8") for p in sorted(LAB.glob("*.tf")))
    taggable = re.findall(
        r'resource "(azurerm_(?:resource_group|key_vault|storage_account)'
        r'|azuread_(?:application|service_principal))" "(\w+)" \{(.*?)\n\}',
        text,
        re.S,
    )
    assert len(taggable) >= 12
    for kind, name, body in taggable:
        assert re.search(r"\btags\s*=", body), f"{kind}.{name} is not tagged"
