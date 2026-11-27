"""The Terraform lab's rendered scope must stay in sync with the collector.

Terraform itself is validated in CI (``terraform validate``); these tests
check the contract between the two halves without needing Terraform.
"""

from __future__ import annotations

import re
from pathlib import Path

from fns.adapters.azure import arm, graph
from fns.models.operations import parse_operation
from fns.models.scope import parse_scope
from fns.probes.data_read import METADATA_READ, SYNTHETIC_TAG
from fns.probes.permissions import OPERATION as PERMISSIONS_OP
from tests.factories import NOW, RG, SP_AGENT, SUB, TENANT

LAB = Path(__file__).resolve().parents[1] / "lab"
FOR_BLOCK = "%{ for op in operations ~}\n    - ${op}\n%{ endfor ~}\n"
PROVE_BLOCK = "%{ for op in prove_operations ~}\n    - ${op}\n%{ endfor ~}\n"
STRIKE_IF = re.compile(r"%\{ if enable_strikes ~\}\n.*?%\{ endif ~\}\n", re.S)
OBJECTS_BLOCK = (
    "%{ for obj in data_objects ~}\n"
    "  - resource: ${obj.resource}\n"
    "    operation: ${obj.operation}\n"
    "%{ endfor ~}\n"
)
AGENT_APP = "00000000-0000-4000-8000-000000000907"
VAULT = f"{RG}/providers/Microsoft.KeyVault/vaults/kv-crown-x"
PAYROLL = f"{RG}/providers/Microsoft.Storage/storageAccounts/stpayrollx"
INVOICES = f"{RG}/providers/Microsoft.Storage/storageAccounts/stinvoicesx"


def _scope_tf_operations() -> list[str]:
    text = (LAB / "scope.tf").read_text(encoding="utf-8")
    block = re.search(r"scout_operations = \[(.*?)\]", text, re.S)
    assert block is not None
    return re.findall(r'"([^"]+)"', block.group(1))


def _resource_names() -> dict[str, str]:
    """Literal names of the lab's secret, containers and blobs (resources.tf)."""
    text = (LAB / "resources.tf").read_text(encoding="utf-8")
    out: dict[str, str] = {}
    for kind, name in (
        ("azurerm_key_vault_secret", "payroll_db"),
        ("azurerm_storage_container", "payroll"),
        ("azurerm_storage_container", "invoices"),
        ("azurerm_storage_blob", "payroll"),
        ("azurerm_storage_blob", "invoice"),
    ):
        block = re.search(rf'resource "{kind}" "{name}" \{{(.*?)\n\}}', text, re.S)
        assert block is not None, (kind, name)
        found = re.search(r'^\s*name\s*=\s*"([^"]+)"', block.group(1), re.M)
        assert found is not None, (kind, name)
        out[f"{kind}.{name}.name"] = found.group(1)
    return out


def _prove_operations() -> tuple[list[str], list[tuple[str, str]]]:
    """``prove_operations`` and ``data_objects`` from scope.tf, references resolved."""
    text = (LAB / "scope.tf").read_text(encoding="utf-8")
    names = _resource_names()

    def resolve(s: str) -> str:
        return re.sub(r"\$\{([\w.]+)\}", lambda m: names[m.group(1)], s)

    local_ops = {k: resolve(v) for k, v in re.findall(r'^\s*(\w+_op)\s*=\s*"([^"]+)"', text, re.M)}
    block = re.search(r"prove_operations = \[(.*?)\]", text, re.S)
    assert block is not None
    ops: list[str] = []
    for item in re.findall(r'"([^"]+)"|local\.(\w+)', block.group(1)):
        ops.append(resolve(item[0]) if item[0] else local_ops[item[1]])
    resources = {
        "azurerm_key_vault.crown_jewels.id": VAULT,
        "azurerm_storage_account.payroll.id": PAYROLL,
        "azurerm_storage_account.invoices.id": INVOICES,
    }
    objects = [
        (resources[r], local_ops[o])
        for r, o in re.findall(r"resource = ([\w.]+), operation = local\.(\w+)", text)
    ]
    return ops, objects


def _render(operations: list[str]) -> str:
    template = (LAB / "scope.lab.yaml.tftpl").read_text(encoding="utf-8")
    # enable_strikes = false (the default): Terraform drops the strike blocks.
    # tests/test_lab_strikes.py renders them switched on.
    return _render_template(STRIKE_IF.sub("", template), operations)


def _render_template(template: str, operations: list[str]) -> str:
    prove_ops, objects = _prove_operations()
    for block in (FOR_BLOCK, PROVE_BLOCK, OBJECTS_BLOCK):
        assert block in template
    text = template.replace(FOR_BLOCK, "".join(f"    - {op}\n" for op in operations))
    text = text.replace(PROVE_BLOCK, "".join(f"    - {op}\n" for op in prove_ops))
    text = text.replace(
        OBJECTS_BLOCK,
        "".join(f"  - resource: {r}\n    operation: {o}\n" for r, o in objects),
    )
    values = {
        "tenant_id": TENANT,
        "subscription_id": SUB,
        "resource_group": RG,
        "agent_object_id": SP_AGENT,
        "agent_app_id": AGENT_APP,
        "expires_at": "2026-12-02T12:00:00Z",
    }
    for key, value in values.items():
        text = text.replace("${" + key + "}", value)
    assert "${" not in text and "%{" not in text
    return text


def test_lab_operations_match_the_collector_catalogue() -> None:
    assert _scope_tf_operations() == [
        *arm.ARM_OPERATIONS,
        *arm.SETTINGS_OPERATIONS,
        *arm.PIM_OPERATIONS,
        *graph.GRAPH_OPERATIONS,
        *graph.PIM_OPERATIONS,
    ]


def test_rendered_scope_is_a_valid_read_only_manifest() -> None:
    manifest = parse_scope(_render(_scope_tf_operations()), now=NOW)
    assert set(manifest.allowed_operations) == {"scout", "prove"}
    assert [str(i.object_id) for i in manifest.test_identities] == [SP_AGENT]
    assert [str(i.app_id) for i in manifest.test_identities] == [AGENT_APP]
    ops = [parse_operation(op) for ops in manifest.allowed_operations.values() for op in ops]
    assert all(op.is_read for op in ops)


def test_prove_scope_matches_what_the_probes_send() -> None:
    """Every operation the live probes need, and nothing more, bound to its resource."""
    manifest = parse_scope(_render(_scope_tf_operations()), now=NOW)
    names = _resource_names()
    secret = names["azurerm_key_vault_secret.payroll_db.name"]
    pay = (
        names["azurerm_storage_container.payroll.name"],
        names["azurerm_storage_blob.payroll.name"],
    )
    inv = (
        names["azurerm_storage_container.invoices.name"],
        names["azurerm_storage_blob.invoice.name"],
    )
    expected = {
        PERMISSIONS_OP,
        METADATA_READ,
        "kv:GET /secrets",
        f"kv:GET /secrets/{secret}",
        f"blob:HEAD /{pay[0]}/{pay[1]}",
        f"blob:HEAD /{inv[0]}/{inv[1]}",
    }
    assert set(manifest.allowed_operations["prove"]) == expected
    bound = {(d.resource.lower(), d.operation) for d in manifest.data_objects}
    assert bound == {
        (VAULT.lower(), f"kv:GET /secrets/{secret}"),
        (PAYROLL.lower(), f"blob:HEAD /{pay[0]}/{pay[1]}"),
        (INVOICES.lower(), f"blob:HEAD /{inv[0]}/{inv[1]}"),
    }


def test_the_probed_secret_is_tagged_synthetic() -> None:
    """V6: the probe reads the secret only if its metadata says it is synthetic."""
    text = (LAB / "resources.tf").read_text(encoding="utf-8")
    block = re.search(r'resource "azurerm_key_vault_secret" "payroll_db" \{(.*?)\n\}', text, re.S)
    assert block is not None
    key, value = SYNTHETIC_TAG
    assert f'"{key}" = "{value}"' in block.group(1)
    assert "random_password.synthetic_secret.result" in block.group(1)


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


def test_rendered_lab_contract_matches_the_example_and_validates() -> None:
    """D5: the lab contract is the example contract with the lab's real names."""
    from fns.models.contract import Contract, load_contract
    from fns.yamlio import loads_yaml

    text = (LAB / "contract.lab.fns.yaml.tftpl").read_text(encoding="utf-8")
    names = {
        "agent": "sp-billing-agent",
        "vault": "kv-crown-jewels",
        "payroll": "st-payroll",
        "invoices": "st-invoices",
        "verifier": "id-verifier",
        "scout": "sp-fns-scout",
    }
    for key, value in names.items():
        text = text.replace("${" + key + "}", value)
    assert "${" not in text
    rendered = Contract.model_validate(loads_yaml(text))
    example = load_contract(LAB.parent / "contracts" / "examples" / "billing-agent.fns.yaml")
    assert rendered == example


def test_lab_contract_tf_references_real_resources() -> None:
    tf = (LAB / "contract.tf").read_text(encoding="utf-8")
    resources = (LAB / "resources.tf").read_text(encoding="utf-8")
    identities = (LAB / "identities.tf").read_text(encoding="utf-8")
    for ref in ("crown_jewels", "payroll", "invoices"):
        assert f'"{ref}"' in resources, ref
        assert ref in tf
    assert 'resource "azuread_application" "billing_agent"' in identities


EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")


def test_the_budget_is_opt_in_and_its_email_lives_only_in_tfvars() -> None:
    """M4 D7: no address in a committed file; no budget unless one is set."""
    budget = (LAB / "budget.tf").read_text(encoding="utf-8")
    blocks = re.findall(r'^resource "(\w+)" "(\w+)" \{(.*?)\n\}', budget, re.S | re.M)
    assert {(k, n) for k, n, _ in blocks} == {
        ("time_static", "budget_start"),
        ("azurerm_consumption_budget_subscription", "lab"),
    }
    for _, _, body in blocks:
        assert "count = local.budget_enabled ? 1 : 0" in body
    assert 'budget_enabled = var.budget_alert_email != ""' in budget
    variables = (LAB / "variables.tf").read_text(encoding="utf-8")
    var = re.search(r'variable "budget_alert_email" \{(.*?)\n\}', variables, re.S)
    assert var is not None
    assert 'default     = ""' in var.group(1)
    assert "sensitive   = true" in var.group(1)
    committed = [*LAB.glob("*.tf"), *LAB.glob("*.tftpl"), LAB / "terraform.tfvars.example"]
    for path in committed:
        for address in EMAIL.findall(path.read_text(encoding="utf-8")):
            assert address.endswith("@example.invalid"), (path.name, address)


def test_the_budget_alerts_at_half_full_and_forecast() -> None:
    budget = (LAB / "budget.tf").read_text(encoding="utf-8")
    notes = re.findall(
        r"threshold\s*=\s*(\d+)\s*\n\s*threshold_type\s*=\s*\"(\w+)\"\s*\n"
        r"\s*contact_emails\s*=\s*\[var\.budget_alert_email\]",
        budget,
    )
    assert sorted(notes) == [("100", "Actual"), ("100", "Forecasted"), ("50", "Actual")]
    assert 'time_grain      = "Monthly"' in budget
    assert 'subscription_id = "/subscriptions/${var.subscription_id}"' in budget
    variables = (LAB / "variables.tf").read_text(encoding="utf-8")
    assert re.search(r'variable "budget_amount" \{[^}]*default\s*=\s*10\b', variables, re.S)
