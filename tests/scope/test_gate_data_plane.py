"""Negative-first tests for the data-plane scope gate and principal pinning (M3 P5.1).

Every denial row also goes through :meth:`Gate.call` to prove the callable is never
invoked. The allow rows are the only data-plane calls the lab's prove scope makes.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from fns.models.operations import OperationError, parse_operation
from fns.models.scope import ScopeManifest
from fns.scope.gate import Allowed, Denied, DenyReason, FrozenClock, ScopeDeniedError
from fns.scope.targets import DirectoryTarget
from tests.factories import (
    LATER,
    NOW,
    OTHER_TENANT,
    RG,
    RG2,
    SP_AGENT,
    SP_VERIFIER,
    SUB,
    TENANT,
    scope_dict,
)
from tests.scope.gatekit import ARM_READ, make_gate

PERMS = "arm:Microsoft.Authorization/permissions/read"
VAULT = f"{RG}/providers/Microsoft.KeyVault/vaults/kv-crown-x"
VAULT2 = f"{RG}/providers/Microsoft.KeyVault/vaults/kv-other-x"
PAYROLL = f"{RG}/providers/Microsoft.Storage/storageAccounts/stpayrollx"
INVOICES = f"{RG}/providers/Microsoft.Storage/storageAccounts/stinvoicesx"
PAYROLL_RG2 = f"{RG2}/providers/Microsoft.Storage/storageAccounts/stpayrollx"
SECRET = "kv:GET /secrets/payroll-db-password"  # noqa: S105 - an operation
LIST = "kv:GET /secrets"
BLOB_PAY = "blob:HEAD /payroll/employees-SYNTHETIC.csv"
BLOB_INV = "blob:HEAD /invoices/invoice-0001-SYNTHETIC.json"
PROVE_OPS = [PERMS, LIST, SECRET, BLOB_PAY, BLOB_INV]
DATA_OBJECTS = [
    {"resource": VAULT, "operation": SECRET},
    {"resource": PAYROLL, "operation": BLOB_PAY},
    {"resource": INVOICES, "operation": BLOB_INV},
]
KV_URL = "https://kv-crown-x.vault.azure.net/secrets/payroll-db-password?api-version=7.4"
LIST_URL = "https://kv-crown-x.vault.azure.net/secrets?api-version=7.4"
PAY_URL = "https://stpayrollx.blob.core.windows.net/payroll/employees-SYNTHETIC.csv"
INV_URL = "https://stinvoicesx.blob.core.windows.net/invoices/invoice-0001-SYNTHETIC.json"
PERMS_URL = f"https://management.azure.com{VAULT}/providers/Microsoft.Authorization/permissions"


def prove_manifest(**overrides: Any) -> ScopeManifest:
    base = scope_dict(
        allowed_operations={"scout": [ARM_READ], "prove": list(PROVE_OPS)},
        data_objects=list(DATA_OBJECTS),
    )
    base.update(overrides)
    return ScopeManifest.model_validate(base)


M = prove_manifest()
# A forged manifest (never valid on load) that lists data-plane reads under every verb.
FORGED = ScopeManifest.model_construct(
    **{
        **M.__dict__,
        "allowed_operations": dict.fromkeys(
            ("scout", "contain", "harden", "molt", "strike"), (*PROVE_OPS, ARM_READ)
        ),
    }
)


@pytest.mark.parametrize(
    ("op", "target", "url"),
    [
        (SECRET, VAULT, KV_URL),
        (LIST, VAULT, LIST_URL),
        (BLOB_PAY, PAYROLL, PAY_URL),
        (BLOB_INV, INVOICES, INV_URL),
        (PERMS, VAULT, PERMS_URL + "?api-version=2022-04-01"),
    ],
)
def test_allowed_prove_calls(op: str, target: str, url: str) -> None:
    gate, _, _ = make_gate(M)
    decision = gate.check("prove", op, target, TENANT, url=url)
    assert isinstance(decision, Allowed), decision


R = DenyReason
ROWS: list[tuple[str, DenyReason, dict[str, Any]]] = [
    # --- verbs: the data plane is for prove only, whatever a manifest says ---
    *[
        (f"{op} under {verb}", R.DATA_PLANE_VERB_NOT_ALLOWED, {"m": FORGED, "verb": verb, "op": op})
        for verb in ("scout", "contain", "harden", "molt", "strike")
        for op in (SECRET, BLOB_PAY)
    ],
    # --- grammar: no write method exists for kv or blob ---
    *[
        (f"parse {op}", R.MALFORMED_OPERATION, {"op": op})
        for op in (
            "kv:PUT /secrets/payroll-db-password",
            "kv:DELETE /secrets/payroll-db-password",
            "kv:POST /secrets/payroll-db-password",
            "kv:GET /secrets/payroll-db-password/0123456789abcdef",
            "kv:GET /keys/k1",
            "kv:get /secrets",
            "blob:PUT /payroll/employees-SYNTHETIC.csv",
            "blob:GET /payroll/employees-SYNTHETIC.csv",
            "blob:DELETE /payroll/employees-SYNTHETIC.csv",
            "blob:HEAD /payroll/dir/employees.csv",
            "blob:HEAD /payroll/..",
            "blob:HEAD /Payroll/employees-SYNTHETIC.csv",
            "blob:HEAD /payroll",
        )
    ],
    ("other secret not listed", R.OPERATION_NOT_ALLOWED, {"op": "kv:GET /secrets/other"}),
    # --- targets ---
    ("blob op on a vault", R.TARGET_KIND_MISMATCH, {"op": BLOB_PAY, "target": VAULT}),
    ("kv op on an account", R.TARGET_KIND_MISMATCH, {"target": PAYROLL}),
    ("kv op on the RG", R.TARGET_KIND_MISMATCH, {"target": RG}),
    ("kv op on the directory", R.TARGET_KIND_MISMATCH, {"target": DirectoryTarget()}),
    ("kv op on a secret ID", R.TARGET_KIND_MISMATCH, {"target": VAULT + "/secrets/x"}),
    ("account in another RG", R.RG_NOT_ALLOWED, {"op": BLOB_PAY, "target": PAYROLL_RG2}),
    # --- binding: each object belongs to one resource ---
    (
        "payroll path on invoices",
        R.DATA_OBJECT_NOT_ALLOWED,
        {
            "op": BLOB_PAY,
            "target": INVOICES,
            "url": "https://stinvoicesx.blob.core.windows.net/payroll/employees-SYNTHETIC.csv",
        },
    ),
    (
        "secret on another vault",
        R.DATA_OBJECT_NOT_ALLOWED,
        {"target": VAULT2, "url": KV_URL.replace("kv-crown-x", "kv-other-x")},
    ),
    (
        "list on a vault without objects",
        R.DATA_OBJECT_NOT_ALLOWED,
        {"op": LIST, "target": VAULT2, "url": LIST_URL.replace("kv-crown-x", "kv-other-x")},
    ),
    # --- URL: exact host ---
    *[
        (f"host {url}", R.BAD_URL, {"url": url})
        for url in (
            KV_URL.replace("kv-crown-x", "kv-other-x"),
            KV_URL.replace("vault.azure.net", "vault.azure.net.example.com"),
            KV_URL.replace("kv-crown-x.", "kv-crown-x.evil."),
            KV_URL.replace("kv-crown-x", "KV-CROWN-X"),
            KV_URL.replace(".net/", ".net:443/"),
            KV_URL.replace(".net/", ".net./"),
            KV_URL.replace("https://", "https://user@"),
            KV_URL.replace("https://", "http://"),
            KV_URL.replace("vault.azure.net", "vault.azure.cn"),
            KV_URL.replace("vault.azure.net", "managedhsm.azure.net"),
            KV_URL.replace(".net/", ".net" + chr(0xA0) + "/"),
        )
    ],
    *[
        (f"blob host {url}", R.BAD_URL, {"op": BLOB_PAY, "target": PAYROLL, "url": url})
        for url in (
            PAY_URL.replace("blob.core", "dfs.core"),
            PAY_URL.replace("blob.core", "file.core"),
            PAY_URL.replace("blob.core", "queue.core"),
            PAY_URL.replace("stpayrollx", "stinvoicesx"),
            PAY_URL.replace("core.windows.net", "core.chinacloudapi.cn"),
        )
    ],
    # --- URL: exact path ---
    *[
        (f"path {url}", R.BAD_URL, {"url": url})
        for url in (
            KV_URL.replace("payroll-db-password", "payroll-db-password/0123abcd"),
            KV_URL.replace("payroll-db-password", "other"),
            KV_URL.replace("/secrets/", "/secrets/../secrets/"),
            KV_URL.replace("/secrets/", "/secrets%2F"),
            KV_URL.replace("?", "/?"),
            KV_URL.replace("/secrets/", "/keys/"),
        )
    ],
    *[
        (f"blob path {url}", R.BAD_URL, {"op": BLOB_PAY, "target": PAYROLL, "url": url})
        for url in (
            PAY_URL.replace("SYNTHETIC", "synthetic"),
            PAY_URL.replace("/payroll/", "/payroll//"),
            PAY_URL + "/",
            PAY_URL.replace("employees-SYNTHETIC.csv", "other.csv"),
        )
    ],
    # --- URL: exact query ---
    *[
        (f"kv query {url}", R.BAD_URL, {"url": url})
        for url in (
            KV_URL.replace("7.4", "7.5"),
            KV_URL.replace("?api-version=7.4", ""),
            KV_URL + "&maxresults=1",
            KV_URL.replace("api-version", "API-VERSION"),
            KV_URL + "#frag",
        )
    ],
    *[
        (f"blob query {url}", R.BAD_URL, {"op": BLOB_PAY, "target": PAYROLL, "url": url})
        for url in (
            PAY_URL + "?comp=list",
            PAY_URL + "?restype=container",
            PAY_URL + "?sv=2023-11-03&sig=abc",
            PAY_URL + "?snapshot=2026-01-01",
            PAY_URL + "?",
        )
    ],
    ("no url", R.BAD_URL, {"url": None}),
    ("paging", R.BAD_URL, {"op": LIST, "url": LIST_URL, "page_of": LIST_URL}),
    # --- principal pinning (V4) ---
    ("prove not signed in as anyone", R.PRINCIPAL_NOT_ALLOWED, {"signed_in_as": None}),
    ("prove as the verifier", R.PRINCIPAL_NOT_ALLOWED, {"signed_in_as": SP_VERIFIER}),
    ("claimed principal differs", R.PRINCIPAL_MISMATCH, {"principal": SP_VERIFIER}),
    (
        "permissions probe without a principal",
        R.PRINCIPAL_NOT_ALLOWED,
        {"op": PERMS, "url": PERMS_URL, "signed_in_as": None},
    ),
    # --- the usual checks still apply to the new APIs ---
    ("expired", R.EXPIRED, {"clock": FrozenClock(LATER)}),
    ("tenant", R.TENANT_MISMATCH, {"tenant": OTHER_TENANT}),
    (
        "budget",
        R.BUDGET_CALLS,
        {"m": prove_manifest(budget={"max_api_calls": 1, "max_minutes": 1}), "pre_calls": 1},
    ),
]


@pytest.mark.parametrize(("name", "reason", "kw"), ROWS, ids=[r[0] for r in ROWS])
def test_denied_and_never_called(name: str, reason: DenyReason, kw: dict[str, Any]) -> None:
    gate, journal, _ = make_gate(
        kw.get("m", M),
        clock=kw.get("clock", FrozenClock(NOW)),
        principal=kw.get("signed_in_as", SP_AGENT),
    )
    for _ in range(kw.get("pre_calls", 0)):
        gate.call("prove", SECRET, VAULT, TENANT, lambda: None, url=KV_URL)
    args = (kw.get("verb", "prove"), kw.get("op", SECRET), kw.get("target", VAULT))
    tenant = kw.get("tenant", TENANT)
    url = kw.get("url", KV_URL)
    decision = gate.check(*args, tenant, kw.get("principal"), url=url, page_of=kw.get("page_of"))
    assert isinstance(decision, Denied), decision
    assert decision.reason is reason, decision

    called: list[bool] = []
    with pytest.raises(ScopeDeniedError):
        gate.call(
            *args,
            tenant,
            lambda: called.append(True),
            url=url if isinstance(url, str) else "https://x.invalid/",
            principal_id=kw.get("principal"),
            page_of=kw.get("page_of"),
        )
    assert called == []
    assert journal.decisions[-1].decision == "denied"


DATA_REASONS = {r[1] for r in ROWS}


# --- the manifest refuses data-plane reads outside prove, and unbound objects ---


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        (
            {"allowed_operations": {"scout": [SECRET]}, "data_objects": []},
            "only under prove",
        ),
        (
            {"data_objects": [{"resource": PAYROLL, "operation": SECRET}]},
            "not a kv resource",
        ),
        (
            {"data_objects": [{"resource": VAULT, "operation": BLOB_PAY}]},
            "not a blob resource",
        ),
        ({"data_objects": [{"resource": VAULT, "operation": LIST}]}, "one secret or one blob"),
        ({"data_objects": [{"resource": VAULT, "operation": PERMS}]}, "one secret or one blob"),
        ({"data_objects": [{"resource": RG, "operation": SECRET}]}, "not a kv resource"),
        (
            {"data_objects": [{"resource": PAYROLL_RG2, "operation": BLOB_PAY}]},
            "outside allowed_resource_groups",
        ),
        (
            {"data_objects": [{"resource": VAULT, "operation": "kv:GET /secrets/unlisted"}]},
            "not listed under prove",
        ),
        (
            {"data_objects": [DATA_OBJECTS[0], {**DATA_OBJECTS[0], "resource": VAULT.upper()}]},
            "duplicate data object",
        ),
    ],
)
def test_manifest_rejects(overrides: dict[str, Any], match: str) -> None:
    with pytest.raises(ValidationError, match=match):
        prove_manifest(**overrides)


def test_manifest_without_data_objects_allows_no_data_plane_call() -> None:
    gate, _, _ = make_gate(prove_manifest(data_objects=[]))
    decision = gate.check("prove", SECRET, VAULT, TENANT, url=KV_URL)
    assert isinstance(decision, Denied)
    assert decision.reason is DenyReason.DATA_OBJECT_NOT_ALLOWED


def test_operation_keys() -> None:
    assert parse_operation("kv:GET /secrets/Payroll-DB-Password").key == SECRET
    assert parse_operation(BLOB_PAY).key == BLOB_PAY  # blob names keep their case
    assert parse_operation(BLOB_PAY).is_read and parse_operation(SECRET).is_read
    with pytest.raises(OperationError):
        parse_operation("blob:HEAD /payroll/" + "a" * 257)


# --- fuzz: on the data plane, exactly the listed URLs are allowed ---

HOSTS = ["kv-crown-x.vault.azure.net", "kv-other-x.vault.azure.net", "KV-crown-x.vault.azure.net"]
HOSTS += ["kv-crown-x.vault.azure.net:443", "kv-crown-x.vault.azure.net.example", "evil.example"]
PATHS = ["/secrets/payroll-db-password", "/secrets", "/secrets/other", "/secrets/x/v1", "/keys/k"]
PATHS += ["/secrets/payroll-db-password/", "/Secrets/payroll-db-password", "/secrets/../secrets"]
QUERIES = ["", "?api-version=7.4", "?api-version=7.5", "?api-version=7.4&x=1", "?x=1"]
EXACT = {(KV_URL, SECRET), (LIST_URL, LIST)}


@given(
    scheme=st.sampled_from(["https://", "http://", "https://u@"]),
    host=st.sampled_from(HOSTS),
    path=st.sampled_from(PATHS),
    query=st.sampled_from(QUERIES),
    op=st.sampled_from([SECRET, LIST, "kv:GET /secrets/other"]),
    target=st.sampled_from([VAULT, VAULT2, PAYROLL]),
)
def test_fuzz_only_exact_urls_pass(
    scheme: str, host: str, path: str, query: str, op: str, target: str
) -> None:
    url = f"{scheme}{host}{path}{query}"
    gate, _, _ = make_gate(M)
    decision = gate.check("prove", op, target, TENANT, url=url)
    # Secret names are case-insensitive in Key Vault, so a path that differs only in
    # case is the same object; every other variation must be denied.
    canonical = url.replace("/Secrets/", "/secrets/")
    expected = target == VAULT and (canonical, op) in EXACT
    assert isinstance(decision, Allowed) is expected, (url, op, target, decision)


@given(principal=st.sampled_from([None, SP_VERIFIER, SUB, TENANT, "not-a-guid"]))
def test_fuzz_prove_needs_the_pinned_test_identity(principal: str | None) -> None:
    gate, _, _ = make_gate(M, principal=principal)
    decision = gate.check("prove", SECRET, VAULT, TENANT, url=KV_URL)
    assert isinstance(decision, Denied)
    assert decision.reason is DenyReason.PRINCIPAL_NOT_ALLOWED
