from __future__ import annotations

import contextlib
import random
import uuid

import pytest
from hypothesis import given
from hypothesis import strategies as st

from fns.models.armid import ArmIdError, ArmPath, ProviderPath, parse_arm_id
from fns.scope.targets import (
    ArmTarget,
    DirectoryTarget,
    TargetError,
    check_next_link,
    check_url,
)
from tests.factories import RG, SUB
from tests.scope.gatekit import ARM_URL, GRAPH_URL, RA_PATH

# --- ARM ID round trip and totality ------------------------------------------------

name = st.from_regex(r"[a-z0-9][a-z0-9_\-.()]{0,20}", fullmatch=True).filter(
    lambda s: s not in {".", ".."}
)
rtype = st.from_regex(r"[a-z][a-z0-9]{0,15}", fullmatch=True)
namespace = st.from_regex(r"[a-z][a-z0-9]{0,8}\.[a-z][a-z0-9]{0,10}", fullmatch=True)
provider = st.builds(
    ProviderPath,
    namespace,
    st.lists(st.tuples(rtype, name), min_size=1, max_size=3).map(tuple),
)


@st.composite
def arm_paths(draw: st.DrawFn) -> ArmPath:
    kind = draw(st.sampled_from(["sub", "rg", "mg", "tenant"]))
    providers = tuple(draw(st.lists(provider, min_size=1 if kind == "tenant" else 0, max_size=2)))
    # The parser reads "/providers/microsoft.management/managementgroups/x" as an MG,
    # so keep generated tenant-level providers off that namespace.
    if kind == "tenant" and providers and providers[0].namespace == "microsoft.management":
        providers = (ProviderPath("microsoft.other", providers[0].pairs), *providers[1:])
    sub = draw(st.uuids()) if kind in {"sub", "rg"} else None
    rg = draw(name) if kind == "rg" else None
    mg = draw(name) if kind == "mg" else None
    return ArmPath(mg, sub, rg, providers)


@given(arm_paths())
def test_parse_format_round_trip(path: ArmPath) -> None:
    assert parse_arm_id(path.format()) == path


@given(arm_paths(), st.randoms())
def test_case_insensitive(path: ArmPath, rnd: random.Random) -> None:
    text = path.format()
    flipped = "".join(c.upper() if rnd.random() < 0.5 else c for c in text)
    assert parse_arm_id(flipped) == path


@given(st.text(max_size=300))
def test_parse_arbitrary_text_is_total(text: str) -> None:
    with contextlib.suppress(ArmIdError):
        parse_arm_id(text)


@given(
    st.lists(
        st.sampled_from(
            [
                "subscriptions",
                "resourceGroups",
                "providers",
                SUB,
                "rg",
                "Microsoft.KeyVault",
                "vaults",
                "kv",
                "",
                "..",
                "%2F",
            ]
        ),
        max_size=12,
    )
)
def test_parse_structured_garbage_is_total(segs: list[str]) -> None:
    with contextlib.suppress(ArmIdError):
        parse_arm_id("/" + "/".join(segs))


def test_arm_target_wraps_errors() -> None:
    with pytest.raises(TargetError):
        ArmTarget.parse("not an id")
    assert str(ArmTarget.parse(RG.upper().replace("SUBSCRIPTIONS", "subscriptions"))) == RG.lower()


def test_directory_target_str() -> None:
    oid = uuid.UUID(int=5)
    assert str(DirectoryTarget()) == "directory"
    assert str(DirectoryTarget(oid)) == f"directory/{oid}"


# --- URL checks ----------------------------------------------------------------------

RG_T = ArmTarget.parse(RG)


@pytest.mark.parametrize(
    ("api", "url", "target"),
    [
        ("arm", ARM_URL, RG_T),
        ("arm", ARM_URL.replace("management.azure.com", "MANAGEMENT.AZURE.COM"), RG_T),
        ("arm", f"https://management.azure.com:443{RG}?api-version=1", RG_T),
        ("graph", GRAPH_URL, DirectoryTarget()),
        ("graph", "https://graph.microsoft.com/beta/applications?$top=5", DirectoryTarget()),
    ],
)
def test_url_ok(api: str, url: str, target: ArmTarget | DirectoryTarget) -> None:
    check_url(api, url, target)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("api", "url", "target"),
    [
        ("arm", ARM_URL.replace("https://", "http://"), RG_T),
        ("arm", ARM_URL.replace("management.azure.com", "management.azure.com.evil.example"), RG_T),
        ("arm", ARM_URL.replace("management.azure.com", "evil.example"), RG_T),
        ("arm", ARM_URL.replace("management.azure.com", "user:pw@management.azure.com"), RG_T),
        ("arm", ARM_URL.replace("management.azure.com", "management.azure.com:8443"), RG_T),
        ("arm", ARM_URL.replace("rg-fns-lab", "rg-fns-lab-prod"), RG_T),
        ("arm", ARM_URL.replace("rg-fns-lab", "rg-fns-la"), RG_T),
        ("arm", ARM_URL.replace("/providers", "//providers"), RG_T),
        ("arm", ARM_URL.replace("/providers", "/../providers"), RG_T),
        ("arm", ARM_URL.replace("rg-fns-lab", "rg-fns-lab%2F..%2Fprod"), RG_T),
        ("arm", ARM_URL + "#frag", RG_T),
        ("arm", ARM_URL + " ", RG_T),
        ("arm", GRAPH_URL, RG_T),
        ("arm", ARM_URL, DirectoryTarget()),
        (
            "graph",
            GRAPH_URL.replace("graph.microsoft.com", "graph.microsoft.us"),
            DirectoryTarget(),
        ),
        ("graph", "https://graph.microsoft.com/servicePrincipals", DirectoryTarget()),
        ("graph", "https://graph.microsoft.com/v2.0/servicePrincipals", DirectoryTarget()),
        ("graph", "https://graph.microsoft.com/v1.0", DirectoryTarget()),
        ("graph", GRAPH_URL, RG_T),
        ("graph", "file:///etc/passwd", DirectoryTarget()),
    ],
)
def test_url_rejected(api: str, url: str, target: ArmTarget | DirectoryTarget) -> None:
    with pytest.raises(TargetError):
        check_url(api, url, target)  # type: ignore[arg-type]


def test_next_link_may_only_change_query() -> None:
    check_next_link(ARM_URL, ARM_URL + "&$skiptoken=abc")
    check_next_link(GRAPH_URL, GRAPH_URL + "?$skiptoken=X")
    for bad in [
        ARM_URL.replace("management.azure.com", "evil.example"),
        ARM_URL.replace(RA_PATH, "providers/Microsoft.Authorization/denyAssignments"),
        ARM_URL.replace("rg-fns-lab", "rg-other"),
        "http://management.azure.com" + ARM_URL.removeprefix("https://management.azure.com"),
    ]:
        with pytest.raises(TargetError):
            check_next_link(ARM_URL, bad)
