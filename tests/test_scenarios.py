"""The scenario gallery (docs/scenarios) is generated, current and honest.

Every fixture set and every ``expected-*.txt`` is what
``scripts/build_scenarios.py`` writes today (golden test), each misconfiguration
fails and its fix stays within budget, and every page says FIXTURE.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GALLERY = ROOT / "docs" / "scenarios"
_spec = importlib.util.spec_from_file_location(
    "build_scenarios", ROOT / "scripts" / "build_scenarios.py"
)
assert _spec is not None and _spec.loader is not None
build_scenarios = importlib.util.module_from_spec(_spec)
sys.modules["build_scenarios"] = build_scenarios  # dataclasses resolve their module
_spec.loader.exec_module(build_scenarios)

SLUGS = [s.slug for s in build_scenarios.SCENARIOS]

# What each tenant must show before and after the fix: (exit code, lines that must appear).
EXPECTED: dict[str, dict[str, tuple[int, tuple[str, ...]]]] = {
    "01-owner-of-privileged-app": {
        "tenant": (
            1,
            (
                "FIXTURE FAIL resource:kv-crown secrets/get  modeled / modeled-only",
                "[owner-adds-credential] sp-report-agent owns app-deployer",
            ),
        ),
        "fixed": (0, ("inconclusive not-reach -        not-assessed  kv-crown secrets/get",)),
    },
    "02-contributor-key-vault-flip": {
        "tenant": (
            1,
            (
                "FIXTURE FAIL resource:kv-crown secrets/get  modeled / modeled-only",
                "FIXTURE FAIL resource:kv-crown secrets/list  modeled / modeled-only",
                "[kv-control-to-data] Contributor allows Microsoft.KeyVault/vaults/write",
            ),
        ),
        "fixed": (
            0,
            (
                "inconclusive not-reach -        not-assessed  kv-crown secrets/get",
                "inconclusive still-do  modeled  modeled-only  stbatch blob/write",
            ),
        ),
    },
    "03-listkeys-is-data-access": {
        "tenant": (
            1,
            (
                "FIXTURE FAIL resource:stpayroll blob/read  modeled / modeled-only",
                "FIXTURE FAIL resource:stpayroll blob/write  modeled / modeled-only",
                "[listkeys-data] Storage Account Key Operator Service Role",
            ),
        ),
        "fixed": (0, ("inconclusive not-reach -        not-assessed  stpayroll blob/read",)),
    },
    "04-github-trust-too-broad": {
        "tenant": (
            0,
            ("high     sp-deployer: any workflow run for a pull request in contoso/billing",),
        ),
        "fixed": (
            0,
            (
                "medium   sp-deployer: any job in contoso/billing that references environment"
                " production",
            ),
        ),
    },
    "05-nested-group-owner": {
        "tenant": (
            1,
            (
                "FIXTURE FAIL resource:kv-crown roleAssignments/write  modeled / modeled-only",
                "FIXTURE FAIL resource:kv-crown secrets/get  modeled / modeled-only",
                "[member-of] sp-sync-agent is in the group grp-platform-admins",
                "transitiveMemberOf/microsoft.graph.group",
            ),
        ),
        "fixed": (0, ("inconclusive not-reach -        not-assessed  kv-crown secrets/get",)),
    },
}


def test_the_gallery_is_what_the_generator_writes() -> None:
    drift = build_scenarios.build(check=True)
    assert drift == [], "docs/scenarios drifted: uv run python scripts/build_scenarios.py"


def test_every_scenario_has_an_expectation() -> None:
    assert sorted(EXPECTED) == sorted(SLUGS)
    assert len(SLUGS) == 5


@pytest.mark.parametrize("slug", SLUGS)
@pytest.mark.parametrize("which", ["tenant", "fixed"])
def test_verdicts(slug: str, which: str) -> None:
    text = (GALLERY / slug / f"expected-{which}.txt").read_text(encoding="utf-8")
    code, lines = EXPECTED[slug][which]
    assert text.endswith(f"(exit {code})\n")
    for line in lines:
        assert line in text, line
    body = text.splitlines()[1:-1]
    assert body and all(line.startswith("FIXTURE") for line in body)
    assert "evidence: rung 1 (modeled) only" in text
    assert not re.search(r"\bpass\b", "\n".join(body)), "modeled evidence never passes"


@pytest.mark.parametrize("slug", SLUGS)
def test_the_fix_is_the_only_difference_in_the_contract(slug: str) -> None:
    tenant = (GALLERY / slug / "tenant" / "contract.fns.yaml").read_text(encoding="utf-8")
    fixed = (GALLERY / slug / "fixed" / "contract.fns.yaml").read_text(encoding="utf-8")
    assert tenant == fixed


@pytest.mark.parametrize("slug", SLUGS)
def test_fixture_sets_are_labelled_and_replayed(slug: str) -> None:
    for which in ("tenant", "fixed"):
        manifest = json.loads(
            (GALLERY / slug / which / "manifest.json").read_text(encoding="utf-8")
        )
        assert manifest["label"] == "FIXTURE"
        exchanges = json.loads(
            (GALLERY / slug / which / "exchanges.json").read_text(encoding="utf-8")
        )
        assert exchanges, "an empty fixture set would replay nothing"
        # The scout only reads, and every read these tenants need is a GET.
        assert {e["request"].split(" ", 1)[0] for e in exchanges} == {"GET"}


@pytest.mark.parametrize("slug", SLUGS)
def test_each_page_says_fixture_and_shows_the_demo_command(slug: str) -> None:
    page = (GALLERY / slug / "README.md").read_text(encoding="utf-8")
    assert "(FIXTURE)" in page.splitlines()[0]
    assert f"uv run fns demo contain --fixture docs/scenarios/{slug}/tenant" in page
    for heading in ("**Story.**", "**Contract**", "**Expected**", "**Fix:**", "**Why the rule"):
        assert heading in page, heading
    assert "learn.microsoft.com" in page


def test_the_index_links_every_scenario_and_the_readme_links_the_index() -> None:
    index = (GALLERY / "README.md").read_text(encoding="utf-8")
    assert "**Every one is a FIXTURE**" in index
    assert "not yet validated live" in index
    for slug in SLUGS:
        assert f"({slug}/README.md)" in index
    assert "(docs/scenarios/README.md)" in (ROOT / "README.md").read_text(encoding="utf-8")
