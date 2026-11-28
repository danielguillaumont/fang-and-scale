"""Scale test: a generated synthetic FIXTURE tenant through scout replay and contain.

    uv run poe scale                                      # 10,000 SPs, about 50,000 edges
    uv run python scripts/scale_test.py --sps 2000        # smaller
    uv run python scripts/scale_test.py run --sps 10000 --out <dir>

``run`` generates the tenant with ``generate`` and then runs ``scout`` and
``contain``, each in its own process, one after the other, so each stage's
peak memory is its own. Nothing here calls a network: the tenant is a spec
answered by the same fake transport as the scenario gallery
(``scripts/build_scenarios.py``), recorded once through the real collector and
then replayed by ``fns demo scout``'s code path. Placeholder GUIDs only;
everything is labelled FIXTURE. ``docs/PERFORMANCE.md`` has the numbers.
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_scenarios as bs

from fns.contain_run import contain, load_snapshot
from fns.demo import run_demo_scout
from fns.fixtures import wellknown as wk
from fns.journal import sqlite as journal_sqlite
from fns.models.contract import load_contract

SEED = 20261128
FIRST = 1_000_000
"""Principal numbers start here, 1000 apart: the gallery's IDs are n, n+200, n+600."""
GROUP_BASE = 100_000

# Role mix for service principal grants (weights sum to 100).
_SP_ROLES = (
    (wk.READER, 40),
    (wk.KEY_VAULT_SECRETS_USER, 20),
    (wk.STORAGE_BLOB_DATA_CONTRIBUTOR, 30),
    (wk.CONTRIBUTOR, 6),
    (wk.STORAGE_ACCOUNT_KEY_OPERATOR, 3),
    (wk.OWNER, 1),
)
_GROUP_ROLES = ((wk.READER, 60), (wk.KEY_VAULT_SECRETS_USER, 25), (wk.CONTRIBUTOR, 15))


@dataclass(frozen=True)
class Size:
    sps: int

    @property
    def groups(self) -> int:
        return max(2, self.sps // 20)

    @property
    def resources(self) -> int:
        return max(4, self.sps // 50)


def _pick(rng: random.Random, table: tuple[tuple[str, int], ...]) -> str:
    return rng.choices([r for r, _ in table], weights=[w for _, w in table])[0]


def tenant(size: Size, seed: int = SEED) -> tuple[bs.Tenant, bs.Principal]:
    """A deterministic synthetic tenant.

    ``sp-00000`` is an ordinary agent (``CONTRACT``); ``sp-00001`` is a wide one
    (``WIDE_CONTRACT``): Owner on the resource group, and owner of 1 in 100
    applications with Application.ReadWrite.OwnedBy.
    """
    rng = random.Random(seed)  # noqa: S311 - test data, not secrets
    resources = tuple(
        (f"kv-{i:04d}", "Microsoft.KeyVault/vaults")
        if i % 2 == 0
        else (f"st{i:04d}", "Microsoft.Storage/storageAccounts")
        for i in range(size.resources)
    )
    names = [n for n, _ in resources]
    groups = tuple(bs.Group(GROUP_BASE + g, f"grp-{g:04d}") for g in range(size.groups))
    numbers = [FIRST + 1000 * i for i in range(size.sps)]
    principals: list[bs.Principal] = []
    for i, n in enumerate(numbers):
        managed = i % 5 == 4  # one in five is a managed identity
        owners: tuple[int, ...] = ()
        if not managed and i > 1 and i % 100 == 2:
            owners = (numbers[1],)  # the wide agent owns 1 in 100 applications
        elif not managed and i > 0 and rng.random() < 0.3:
            owners = (rng.choice(numbers[:i]),)
        graph_roles: tuple[str, ...] = ()
        if i == 1 or rng.random() < 0.02:
            graph_roles = ("Application.ReadWrite.OwnedBy",)
        principals.append(
            bs.Principal(
                n,
                f"sp-{i:05d}",
                managed=managed,
                owners=owners,
                graph=graph_roles,
                groups=tuple(sorted({GROUP_BASE + rng.randrange(size.groups) for _ in range(2)})),
            )
        )
    grants: list[tuple[int, str, str]] = []
    for n in numbers:
        for _ in range(2):
            scope = "rg" if rng.random() < 0.01 else rng.choice(names)
            grants.append((n, _pick(rng, _SP_ROLES), scope))
    for g in groups:
        grants.append((g.n, _pick(rng, _GROUP_ROLES), rng.choice(names)))
    grants.append((numbers[1], wk.OWNER, "rg"))  # the wide agent: Owner on the resource group
    t = bs.Tenant(resources, tuple(principals), tuple(grants), groups=groups)
    return t, principals[0]


def scope_yaml(t: bs.Tenant, agent: bs.Principal) -> str:
    calls = 10 * len(t.principals) + 100
    text = bs.scope_yaml(t, agent).replace("max_api_calls: 200", f"max_api_calls: {calls}")
    return text.replace("scenario-gallery tenant", "synthetic scale tenant")


CONTRACT = """# Synthetic scale tenant (FIXTURE, scripts/scale_test.py).
version: 1
contract: scale-agent-blast-radius
assume_compromised: sp:sp-00000
must_not_reach:
  - resource: kv-0000
    operations: [secrets/get, secrets/list]
  - resource: st0001
    operations: [blob/read, listKeys]
  - directory: tenant
    operations: [roleAssignments/write]
budget:
  max_critical_reachable: 0
  max_inconclusive: 5
on_inconclusive: fail
"""


WIDE_CONTRACT = (
    CONTRACT.replace("scale-agent", "scale-wide-agent")
    .replace("sp:sp-00000", "sp:sp-00001")
    .replace("max_inconclusive: 5", "max_inconclusive: 0")
)


def write_fixture(out: Path, size: Size) -> dict[str, Any]:
    t, agent = tenant(size)
    scope = scope_yaml(t, agent)
    out.mkdir(parents=True, exist_ok=True)
    manifest = {
        "description": f"Synthetic scale tenant, {size.sps} service principals "
        "(scripts/scale_test.py); placeholder GUIDs only.",
        "format": 1,
        "label": "FIXTURE",
        "name": f"scale-{size.sps}",
        "recorded_at": bs.RECORDED_AT,
        "tenant_id": bs.TENANT,
    }
    exchanges = bs.exchanges(t, scope)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (out / "scope.yaml").write_text(scope, encoding="utf-8")
    (out / "contract.fns.yaml").write_text(CONTRACT, encoding="utf-8")
    (out / "wide.fns.yaml").write_text(WIDE_CONTRACT, encoding="utf-8")
    text = json.dumps(exchanges, sort_keys=True, separators=(",", ":"))
    (out / "exchanges.json").write_text(text + "\n", encoding="utf-8")
    return {"exchanges": len(exchanges), "exchanges_bytes": len(text) + 1}


def peak_rss_mib() -> float:
    """Peak resident memory of this process so far."""
    platform: str = sys.platform  # a plain str: mypy checks both branches
    if platform == "win32":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        c = Counters()
        c.cb = ctypes.sizeof(c)
        k32 = ctypes.WinDLL("kernel32")
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        info = k32.K32GetProcessMemoryInfo
        info.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        info.restype = wintypes.BOOL
        if not info(k32.GetCurrentProcess(), ctypes.byref(c), c.cb):
            raise OSError("K32GetProcessMemoryInfo failed")
        return float(c.PeakWorkingSetSize) / 2**20
    import resource

    peak = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)  # type: ignore[attr-defined,unused-ignore]
    return peak / (2**20 if platform == "darwin" else 2**10)  # bytes on macOS, KiB on Linux


def stage(name: str, out: Path, sps: int) -> dict[str, Any]:
    """Run one stage in this process and return its measurements."""
    fixture, work = out / "fixture", out / "work"
    start = time.perf_counter()
    result: dict[str, Any] = {"stage": name}
    if name == "generate":
        result |= write_fixture(fixture, Size(sps))
    elif name in ("scout", "scout-nofsync"):
        if name == "scout-nofsync":
            # What tests/conftest.py does for test journals; the product never does it.
            journal_sqlite.SYNCHRONOUS = "OFF"  # type: ignore[misc]
            work = out / "work-nofsync"
        scout = run_demo_scout(work, fixture)
        snap = scout.snapshot
        result |= {
            "api_calls": scout.calls,
            "entities": len(snap.entities),
            "edges": len(snap.edges),
            "snapshot_digest": scout.digest,
            "snapshot_bytes": scout.snapshot_path.stat().st_size,
        }
        (out / f"{name}.snapshot").write_text(str(scout.snapshot_path), encoding="utf-8")
    elif name in ("contain", "contain-wide"):
        snapshot = load_snapshot(Path((out / "scout.snapshot").read_text(encoding="utf-8")))
        loaded = time.perf_counter()
        file = "contract.fns.yaml" if name == "contain" else "wide.fns.yaml"
        report = contain(load_contract(fixture / file), snapshot, now=snapshot.collected_at)
        s = report.summary
        result |= {
            "load_seconds": round(loaded - start, 2),
            "critical": s.critical,
            "inconclusive": s.inconclusive,
            "exit_code": s.exit_code,
            "report_digest": report.digest(),
        }
    else:
        raise SystemExit(f"unknown stage {name}")
    result["seconds"] = round(time.perf_counter() - start, 2)
    result["peak_rss_mib"] = round(peak_rss_mib(), 1)
    return result


STAGES = ("generate", "scout", "scout-nofsync", "contain", "contain-wide")


def run(out: Path, sps: int) -> list[dict[str, Any]]:
    """Each stage in a fresh process, sequentially (never in parallel)."""
    results = []
    for name in STAGES:
        done = subprocess.run(  # noqa: S603
            [sys.executable, __file__, "stage", name, "--out", str(out), "--sps", str(sps)],
            capture_output=True,
            text=True,
            check=False,
        )
        if done.returncode != 0:
            raise SystemExit(f"stage {name} failed:\n{done.stdout}\n{done.stderr}")
        results.append(json.loads(done.stdout.strip().splitlines()[-1]))
    digests = {r["snapshot_digest"] for r in results if "snapshot_digest" in r}
    if len(digests) != 1:
        raise SystemExit(f"the two scout runs disagree: {sorted(digests)}")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", nargs="?", default="run", choices=["run", "stage"])
    parser.add_argument("name", nargs="?", default="")
    parser.add_argument("--sps", type=int, default=10_000)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    if args.command == "stage":
        sys.stdout.write(json.dumps(stage(args.name, args.out, args.sps), sort_keys=True) + "\n")
        return 0
    with tempfile.TemporaryDirectory(prefix="fns-scale-") as tmp:
        out = args.out or Path(tmp)
        sys.stdout.write(f"FIXTURE synthetic tenant, {args.sps} service principals\n")
        for r in run(out, args.sps):
            sys.stdout.write(json.dumps(r, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
