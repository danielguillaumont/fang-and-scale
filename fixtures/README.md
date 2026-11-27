# Recorded fixtures

Sanitized API responses recorded from the lab with `fns scout --record` (Phase B).

- Tenant, subscription and object IDs are replaced with placeholder GUIDs.
- The real-to-placeholder mapping (`_idmap.json`) is gitignored and never committed.
- Anything replayed from here is labelled `FIXTURE`.

Three sets are recorded from the live lab:

- `lab-run-1`: the M1 run (scout as the lab admin, then as `sp-fns-scout`).
- `lab-run-2`: the M2 run (2026-11-26), signed in as `sp-fns-scout`, with the
  resource settings and PIM collectors. Its `contract.fns.yaml` is the v2 contract
  that `lab/contract.tf` rendered, names only. Together they are the M2 C4
  regression test (`tests/fixtures/test_lab_run_2.py`).
- `lab-run-3`: the M3 run (2026-11-26). Its scout half was recorded as
  `sp-fns-scout` and replays to the same digest as `lab-run-2`. Its `probes.json`
  is **recorded live**, by `fns prove --live --record` as `sp-billing-agent`.
  That file is sanitized: status and allowlisted error codes only, with no request
  IDs, bodies or principals. Together they are the M3 regression test
  (`tests/fixtures/test_lab_run_3.py`).

The `probes.json` in `lab-run-1` and `lab-run-2` holds **hand-written** probe
results, made for the M3 offline demo before any probe ran live. A replay digest
differs from the live digest of the same run, because the IDs are placeholders
and the mode is `FIXTURE`. The replay digests are pinned in `tests/golden/`. For
`fns prove`, see `docs/FINDINGS.md`, "Live and replay bundle digests differ".

Every `fns demo` command replays `lab-run-3` by default (run from a checkout).
The hand-written `demo-scout` set, used by the tests, ships inside the package at
`src/fns/fixtures/data/`.

`strike-demo` is **not recorded live**. `tests/strike/make_fixture.py` generates it
from the fake lab tenant in `tests/strike/faketenant.py`, and a test fails if the
committed files drift from that generator. It holds a placeholder `scope.yaml` and
two runs: `before-harden.json` (S1 to S3, each write succeeds and is undone) and
`after-harden.json` (D-1 to D-5, each one denied). Every response body was
stripped of secrets (`REDACTED`) before it was written. Replay it with
`fns strike plan --strikes S1,S2,S3 --fixture fixtures/strike-demo`, then the
`fns strike run` command that prints. The first live strike recording will come
from the M4 live run.

`strike-demo/detections.yaml` is **hand-written**: detection results per strike in
the D5 format (`schemas/detection-results.schema.json`), for the demo run
`202611251200-demo01`, with S3 marked missed so the report shows a detection
gap. No workspace was queried. `tests/report_golden.py` builds the report golden
from it, the bundled `demo-scout` set and both strike runs. They share one
placeholder tenant.
