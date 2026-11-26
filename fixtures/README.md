# Recorded fixtures

Sanitized API responses recorded from the lab with `fns scout --record` (Phase B).

- Tenant, subscription and object IDs are replaced with placeholder GUIDs.
- The real-to-placeholder mapping (`_idmap.json`) is gitignored and never committed.
- Anything replayed from here is labelled `FIXTURE`.

Two sets are recorded from the live lab:

- `lab-run-1`: the M1 run (scout as the lab admin, then as `sp-fns-scout`).
- `lab-run-2`: the M2 run (2026-11-26), signed in as `sp-fns-scout`, with the
  resource settings and PIM collectors. Its `contract.fns.yaml` is the v2 contract
  that `lab/contract.tf` rendered, names only. Together they are the M2 C4
  regression test (`tests/fixtures/test_lab_run_2.py`).

Both carry a `probes.json` with **hand-written** probe results for the M3 offline
demo; those are not recorded. A replay digest differs from the live digest of the
same run, because the IDs are placeholders and the mode is `FIXTURE`; the replay
digests are pinned in `tests/golden/`.

Every `fns demo` command replays `lab-run-2` by default (run from a checkout).
The hand-written `demo-scout` set, used by the tests, ships inside the package at
`src/fns/fixtures/data/`.
