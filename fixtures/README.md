# Recorded fixtures

Sanitized API responses recorded from the lab with `fns scout --record` (Phase B).

- Tenant, subscription and object IDs are replaced with placeholder GUIDs.
- The real-to-placeholder mapping (`_idmap.json`) is gitignored and never committed.
- Anything replayed from here is labelled `FIXTURE`.

Every `fns demo` command replays `lab-run-1` by default (run from a checkout).
The hand-written `demo-scout` set, used by the tests, ships inside the package at
`src/fns/fixtures/data/`.
