# Recorded fixtures

Sanitized API responses recorded from the lab with `fns scout --record` (Phase B).

- Tenant, subscription and object IDs are replaced with placeholder GUIDs.
- The real-to-placeholder mapping (`_idmap.json`) is gitignored and never committed.
- Anything replayed from here is labelled `FIXTURE`.

The hand-written demo fixture used by `fns demo` ships inside the package at
`src/fns/fixtures/data/`.
