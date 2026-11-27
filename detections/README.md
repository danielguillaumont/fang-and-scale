# Detection rules

One YAML file per rule. `uv run fns detections check` and
`tests/harden/test_detections.py` lint them. Nothing here is deployed
automatically: `uv run fns detections export --param monitored_identities='["<object id>"]'`
renders Sentinel scheduled alert rule bodies, and deploying them is M4 K4.

`covers` ties each rule to the reach model:

- `rule:<name>`: an escalation rule in `fns.contain`;
- `op:<resource|directory>:<operation>`: a row of the semantics table;
- `way:<name>`: an indirect final way.

A test requires every escalation rule and every semantics operation to be
covered by a rule or listed in `EXEMPT.yaml` with a reason.

## Sample rows

Every rule has `samples/<id>.yaml`: rows that must make it alert, and rows that
must not. `fns detections check` runs them and reports any case that disagrees.
The rows use placeholder IDs only, and their shapes follow what the 2026-11-27
log path check saw (`docs/FINDINGS.md`) and Microsoft's documented columns.

The samples run through `fns.harden.kql`, a small evaluator of the KQL the rules
use (`where`, `extend`, `project`, `summarize` without `by`, `mv-apply`, and a
fixed list of functions). It refuses anything else, so a rule that uses more
KQL has to extend the evaluator, with tests, before its samples can run.

**What a passing sample shows, and what it doesn't.** It shows the rule's logic
does what its author meant on rows of that shape. It does not show that Kusto
accepts the query, or that the real rows look like the samples. The live
detection results (M4 session C) are the evidence for those.

Two rules were changed by what the log path check found:

- `app-credential-added-by-workload`: adding and deleting a key log the same
  operation name. The rule counts the keys before and after (the
  `KeyDescription` property) and drops only a change known to be a delete. If
  the key lists are missing or unreadable, it still alerts (`Change` =
  `unknown`).
- `workload-sign-in-with-secret` (new, for strike S4): a monitored identity
  signing in with anything other than a key-based assertion, a federated
  credential or a managed identity. A certificate sign-in logs
  `clientAssertion`, so the lab's normal sign-ins stay quiet.
