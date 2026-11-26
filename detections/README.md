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
