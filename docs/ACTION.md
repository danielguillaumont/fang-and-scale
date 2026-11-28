# The GitHub Action

`action.yml` at the root of this repository is a composite action. It
evaluates a blast-radius contract on a snapshot, optionally replays probe
results and mutation-tests the contract, writes the result to the job summary,
and keeps one sticky comment on the pull request up to date.

It is **read-only**: it never signs in to Azure or Entra, never needs a
secret, and never writes to a tenant. It reads files: a snapshot your scout
run wrote, or a recorded FIXTURE set.

**Status (2026-11-28).** This repository runs the action on its own pull
requests (`.github/workflows/blast-radius.yml`). Use from another repository
follows the same path, but has not been tried from one yet (backlog LV-15).
The `fixture` input and the `contain-json` output are newer than v0.1.0.

## Try it without a tenant

[`docs/examples/blast-radius.yml`](examples/blast-radius.yml) is a complete
workflow. It replays the bundled FIXTURE tenant, so it runs with no Azure login:

```yaml
- id: fns
  uses: danielguillaumont/fang-and-scale@RELEASE_COMMIT_SHA # vX.Y.Z
  with:
    fixture: bundled
    fail-on-contract: "false"
```

Every line it writes is labelled `FIXTURE`. `fixture` also takes any recorded
set inside the action's checkout, e.g. one of the
[scenario gallery](scenarios/README.md) tenants:
`fixture: docs/scenarios/02-contributor-key-vault-flip/tenant`.

## Your own tenant

The action does not run `fns scout`: scouting needs the read-only scout
identity and a scope, and that belongs in a job you control (see the
[guide](GUIDE.md)). Pass what it wrote:

```yaml
- uses: danielguillaumont/fang-and-scale@RELEASE_COMMIT_SHA # vX.Y.Z
  with:
    contract: contracts/billing-agent.fns.yaml
    snapshot: .fns/snapshots/<digest>.json
```

## Inputs

| Input | Default | What it does |
| --- | --- | --- |
| `contract` | `""` | Contract file (`*.fns.yaml`). Required unless `fixture` is set; then the fixture set's own `contract.fns.yaml` |
| `snapshot` | `""` | Snapshot JSON written by `fns scout` (or `fns demo scout`). Set this or `fixture`, not both |
| `fixture` | `""` | `bundled`, or a relative path to a recorded fixture set inside the action's checkout. Replayed with `fns demo scout`; output labelled FIXTURE. No absolute paths, `..`, `\` or `:` |
| `probes` | `""` | Probe results to replay with `fns prove` (FIXTURE only). The bundle is signed with `offline-test` and says TEST signature, never a real one |
| `lab` | `""` | Terraform directory for `fns mutate --harden` (model only). Empty to skip |
| `baseline` | `""` | Contain report JSON from the base branch, for deltas in the comment. Skipped if missing |
| `comment` | `"true"` | Post or update the sticky comment on the pull request |
| `fail-on-contract` | `"true"` | Fail the job when the contract fails (exit 1) or is inconclusive over budget (3) |
| `github-token` | `${{ github.token }}` | Used only to post the comment |

## Outputs

| Output | What it holds |
| --- | --- |
| `exit-code` | `0` within budget, `1` contract failed, `3` inconclusive over budget. Errors end the step with `2` (usage or invalid input), `4` (scope denied) or `5` (evidence invalid) |
| `comment-file` | Path of the Markdown comment (also written to the job summary) |
| `contain-json` | Path of the contain report JSON: verdicts, evidence rungs, coverage states |

## The sticky comment

- The comment starts with the marker `<!-- fns:blast-radius -->`. On each run
  the action looks for the first comment by a bot that starts with it, and
  edits it; if there is none, it posts one. So a pull request has one comment,
  updated in place, not one per push.
- It needs `pull-requests: write` on the job. Without it, set
  `comment: "false"` and read the job summary.
- On a pull request from a fork the token is read-only: the action does not
  try, and the comment is in the job summary only.
- Two jobs in one repository that both comment edit the same comment. Keep
  `comment: "true"` on one of them.
- Tenant strings in the comment (names, paths) are escaped, so they cannot
  close the Markdown or mention a user or team.

## Pinning

Pin the action to the full commit SHA of a release tag, with the tag in a
comment, as `actions/checkout` is pinned above. v0.1.0 is
`0ddfa34f62a8f94a374150664957c962be7a4fa2`; it has every input above except
`fixture`, and every output except `contain-json`. Dependabot's
`github-actions` ecosystem updates such pins.

## What it does not do

- It does not run live probes (`fns prove` with real HTTP calls), `fns strike`
  or `fns harden --apply`. Nothing in it writes to a tenant.
- It does not turn a modeled finding into `pass`: with snapshot evidence only,
  a target the model does not reach is `inconclusive`.
