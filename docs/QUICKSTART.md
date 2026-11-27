# Quickstart: `fns demo` in under 5 minutes

No tenant, no Azure account, no credentials. Every command below replays recorded
or hand-written files. Every line it prints starts with `FIXTURE`, and it makes
no network call.

Fang & Scale needs **Python 3.12** (exactly; 3.13 is not supported yet).

## Path A: install the tool (about 2 minutes)

With [pipx](https://pipx.pypa.io/):

```
pipx install --python 3.12 "git+https://github.com/danielguillaumont/fang-and-scale@v0.1.0"
```

Or with [uv](https://docs.astral.sh/uv/):

```
uv tool install --python 3.12 "git+https://github.com/danielguillaumont/fang-and-scale@v0.1.0"
```

Until the `v0.1.0` tag exists, use `@main` instead. Then, in any empty directory:

```
fns --version                     # fns 0.1.0
fns demo scout --bundled          # 1. Replay a scout: what the snapshot holds
fns demo contain --bundled        # 2. What can the compromised identity reach? (exit 1: it can)
fns demo prove --bundled          # 3. Freeze assertions, replay probes, verify in a separate process
fns demo report --bundled         # 4. One HTML page: .fns/report.FIXTURE.html
```

`--bundled` replays the **hand-written** `demo-scout` set that ships in the
package, and the first line says so. Without it, `fns demo` looks for the
recorded lab runs (`fixtures/lab-run-*`), which come with a checkout (path B), as
does `fns demo mutate`, which needs the lab's Terraform.

## Path B: a checkout (about 3 minutes)

Needs [uv](https://docs.astral.sh/uv/) and git:

```
git clone https://github.com/danielguillaumont/fang-and-scale
cd fang-and-scale
uv sync
uv run fns demo contain      # 1. The M3 live lab run, replayed: what a compromised billing agent reaches
uv run fns demo prove        # 2. The probes it ran live, replayed and verified
uv run fns demo mutate       # 3. Harden the lab in the model, then try to break the contract
uv run fns demo report       # 4. .fns/report.FIXTURE.html, with the mutation score
```

In a checkout, `fns demo` replays `fixtures/lab-run-3` by default: the M3 run
against the lab tenant, recorded and sanitized. Its scout ran as `sp-fns-scout`
and its probes as `sp-billing-agent`.

### Strikes and detections (checkout only)

The strike engine also replays from a fixture. These runs are generated from a
fake lab tenant, not recorded live, and make no network call:

```
uv run fns strike plan --strikes S1,S2,S3 --fixture fixtures/strike-demo --out .fns/strike
```

It prints `plan sha256:<hash>` and the exact `fns strike run` command, with
`--approve`, that runs it. Each write is undone and checked by a separate
read-only identity. To put the result on a report page, pass that run directory
to `fns report`, as `--strike .fns/strike/<run id>`.

## What you are looking at

- **Exit codes:**
  - `0`: within the contract's budget;
  - `1`: the contract failed (the demo's expected result);
  - `3`: too many items `inconclusive`;
  - `2`: invalid input;
  - `4`: the scope gate refused something;
  - `5`: the evidence did not check out.
- **The report** opens with coverage: what was actually checked, at which rung
  of the evidence ladder (modeled, evaluated, observed, logged). Read that
  before the verdicts.
- **`inconclusive` is never a pass.** Anything the tool cannot model or probe
  says so.

## Next

- Write a contract: `contracts/examples/billing-agent.fns.yaml` and
  `schemas/contract.schema.json`.
- Run it against your own lab tenant: `docs/runbooks/m1-live-run.md`. Only use a
  tenant you own or have written permission to test (see the README).
- What each fixture proves: the README, "Real vs. fixture".
