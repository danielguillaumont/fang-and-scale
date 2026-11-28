# 4. A GitHub trust that accepts every pull request (FIXTURE)

**Story.** `sp-deployer` deploys from GitHub Actions without a secret: its
application has a **federated identity credential** for
`https://token.actions.githubusercontent.com` with subject
`repo:contoso/billing:pull_request`. The deployer reads deployment settings in
`kv-deploy`, which is its job. But that subject matches **every** workflow run
triggered by a pull request in the repository, so whoever can open one that
runs a workflow can sign in as the deployer, whatever the branch or review
state.

**Contract** (`tenant/contract.fns.yaml`):

```yaml
assume_compromised: sp:sp-deployer
must_not_reach:
  - resource: kv-crown
    operations: [secrets/get]
must_still_do:
  - resource: kv-deploy
    operations: [secrets/get]
```

**Run:** `uv run fns demo contain --fixture docs/scenarios/04-github-trust-too-broad/tenant`

**Expected** ([full output](expected-tenant.txt)): the deployer does not
reach `kv-crown` (`inconclusive`, within budget, exit 0), and the report lists
a **front door**:

```text
Front doors (outside parties that can sign in as an identity above; modeled, not validated live)
  high     sp-deployer: any workflow run for a pull request in contoso/billing
```

A front door never changes a verdict or the exit code: the attacker the
contract assumes already *is* the deployer. It says who else can become it,
here anyone who can get a pull-request workflow to run.

**Fix:** trust a protected environment instead, e.g.
`repo:contoso/billing:environment:production`, and require reviewers on it.
After the fix ([output](expected-fixed.txt)) the front door is **medium**: who
can sign in now depends on the environment's protection rules, which are
GitHub settings the snapshot does not hold.

**Why the rule holds.** GitHub's token carries `repo:ORG/REPO:pull_request`
"when the workflow is triggered by a pull request event", and
`repo:ORG/REPO:environment:NAME` "when the job references an environment"
([GitHub OIDC reference](https://docs.github.com/en/actions/reference/security/oidc)).
Entra matches the subject exactly ("must case-sensitively match") and
supports no wildcards
([Workload identity federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)).
Microsoft Learn writes the pull-request subject with a hyphen
(`pull-request`), which may match no token: FINDINGS R2, live check LV-7.
Whether a pull request from a **fork** can obtain a token is not stated in the
pages read (LV-7).
