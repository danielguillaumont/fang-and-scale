# Security policy

## Reporting a vulnerability

Report vulnerabilities **privately**, through GitHub's private vulnerability
reporting: the repository's **Security** tab, then **Report a vulnerability**.
Please do not open a public issue, pull request or discussion for a
vulnerability.

Include what you found, how to reproduce it (against fixtures or your own lab),
and what an attacker would gain. Expect an acknowledgement within 7 days. This
is a personal project with no bug bounty.

## In scope

Bugs in this repository's code, workflows or the GitHub Action, especially:

- a way to make the scope gate (`fns.scope.gate`) allow a request it should deny:
  a wrong tenant, an operation that is not listed, a target outside the scope, or
  a request after the budget or expiry;
- any write to Azure or Entra outside `strike` and `harden --apply` with
  `--approve <plan-hash>`, or any write at all outside the lab;
- a way to make `fns verify` accept a tampered or incomplete run, or a verdict
  stronger than its evidence (for example `pass` without an observed denial);
- secrets, tokens or real tenant identifiers that end up in fixtures, reports,
  bundles, logs or PR comments;
- script or HTML injection through tenant data in `fns report` or `fns comment`;
- weaknesses in the GitHub workflows (token permissions, untrusted input).

## Out of scope

- Findings about Microsoft Entra ID or Azure themselves. Report those to the
  [Microsoft Security Response Center](https://msrc.microsoft.com/). API
  behaviour that differs from the documentation goes in `docs/FINDINGS.md`
  through a normal issue.
- Attack paths that Fang & Scale reports in **your** tenant. That is the tool
  working.
- The deliberately over-privileged identities in `lab/`. They are the test
  subject.

## Use only on tenants you are authorized to test

Fang & Scale reads directory and RBAC data and, with `fns prove --live`, sends
real requests as the identity a contract names. Run it only against a tenant you
own or have written permission to test, preferably a **dedicated lab tenant**
like the one `lab/` builds. Never use it against a tenant you are not authorized
to test, and never test a vulnerability report against someone else's tenant.

## Supported versions

Only the latest commit on `main` gets fixes. There is no released version yet.
