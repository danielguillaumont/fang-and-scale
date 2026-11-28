# Proposal: logged `blob/write` evidence from `fns record`

**Status: future proposal only, not approved for verdicts** (decided 2026-11-27:
"logged blob/write evidence from fns record stays out of verdicts"). Nothing in
this document is built. Verdicts do not read `fns record` output.

## The gap

`must_still_do` invoices `blob/write` stays `inconclusive` after harden. The
permissions API evaluates the write as allowed (rung 2, evaluated), but an observed
success needs a write, and `fns prove` never writes. The lab budget accepts the
item by name (`budget.accepted_inconclusive`, reason: writes stay rung 2 by
design).

The workload makes that write itself in normal use. Session B of the M4 runbook
uploads a synthetic invoice as the agent, and the storage diagnostic logs record
it (`StorageBlobLogs`: caller object ID, operation `PutBlob`, status 201). `fns
record` already reads those rows to derive `must_still_do` items.

## What could be proposed

A logged success could become rung 4 (logged) evidence for a `must_still_do`
item, under conditions like these, each a guardrail test:

1. **Only `must_still_do`, only toward `pass`.** A logged success shows that a
   legitimate operation works. It never says anything about `must_not_reach`.
2. **The exact identity, operation and object.** The row's caller is the frozen
   compromised identity's object ID; the operation maps one-to-one to the
   contract operation; the resource is the item's exact ARM ID.
3. **After the change it proves.** The row's time is after the harden apply and
   inside a stated window before the freeze; an older row proves nothing about
   the hardened state.
4. **Signed and content-addressed like a probe.** The query, its workspace, the
   rows and their digest are journaled before the verdict, and the verifier
   re-hashes them. FIXTURE rows never become LIVE evidence.
5. **No row, no change.** Missing, ambiguous or late rows leave the item
   `inconclusive`; they never fail or pass it on their own.

## Why not now

It adds a new evidence source (logs) to the verdict path and a new trust
dependency (Log Analytics ingestion and its delays). The evidence ladder and the
verifier's inputs would change, which needs its own plan and review. Until then
the item is accepted by name, and any other inconclusive item still fails.
