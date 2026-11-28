# Performance

How long `fns` takes, and how much memory it uses, on a large synthetic
tenant. Measured 2026-11-28 on one machine (below). These are **FIXTURE**
numbers: no tenant was called. A live scout also waits on the network and on
Graph and ARM throttling, which this does not model.

## The tenant

`scripts/scale_test.py` generates it deterministically (seed `20261128`):

| | 10,000 SP run |
| --- | --- |
| Service principals | 10,000 (8,000 with an application, 2,000 managed identities) |
| Groups | 500; every SP is in up to 2 |
| Resources | 200 (half Key Vaults, half storage accounts) |
| RBAC grants | 20,501 (2 per SP, 1 per group, plus Owner on the resource group for the wide agent) |
| Graph app permissions | about 2% of SPs hold Application.ReadWrite.OwnedBy |
| Recorded exchanges | 38,013 (29 MB) |
| Snapshot | 18,709 entities, **51,350 edges** (32 MB) |

Two contracts: an ordinary agent (`sp-00000`), and a **wide** one
(`sp-00001`: Owner on the resource group, and owner of 1 in 100 applications
with Application.ReadWrite.OwnedBy), so the closure has real work to do.

The tenant is answered by the scenario gallery's fake transport, recorded
once through the real collector, then replayed by the same code path as
`fns demo scout`: gate, journal, collector, snapshot writer.

## Results (10,000 SPs)

Each stage ran in its own process, one after another; peak memory is that
process's peak working set.

| Stage | Before | After | Peak memory |
| --- | --- | --- | --- |
| Generate + record the fixture (not a product path) | 19.7 s | 19.6 s | 288 MiB |
| **Scout replay**, as shipped (journal fsyncs every write) | 774 s | 868 s | 442 MiB |
| Scout replay, journal fsync off (what the test suite does) | 409 s | 375 s | 444 MiB |
| **Contain**, ordinary agent (of which loading the snapshot) | 3.3 s (1.9 s) | 3.1 s (2.0 s) | 224 MiB |
| **Contain**, wide agent (of which loading the snapshot) | 8.8 s (2.1 s) | **3.3 s** (2.0 s) | 225 MiB |

Results did not change: the snapshot digest (`accc6333…`) and both report
digests (`675d99c9…`, `a04aab8c…`) are the same before and after, and so are
the contain reports of every committed fixture (`lab-run-1/2/3`, the bundled
demo set).

The two scout rows moved in opposite directions between runs of the same code
(the whitespace change below is a few seconds at most): run-to-run variation
on this disk is about 10%. Read them as "about 13 minutes" and "about 6 to 7
minutes".

## Where the time goes

**Scout replay is journal-bound.** Every gated call writes two journal rows
(the decision before the call, the result after), each in its own SQLite
transaction. Profiled at 10,000 SPs with fsync off, SQLite commits and
statements were 293 s of 349 s; with fsync on, the commits are most of the
rest. That is by design: the journal is the audit trail, and DECISIONS
(2026-11-27, approved) says the product always fsyncs. **Not changed.** For a
live scout each call also makes a network round trip, so the journal's share
is smaller there (here it costs about 10 ms per call with fsync off and about
23 ms with it on: 375 s and 868 s over 38,013 calls); not measured live. Options, if replay speed ever matters, are in "Not done" below.

**Contain was superlinear in the closure's queries.** `Closure.effective`,
`app_perms` and `facts_of` scanned every derived fact on each call, and the
front-door step scanned every edge for each controlled identity. For the wide
agent at 10,000 SPs that was 6.7 s of evaluation (from 0.4 s at 2,000 SPs: 5
times the size, 16 times the time).

## What was changed (results identical)

1. **Closure indexes** (`fns.contain.closure`): facts by kind and by (kind,
   principal), kept in step by `_add`, the only writer. The rules see exactly
   the facts they saw before: a round's new facts are still added after every
   rule has run. `tests/contain/test_closure.py::test_indexed_queries_match_a_full_scan`
   checks the indexed answers against a full scan on random tenants.
2. **Front doors** (`fns.contain.evaluate`): `instanceOf` edges grouped by
   source once, in edge order, instead of a scan per identity.
3. **Whitespace check** (`fns.models.armid.has_ascii_whitespace`, used by
   `parse_arm_id` and the gate's URL check): the per-character `isspace` loop,
   15 million calls at 10,000 SPs, becomes ten substring scans in C. Both
   callers check `isascii()` first, and on ASCII input the answer is the same
   (`tests/models/test_armid_whitespace.py`, a hypothesis test plus every ASCII
   whitespace character). Small in wall time on this machine (the journal hides
   it), measurable in the profile.

## Not done (would change behaviour or a decision)

- **Journal durability or batching** for replay. Lowering `synchronous`, using
  WAL, or one transaction per collector step would make replay several times
  faster, but changes the audit trail's crash guarantees, and WAL mode could
  affect `fns.verify`, which opens the journal read-only. That's Daniel's call;
  not proposed as a change here.
- **Pagination.** The fake tenant answers each list in one page; a real
  tenant this size returns long lists in several pages, which adds requests
  (and journal rows), not compute.
- **Throttling and retries** are not modeled; a live 10,000-SP scout would
  also wait on `Retry-After`.

## Run it

```powershell
uv run poe scale                               # 10,000 SPs, about 20 minutes here
uv run python scripts/scale_test.py --sps 2000 # about 2.5 minutes
```

CI runs `tests/test_scale.py` instead: a 60-SP tenant, the same generator and
stages, determinism and shape only, no timing (timings on shared runners are
noise). The big run is opt-in and is not part of `poe check`.

## The machine

Windows 11 Home, 8 logical CPUs, 15.7 GiB RAM, Python 3.12.16, SQLite 3.53.1,
an ordinary laptop SSD with real-time antivirus on. Linux has not been
measured; SQLite commits are usually much cheaper there, so scout replay
should be faster, and contain about the same.
