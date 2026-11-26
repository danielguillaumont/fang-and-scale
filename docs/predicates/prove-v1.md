# Predicate type: fns prove v1

`predicateType`: `https://github.com/danielguillaumont/fang-and-scale/blob/main/docs/predicates/prove-v1.md`

The predicate of an in-toto Statement v1 written by `python -m fns.verify run`.
It is the `EvidenceBundle` model, as canonical JSON. The committed schema is
`schemas/evidence-bundle.schema.json`.

## Subjects

| Name | Digest |
| --- | --- |
| `assertions.json` | sha256 of the frozen assertions, the same digest the journal recorded before any probe ran |
| `artifacts/<sha256>.json` | each probe observation the bundle relies on |

## Fields that matter to a consumer

- `mode`: `FIXTURE` means replayed or hand-written inputs. Never treat a
  FIXTURE bundle as evidence about a real tenant.
- `findings[]`: the `Finding` model. Each finding carries its verdict, its
  coverage state, and evidence with rungs (modeled, evaluated, observed, logged).
- `summary.exit_code`: 0 within budget, 1 contract failed, 3 inconclusive over
  budget.
- `verifier`: who verified, as a label. It is not an authenticated identity.
  Only a Sigstore signature binds an identity.

## Envelope and signature

The statement bytes (canonical JSON) are the DSSE payload, with `payloadType`
`application/vnd.in-toto+json`.

`signing.json` names the signer:

- `offline-test`: Ed25519 with an ephemeral key. This proves integrity only;
  anyone can produce another valid signature with their own key. It is always
  labelled `TEST SIGNATURE`.
- `sigstore`: keyless, through Fulcio and Rekor. Verify it with an identity
  policy (`--sigstore-identity`, `--sigstore-issuer`).
- `none`: unsigned. `fns verify` rejects it.

`fns verify <run dir>` checks the following and exits 5 on any mismatch:

- the signature;
- that the statement file equals the signed payload;
- that `bundle.json` equals the predicate;
- every subject digest;
- the journal ordering;
- that the verdicts follow from the inputs.
