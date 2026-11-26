# Findings: Microsoft API behaviour vs documentation

Record every case where ARM or Graph behaves differently than documented: the
request (sanitized), the response, the date, and what the code does about it.

| Date | API | Request | Documented | Observed | Handling |
| --- | --- | --- | --- | --- | --- |

Open questions to settle on the first live lab run (M1 Phase B):

- Whether `Application.Read.All` alone returns owner/member objects of type user and
  group in full, or whether `Directory.Read.All` is needed (README, "Scout permissions").
- That the IDs in `src/fns/fixtures/wellknown.py` (built-in roles, Graph app roles,
  directory role templates) match the lab tenant.
- Whether subscription-scope role assignment listings include assignments at `/`
  and at management groups (the collector handles both).
