# Live validation backlog

Everything added in the 2026-11-28 coverage build session is **modeled or
fixture only, not yet validated live**. Each row below is a check to run against
the lab (or a real tenant, read-only) before the feature is trusted. Nothing
here needs a new Graph or ARM permission unless the row says so.

Record each result in `docs/FINDINGS.md` when Microsoft's behaviour differs from
the documentation cited here, and strike the row through with the date.

| ID | Feature | Check | Expected (from the docs) | Source |
| --- | --- | --- | --- | --- |
| LV-1 | Credential metadata (`graph.credentials`) | With `graph:GET /applications/{id}` and `graph:GET /servicePrincipals/{id}` added to a scout scope, run `fns scout --record` on the lab and read the recording | `keyCredentials` and `passwordCredentials` arrive as lists on both objects; `secretText` is null; the recording shows `key`, `customKeyIdentifier` and `hint` as `REDACTED`; the snapshot holds only keyId, kind, displayName, type, usage, start and end | [keyCredential](https://learn.microsoft.com/en-us/graph/api/resources/keycredential?view=graph-rest-1.0), [passwordCredential](https://learn.microsoft.com/en-us/graph/api/resources/passwordcredential?view=graph-rest-1.0) |
| LV-2 | Credential metadata | The same run with the scout's current permissions | 200 for both reads with Application.Read.All (no new permission) | [Get application](https://learn.microsoft.com/en-us/graph/api/application-get?view=graph-rest-1.0), [Get servicePrincipal](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-get?view=graph-rest-1.0) |
| LV-3 | Credential metadata | A list call (`GET /applications?$select=id,keyCredentials`) for comparison, by hand, not by the tool | `key` is null in a list: "only available for single object requests" | [keyCredential](https://learn.microsoft.com/en-us/graph/api/resources/keycredential?view=graph-rest-1.0) |
