"""``fns scout``: collect a read-only snapshot through the scope gate.

Every request, every page and every retry is a separate ``gate.call`` (so
budget and journal see all of them). Failures are recorded in coverage and
never abort the snapshot:

- ``complete``: every request of the collector succeeded;
- ``partial``: some succeeded, some failed;
- ``failed``: every request failed;
- ``skipped``: the scope gate denied every request.

Per-object Graph calls (owners, app role assignments, memberships) are made
only for tenant-owned service principals and managed identities, so a tenant
with hundreds of Microsoft first-party service principals stays within budget.

PIM eligibility (M3 E1) runs only when the scope allows its reads. The surface
``pim-eligibility`` then ends in one of three states:

- collected: every eligibility listing succeeded (the edges are in the snapshot);
- not applicable: no listing returned a row, at least one failed with an HTTP
  error, and ``/subscribedSkus`` succeeded and every service plan in it is known,
  by ID, not to carry PIM (``graph.PIM_FREE_PLAN_IDS``). An unknown plan or SKU
  keeps the surface not collected. The responses are the evidence; nothing is
  inferred from a failure alone;
- otherwise not collected, with the reason.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from fns import __version__
from fns.adapters.azure import arm, graph
from fns.adapters.azure.http import ApiRequest, ApiResponse, Transport, TransportError
from fns.inventory.builder import PRIORITY_PRIMARY, SnapshotBuilder
from fns.models.scope import ScopeManifest
from fns.models.snapshot import (
    CollectorRun,
    CollectorStatus,
    NotApplicable,
    NotCollected,
    Provenance,
    Snapshot,
    SnapshotCoverage,
)
from fns.scope.gate import Clock, Gate, ScopeDeniedError

MAX_PAGES: Final = 1000
RETRY_STATUSES: Final = frozenset({429, 500, 502, 503, 504})
MAX_BACKOFF_SECONDS: Final = 60.0

KV_ACCESS_POLICIES: Final = "key-vault-access-policies"
PIM_ELIGIBILITY: Final = "pim-eligibility"
PIM_COLLECTOR: Final = "pim.eligibility"
NOT_COLLECTED: Final = (
    NotCollected(surface=PIM_ELIGIBILITY, reason="eligible assignments not collected in M1"),
    NotCollected(surface="conditional-access", reason="not collected in M1"),
    NotCollected(
        surface=KV_ACCESS_POLICIES,
        reason="vault access policies (non-RBAC) not collected in M1",
    ),
    NotCollected(
        surface="app-credentials", reason="key/password credential metadata not collected in M1"
    ),
    NotCollected(surface="federated-identity-credentials", reason="not collected in M1"),
    NotCollected(
        surface="user-group-memberships",
        reason="memberships collected for in-scope service principals only",
    ),
)


_ERROR_CODE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


def _error_code(body: dict[str, Any]) -> str | None:
    """The ``error.code`` of an ARM or Graph error body, if well formed."""
    err = body.get("error")
    code = err.get("code") if isinstance(err, dict) else None
    return code if isinstance(code, str) and _ERROR_CODE.fullmatch(code) else None


class _CollectError(Exception):
    def __init__(self, code: str, *, denied: bool = False, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.denied = denied
        self.detail = detail
        """The response's error code, when there was a response."""


@dataclass(frozen=True)
class _Step:
    ok: bool
    error: _CollectError | None = None

    @property
    def responded(self) -> bool:
        """Failed with an HTTP status from the service (not scope, not transport)."""
        return self.error is not None and self.error.code.startswith("http-")

    def text(self) -> str:
        if self.error is None:
            return "ok"
        return " ".join(x for x in (self.error.code, self.error.detail) if x)


@dataclass
class _Tally:
    name: str
    ok: int = 0
    failed: int = 0
    denied: int = 0
    items: int = 0
    errors: set[str] = field(default_factory=set)
    started: float = 0.0
    ended: float = 0.0
    depends: tuple[_Tally, ...] = ()
    verdict: Literal["not-applicable"] | None = None
    """Set when evidence beyond this collector's own requests decides its status."""

    def run(self) -> CollectorRun:
        """Never report more than was observed (CLAUDE.md rule 4).

        A collector whose inputs come from an incomplete upstream listing is at
        best ``partial``; with no requests at all it is ``skipped``, not an
        empty ``complete``.
        """
        status: CollectorStatus
        errors = set(self.errors)
        upstream_ok = all(d.run().status == "complete" for d in self.depends)
        if not upstream_ok:
            errors.add("upstream-incomplete")
        attempted = self.ok + self.failed + self.denied
        if attempted == 0:
            status = "complete" if upstream_ok else "skipped"
        elif self.failed == 0 and self.denied == 0:
            status = "partial" if errors else "complete"
        elif self.ok > 0:
            status = "partial"
        elif self.failed == 0:
            status = "skipped"
        else:
            status = "failed"
        if self.verdict is not None:
            status = self.verdict
        return CollectorRun(
            name=self.name,
            status=status,
            items=self.items,
            error_codes=tuple(sorted(errors)),
            duration_ms=max(0, int((self.ended - self.started) * 1000)),
        )


class Collector:
    def __init__(
        self,
        *,
        manifest: ScopeManifest,
        gate: Gate,
        transport: Transport,
        clock: Clock,
        mode: Literal["LIVE", "FIXTURE"],
        sleep: Callable[[float], None] = time.sleep,
        max_retries: int = 3,
    ) -> None:
        self.manifest = manifest
        self.gate = gate
        self.transport = transport
        self.clock = clock
        self.mode = mode
        self.sleep = sleep
        self.max_retries = max_retries
        self.tenant = str(manifest.tenant_id)
        self.calls: list[ApiRequest] = []

    # -- plumbing ------------------------------------------------------------------------

    def _prov(self, req: ApiRequest, resp: ApiResponse) -> Provenance:
        return Provenance(
            source_api=req.operation, request_id=resp.request_id, observed_at=self.clock.now()
        )

    def _exchange(self, req: ApiRequest, page_of: str | None) -> ApiResponse:
        attempt = 0
        while True:
            self.calls.append(req)

            def fetch(req: ApiRequest = req) -> ApiResponse:
                return self.transport.fetch(req)

            try:
                resp = self.gate.call(
                    "scout",
                    req.operation,
                    req.target,
                    self.tenant,
                    fetch,
                    url=req.url,
                    page_of=page_of,
                )
            except ScopeDeniedError as exc:
                if page_of is not None:
                    # A nextLink the gate rejects is untrusted API output that pointed
                    # out of scope: a failure of this listing, not a scope decision.
                    raise _CollectError("next-link-denied") from exc
                raise _CollectError(
                    f"scope-denied:{exc.decision.reason.value}", denied=True
                ) from exc
            except TransportError as exc:
                raise _CollectError("transport-error") from exc
            if resp.status in RETRY_STATUSES:
                if attempt >= self.max_retries:
                    raise _CollectError(f"http-{resp.status}-exhausted")
                delay = resp.retry_after if resp.retry_after is not None else 2.0**attempt
                self.sleep(min(max(delay, 0.0), MAX_BACKOFF_SECONDS))
                attempt += 1
                continue
            if not resp.ok:
                raise _CollectError(f"http-{resp.status}", detail=_error_code(resp.body))
            return resp

    def _list(self, req: ApiRequest) -> tuple[list[dict[str, Any]], Provenance]:
        first = req.url
        resp = self._exchange(req, None)
        prov = self._prov(req, resp)
        items: list[dict[str, Any]] = []
        pages = 0
        while True:
            value = resp.body.get("value")
            if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
                raise _CollectError("bad-response")
            items.extend(value)
            nxt = resp.next_link()
            if nxt is None:
                return items, prov
            pages += 1
            if pages >= MAX_PAGES:
                raise _CollectError("too-many-pages")
            page_req = ApiRequest(api=req.api, operation=req.operation, target=req.target, url=nxt)
            resp = self._exchange(page_req, first)

    def _get(self, req: ApiRequest) -> dict[str, Any]:
        return self._exchange(req, None).body

    def _attempt(self, tally: _Tally, fn: Callable[[], int]) -> bool:
        return self._step(tally, fn).ok

    def _step(self, tally: _Tally, fn: Callable[[], int]) -> _Step:
        try:
            tally.items += fn()
            tally.ok += 1
            return _Step(True)
        except _CollectError as exc:
            tally.errors.add(exc.code.split(":")[0] if exc.denied else exc.code)
            if exc.denied:
                tally.denied += 1
            else:
                tally.failed += 1
            return _Step(False, exc)
        except (arm.ParseError, graph.ParseError):
            tally.errors.add("bad-response")
            tally.failed += 1
            return _Step(False, _CollectError("bad-response"))

    # -- collection -----------------------------------------------------------------------

    def run(self) -> Snapshot:
        b = SnapshotBuilder()
        tallies: list[_Tally] = []

        def collector(name: str, *depends: _Tally) -> _Tally:
            t = _Tally(name, started=self.clock.monotonic(), depends=depends)
            tallies.append(t)
            return t

        for sub in self.manifest.subscription_ids:
            b.entity(f"/subscriptions/{sub}", "scope", priority=PRIORITY_PRIMARY)

        # ARM: resources per allowed resource group.
        t = res_t = collector("arm.resources")
        settings_targets: list[tuple[str, str]] = []
        for rg in self.manifest.allowed_resource_groups:

            def resources(rg: str = rg) -> int:
                items, prov = self._list(arm.resources_request(rg))
                settings_targets.extend(
                    (str(i["id"]), str(i["type"]).lower())
                    for i in items
                    if isinstance(i.get("id"), str)
                    and str(i.get("type", "")).lower() in arm.SETTINGS_TYPES
                )
                sub = rg.split("/resourcegroups/")[0]
                b.entity(rg, "scope", priority=PRIORITY_PRIMARY)
                b.edge({"type": "contains", "src": sub, "dst": rg}, prov)
                t.errors.update(arm.parse_resources(b, rg, items, prov))
                return len(items)

            self._attempt(t, resources)
        t.ended = self.clock.monotonic()

        # ARM: per-resource settings the reach model needs, when the scope allows them.
        not_collected = list(NOT_COLLECTED)
        allowed = set(self.manifest.allowed_operations.get("scout", ()))
        settings_ops = allowed & set(arm.SETTINGS_OPERATIONS)
        if settings_ops:
            t = collector("arm.resource-settings", res_t)
            for rid, rtype in sorted(set(settings_targets)):
                if arm.SETTINGS_TYPES[rtype] not in settings_ops:
                    continue

                def settings(rid: str = rid, rtype: str = rtype) -> int:
                    req = arm.resource_settings_request(rid, rtype)
                    resp = self._exchange(req, None)
                    if arm.SETTINGS_TYPES[rtype] == arm.OP_KEY_VAULT:
                        t.errors.update(
                            arm.parse_key_vault(
                                b, rid, resp.body, self.tenant, self._prov(req, resp)
                            )
                        )
                    else:
                        arm.parse_storage_account(b, rid, resp.body)
                    return 1

                self._attempt(t, settings)
            t.ended = self.clock.monotonic()
            if arm.OP_KEY_VAULT in settings_ops and t.run().status == "complete":
                not_collected = [n for n in not_collected if n.surface != KV_ACCESS_POLICIES]

        # ARM: role assignments, then each referenced role definition.
        role_defs: dict[str, str] = {}  # referenced definition id -> subscription listed in
        t = ras = collector("arm.role-assignments")
        for sub in self.manifest.subscription_ids:

            def assignments(sub: str = str(sub)) -> int:
                items, prov = self._list(arm.role_assignments_request(sub))
                refs, errs = arm.parse_role_assignments(b, items, prov)
                for ref in sorted(refs):
                    role_defs.setdefault(ref, sub)
                t.errors.update(errs)
                return len(items)

            self._attempt(t, assignments)
        t.ended = self.clock.monotonic()

        t = collector("arm.role-definitions", ras)
        for rd in sorted(role_defs):

            def definition(rd: str = rd) -> int:
                req = arm.role_definition_request(role_defs[rd], arm.role_definition_guid(rd))
                arm.parse_role_definition(b, self._get(req), rd)
                return 1

            self._attempt(t, definition)
        t.ended = self.clock.monotonic()

        t = collector("arm.deny-assignments")
        for sub in self.manifest.subscription_ids:

            def denies(sub: str = str(sub)) -> int:
                items, prov = self._list(arm.deny_assignments_request(sub))
                t.errors.update(arm.parse_deny_assignments(b, items, prov))
                return len(items)

            self._attempt(t, denies)
        t.ended = self.clock.monotonic()

        # Graph: service principals and applications.
        app_roles: dict[str, dict[str, str]] = {}
        sp_rows: list[dict[str, Any]] = []
        t = sps_t = collector("graph.service-principals")

        def sps() -> int:
            items, _ = self._list(graph.service_principals_request())
            roles, errs = graph.parse_service_principals(b, items)
            app_roles.update(roles)
            sp_rows.extend(items)
            t.errors.update(errs)
            return len(items)

        self._attempt(t, sps)
        t.ended = self.clock.monotonic()

        in_scope_sps = sorted(
            str(r["id"]).lower()
            for r in sp_rows
            if isinstance(r.get("id"), str)
            and (
                str(r.get("appOwnerOrganizationId") or "").lower() == self.tenant
                or r.get("servicePrincipalType") == "ManagedIdentity"
            )
        )
        sp_by_app_id = {
            str(r.get("appId", "")).lower(): str(r["id"]).lower()
            for r in sp_rows
            if isinstance(r.get("id"), str) and r.get("appId")
        }

        app_ids: list[str] = []
        t = apps_t = collector("graph.applications", sps_t)

        def apps() -> int:
            items, prov = self._list(graph.applications_request())
            t.errors.update(graph.parse_applications(b, items, sp_by_app_id, prov))
            app_ids.extend(
                sorted(str(i["id"]).lower() for i in items if isinstance(i.get("id"), str))
            )
            return len(items)

        self._attempt(t, apps)
        t.ended = self.clock.monotonic()

        t = collector("graph.owners", sps_t, apps_t)
        for sp in in_scope_sps:

            def sp_owners(sp: str = sp) -> int:
                items, prov = self._list(graph.sp_owners_request(sp))
                t.errors.update(graph.parse_owners(b, sp, items, prov))
                return len(items)

            self._attempt(t, sp_owners)
        for app in app_ids:

            def app_owners(app: str = app) -> int:
                items, prov = self._list(graph.app_owners_request(app))
                t.errors.update(graph.parse_owners(b, app, items, prov))
                return len(items)

            self._attempt(t, app_owners)
        t.ended = self.clock.monotonic()

        t = collector("graph.app-role-assignments", sps_t)
        for sp in in_scope_sps:

            def grants(sp: str = sp) -> int:
                items, prov = self._list(graph.sp_app_role_assignments_request(sp))
                t.errors.update(graph.parse_app_role_assignments(b, items, app_roles, prov))
                return len(items)

            self._attempt(t, grants)
        t.ended = self.clock.monotonic()

        t = collector("graph.memberships", sps_t)
        for sp in in_scope_sps:

            def member_of(sp: str = sp) -> int:
                items, prov = self._list(graph.sp_member_of_request(sp))
                t.errors.update(graph.parse_member_of(b, sp, items, prov))
                return len(items)

            self._attempt(t, member_of)
        t.ended = self.clock.monotonic()

        t = collector("graph.directory-roles")

        def dir_roles() -> int:
            defs, _ = self._list(graph.directory_role_definitions_request())
            t.errors.update(graph.parse_directory_role_definitions(b, defs))
            items, prov = self._list(graph.directory_role_assignments_request())
            t.errors.update(graph.parse_directory_role_assignments(b, items, prov))
            return len(defs) + len(items)

        self._attempt(t, dir_roles)
        t.ended = self.clock.monotonic()

        # PIM eligibility last: it keeps only principals the snapshot already holds.
        not_applicable: list[NotApplicable] = []
        pim_ops = allowed & {*arm.PIM_OPERATIONS, *graph.PIM_OPERATIONS}
        if pim_ops:
            t = collector(PIM_COLLECTOR)
            state = self._pim(b, t, pim_ops)
            t.ended = self.clock.monotonic()
            not_collected = [n for n in not_collected if n.surface != PIM_ELIGIBILITY]
            if isinstance(state, NotApplicable):
                not_applicable.append(state)
                t.verdict = "not-applicable"
            elif state is not None:
                not_collected.append(state)

        coverage = SnapshotCoverage(
            collectors=tuple(x.run() for x in tallies),
            not_collected=tuple(not_collected),
            not_applicable=tuple(not_applicable),
        )
        return b.build(
            mode=self.mode,
            tenant_id=self.tenant,
            collected_at=self.clock.now(),
            collector_version=f"fns {__version__}",
            coverage=coverage,
        )

    # -- PIM eligibility (M3 E1) -----------------------------------------------------------

    def _pim(
        self, b: SnapshotBuilder, t: _Tally, ops: set[str]
    ) -> NotApplicable | NotCollected | None:
        """Collect eligibility. None means collected: the surface is closed."""
        rows = 0
        listings: list[tuple[str, _Step]] = []
        missing: list[str] = []
        directory_listing = "GET /roleManagement/directory/roleEligibilitySchedules"

        if graph.OP_DIR_ROLE_ELIGIBILITY in ops:

            def directory() -> int:
                nonlocal rows
                items, prov = self._list(graph.directory_role_eligibility_request())
                rows += len(items)
                t.errors.update(graph.parse_directory_role_eligibility(b, items, prov)[1])
                return len(items)

            listings.append((directory_listing, self._step(t, directory)))
        else:
            missing.append(f"{directory_listing} is not in the scope")

        for sub in self.manifest.subscription_ids:
            name = f"ARM roleEligibilitySchedules on /subscriptions/{sub}"
            if arm.OP_ROLE_ELIGIBILITY not in ops:
                missing.append(f"{name} is not in the scope")
                continue

            def resources(sub: str = str(sub)) -> int:
                nonlocal rows
                items, prov = self._list(arm.role_eligibility_request(sub))
                rows += len(items)
                t.errors.update(arm.parse_role_eligibility(b, items, prov)[1])
                return len(items)

            listings.append((name, self._step(t, resources)))

        if not missing and all(step.ok for _, step in listings):
            return None

        evidence = [f"{name} -> {step.text()}" for name, step in listings]
        found: list[graph.Licences] = []
        sku_step: _Step | None = None
        if graph.OP_SUBSCRIBED_SKUS in ops:

            def licences() -> int:
                items, _ = self._list(graph.subscribed_skus_request())
                found.append(graph.pim_licences(items))
                return len(items)

            sku_step = self._step(t, licences)
            if sku_step.ok:
                got = found[0]
                line = (
                    f"GET /subscribedSkus -> ok: {len(got.skus)} SKU(s)"
                    f" [{', '.join(got.skus) or 'none'}];"
                    f" plans that may carry PIM: {', '.join(got.pim) or 'none'}"
                )
                if got.unknown:
                    line += f"; plans not known to be PIM-free: {', '.join(got.unknown)}"
                evidence.append(line)
            else:
                evidence.append(f"GET /subscribedSkus -> {sku_step.text()}")
        else:
            evidence.append("GET /subscribedSkus is not in the scope")

        failed = [step for _, step in listings if not step.ok]
        lic = found[0] if found and sku_step is not None and sku_step.ok else None
        if (
            lic is not None
            and lic.rules_out_pim
            and rows == 0
            and failed
            and all(step.responded for step in failed)
        ):
            return NotApplicable(
                surface=PIM_ELIGIBILITY,
                reason=(
                    "no subscribed licence carries PIM (Entra ID P2 or ID Governance), "
                    "and no eligibility listing returned a row"
                ),
                evidence=tuple(evidence),
            )
        why = [*missing, *(f"{n} -> {s.text()}" for n, s in listings if not s.ok)]
        if lic is not None and lic.pim:
            why.append(f"licences that may carry PIM: {', '.join(lic.pim)}")
        if lic is not None and lic.unknown:
            why.append(
                "service plans not known to be PIM-free, so PIM cannot be ruled out: "
                + ", ".join(lic.unknown)
            )
        elif lic is None:
            why.append("subscribed SKUs not collected, so PIM cannot be ruled out")
        return NotCollected(surface=PIM_ELIGIBILITY, reason="; ".join(why))
