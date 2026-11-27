"""The scope gate: the only path to any Azure or Graph call (CLAUDE.md rule 2).

Deny by default. :meth:`Gate.check` walks a fixed list of conditions and
returns :class:`Allowed` only if every one passes; anything unexpected,
including a bug inside the gate, returns :class:`Denied`. :meth:`Gate.call`
journals the decision, reserves budget, and only then invokes the SDK
callable. Nothing is invoked on a denial.

Order of checks (first failure wins):

 1. manifest present                   NO_MANIFEST
 2. not expired (every call)           EXPIRED
 3. signed-in tenant == manifest == call tenant   TENANT_MISMATCH
 4. verb allowed                       VERB_NOT_ALLOWED
 5. operation well formed / listed     MALFORMED_OPERATION / DATA_PLANE_VERB_NOT_ALLOWED /
                                       OPERATION_NOT_ALLOWED
 6. read-only verb never writes        WRITE_BY_READ_ONLY_VERB
 7. no writes on this path             WRITE_ON_READ_PATH (writes go through check_write)
 8. target well formed and in scope    MALFORMED_TARGET / TARGET_KIND_MISMATCH /
                                       TENANT_LEVEL_NOT_ALLOWED / MG_NOT_ALLOWED /
                                       SUBSCRIPTION_NOT_ALLOWED / RG_NOT_ALLOWED
 9. data plane: a vault or storage account, and a listed object
                                       TARGET_KIND_MISMATCH / DATA_OBJECT_NOT_ALLOWED
10. request URL on the right host/path BAD_URL (data plane: exact host, path, query)
11. prove and strike act only as a test identity
                                       PRINCIPAL_NOT_ALLOWED / PRINCIPAL_MISMATCH
12. budget                             BUDGET_CALLS / BUDGET_TIME

Data plane (``kv:``, ``blob:``; M3 P5.1): only the verb ``prove`` may use it, even
if a forged manifest lists it elsewhere. The URL is required and must be exactly
``https://<resource name>.vault.azure.net<path>?api-version=7.4`` or
``https://<resource name>.blob.core.windows.net<path>``; there is no paging.

Principal pinning (decision V4): a ``prove`` call is allowed only when the gate was
built with the signed-in principal (the token's ``oid``) and that principal is a
test identity. A caller-supplied ``principal_id`` that differs is denied.

Writes (M4, ``docs/milestones/M4-strikes-plan.md``) have their own entry points,
:meth:`Gate.check_write` and :meth:`Gate.call_write`. Order (first failure wins):

 1. hard denylist, before the manifest is read   HARD_DENY
 2. manifest, expiry, ``strike:`` block, its expiry
                                       NO_MANIFEST / EXPIRED / NO_STRIKE_SCOPE
 3. tenant                             TENANT_MISMATCH
 4. verb is strike, operation is a write form and listed
                                       VERB_NOT_ALLOWED / MALFORMED_OPERATION /
                                       NOT_A_WRITE_FORM / OPERATION_NOT_ALLOWED
 5. signed in as a test identity, or as the escalated identity (S4) for the
    marker assignment and its removal only
                                       PRINCIPAL_NOT_ALLOWED
 6. method, host, exact path, pinned query   BAD_URL
 7. every ID a strike target of the right kind, inside the scope
                                       STRIKE_TARGET_NOT_ALLOWED / RG_NOT_ALLOWED / ...
 8. Graph targets passed the live lab check  LAB_CHECK_FAILED
 9. body: only what the form allows    BAD_BODY
10. the request is a step of the approved plan
                                       NO_APPROVED_PLAN / NOT_IN_APPROVED_PLAN
11. budget                             BUDGET_CALLS / BUDGET_TIME

The plan binding (step 10) comes from ``fns strike plan`` and ``--approve <hash>``;
a gate without one denies every write.

S4 (approved 2026-11-27) needs the scope's ``strike.escalation`` block for two
things, both denied without it:

- the token request (:data:`~fns.scope.writes.TOKEN_OPERATION`), sent by the agent:
  exactly ``POST https://login.microsoftonline.com/<scope tenant>/oauth2/v2.0/token``
  with client credentials for the escalation target's appId and the Graph
  ``.default`` scope, after the live check of that application and its service
  principal, and inside the approved plan. The gate never sees the secret;
- a gate signed in as the escalation target's service principal (the token's
  ``oid``) may send only the marker assignment to that same service principal, with
  a test identity as ``principalId`` and the scope's marker role as ``appRoleId``,
  and the removal of an assignment there. A test identity may send neither.
"""

from __future__ import annotations

import enum
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Final, Literal, Protocol, TypeVar

from fns.models.armid import GUID_RE, parse_arm_id
from fns.models.base import sha256_hex
from fns.models.firstparty import is_first_party
from fns.models.operations import (
    WRITE_FORM_OPERATIONS,
    Operation,
    OperationError,
    parse_operation,
)
from fns.models.scope import DATA_PLANE_VERB, READ_ONLY_VERBS, ScopeManifest, data_resource
from fns.scope.targets import (
    ArmTarget,
    DirectoryTarget,
    Target,
    TargetError,
    check_data_url,
    check_next_link,
    check_url,
)
from fns.scope.writes import (
    FORMS_BY_KEY,
    TOKEN_OPERATION,
    BodyContext,
    LabObject,
    WriteRefusedError,
    canonical_body,
    check_body,
    check_lab_object,
    check_token_body,
    hard_deny,
    match_form,
    token_url,
)

T = TypeVar("T")

KNOWN_VERBS: Final = frozenset({"scout", "contain", "strike", "harden", "prove", "molt"})


class DenyReason(enum.StrEnum):
    NO_MANIFEST = "no-manifest"
    EXPIRED = "expired"
    TENANT_MISMATCH = "tenant-mismatch"
    VERB_NOT_ALLOWED = "verb-not-allowed"
    MALFORMED_OPERATION = "malformed-operation"
    DATA_PLANE_VERB_NOT_ALLOWED = "data-plane-verb-not-allowed"
    OPERATION_NOT_ALLOWED = "operation-not-allowed"
    WRITE_BY_READ_ONLY_VERB = "write-by-read-only-verb"
    WRITE_ON_READ_PATH = "write-on-read-path"
    HARD_DENY = "hard-deny"
    NO_STRIKE_SCOPE = "no-strike-scope"
    NOT_A_WRITE_FORM = "not-a-write-form"
    STRIKE_TARGET_NOT_ALLOWED = "strike-target-not-allowed"
    LAB_CHECK_FAILED = "lab-check-failed"
    BAD_BODY = "bad-body"
    NO_APPROVED_PLAN = "no-approved-plan"
    NOT_IN_APPROVED_PLAN = "not-in-approved-plan"
    MALFORMED_TARGET = "malformed-target"
    TARGET_KIND_MISMATCH = "target-kind-mismatch"
    TENANT_LEVEL_NOT_ALLOWED = "tenant-level-not-allowed"
    MG_NOT_ALLOWED = "management-group-not-allowed"
    SUBSCRIPTION_NOT_ALLOWED = "subscription-not-allowed"
    RG_NOT_ALLOWED = "resource-group-not-allowed"
    DATA_OBJECT_NOT_ALLOWED = "data-object-not-allowed"
    BAD_URL = "bad-url"
    PRINCIPAL_NOT_ALLOWED = "principal-not-allowed"
    PRINCIPAL_MISMATCH = "principal-mismatch"
    BUDGET_CALLS = "budget-calls-exhausted"
    BUDGET_TIME = "budget-time-exhausted"
    JOURNAL_FAILED = "journal-failed"
    INTERNAL_ERROR = "internal-error"


@dataclass(frozen=True, slots=True)
class Allowed:
    operation: Operation
    target: str
    allowed: Literal[True] = True


@dataclass(frozen=True, slots=True)
class Denied:
    reason: DenyReason
    detail: str
    allowed: Literal[False] = False


Decision = Allowed | Denied


_REFUSALS: Final[dict[str, DenyReason]] = {
    "hard-deny": DenyReason.HARD_DENY,
    "url": DenyReason.BAD_URL,
    "target": DenyReason.STRIKE_TARGET_NOT_ALLOWED,
    "lab-check": DenyReason.LAB_CHECK_FAILED,
    "body": DenyReason.BAD_BODY,
}


@dataclass(frozen=True, slots=True)
class WriteRequest:
    """One write, exactly as it would be sent."""

    verb: str
    operation: str
    """The scope operation it claims to be (one of ``WRITE_FORM_OPERATIONS``)."""
    method: str
    url: str
    body: object
    """The JSON body (``None`` for none)."""
    tenant_id: uuid.UUID | str


class PlanBinding(Protocol):
    """The approved strike plan (``fns strike plan`` and ``--approve <hash>``, later PR).

    ``admits`` answers whether this request, with this canonical body digest, is a
    step of the plan the operator approved. It is consulted after every other rule,
    so it can narrow what the gate allows but never widen it.
    """

    def admits(self, request: WriteRequest, body_digest: str) -> bool: ...


class ScopeDeniedError(PermissionError):
    """Raised by :meth:`Gate.call` when the gate denies a call."""

    def __init__(self, decision: Denied) -> None:
        super().__init__(f"scope gate denied: {decision.reason.value}: {decision.detail}")
        self.decision = decision


# --- clock --------------------------------------------------------------------


class Clock(Protocol):
    def now(self) -> datetime: ...
    def monotonic(self) -> float: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()


@dataclass
class FrozenClock:
    """Deterministic clock for tests and fixture replay."""

    at: datetime
    mono: float = 0.0

    def now(self) -> datetime:
        return self.at

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.at = self.at + timedelta(seconds=seconds)
        self.mono += seconds


# --- journal sink ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GateRecord:
    """One gate decision, as written to the run journal."""

    run_id: str
    seq: int
    verb: str
    operation: str
    target: str
    tenant_id: str
    principal_id: str | None
    url: str | None
    decision: Literal["allowed", "denied"]
    reason: str | None
    detail: str
    at: datetime


class JournalSink(Protocol):
    def record_decision(self, record: GateRecord) -> None: ...
    def record_call_result(
        self,
        run_id: str,
        seq: int,
        status: Literal["succeeded", "failed"],
        detail: str,
        at: datetime,
    ) -> None: ...


@dataclass
class InMemoryJournal:
    decisions: list[GateRecord] = field(default_factory=list)
    results: list[tuple[str, int, str, str]] = field(default_factory=list)

    def record_decision(self, record: GateRecord) -> None:
        self.decisions.append(record)

    def record_call_result(
        self,
        run_id: str,
        seq: int,
        status: Literal["succeeded", "failed"],
        detail: str,
        at: datetime,
    ) -> None:
        self.results.append((run_id, seq, status, detail))


# --- gate -------------------------------------------------------------------------


def _as_uuid(value: object) -> uuid.UUID | None:
    if isinstance(value, uuid.UUID):
        return value
    if isinstance(value, str) and GUID_RE.fullmatch(value):
        return uuid.UUID(value)
    return None


@dataclass(frozen=True, slots=True)
class _GraphTarget:
    kind: Literal["graph-application", "graph-service-principal"]
    display_name: str
    application: uuid.UUID | None


@dataclass(frozen=True, slots=True)
class _Policy:
    """Immutable copy of the manifest, taken once so later mutation cannot widen scope."""

    tenant_id: uuid.UUID
    subscriptions: frozenset[uuid.UUID]
    resource_groups: frozenset[str]
    test_identities: frozenset[uuid.UUID]
    operations: dict[str, frozenset[str]]
    data_objects: frozenset[tuple[str, str]]
    """(resource ID, operation key) pairs from ``data_objects``."""
    max_api_calls: int
    max_seconds: float
    expires_at: datetime
    strike_expires_at: datetime | None = None
    arm_targets: dict[str, str] = field(default_factory=dict)
    """Strike ARM targets: lowercased ID to ``data_resource`` kind (kv or blob)."""
    graph_targets: dict[uuid.UUID, _GraphTarget] = field(default_factory=dict)
    escalation_sp: uuid.UUID | None = None
    """``strike.escalation.service_principal`` (S4), or None: no escalation at all."""
    marker_role: uuid.UUID | None = None


_ESCALATED_KEYS: Final = frozenset(
    parse_operation(op).key for op in (WRITE_FORM_OPERATIONS[6], WRITE_FORM_OPERATIONS[7])
)
"""The marker assignment and its removal: the escalated identity's only writes."""


def _policy_from(manifest: object) -> _Policy | None:
    if not isinstance(manifest, ScopeManifest):
        return None
    try:
        ops: dict[str, frozenset[str]] = {}
        for verb, op_list in manifest.allowed_operations.items():
            keys = set()
            for op in op_list:
                try:
                    keys.add(parse_operation(op).key)
                except OperationError:
                    continue  # an unparsable entry allows nothing
            ops[str(verb)] = frozenset(keys)
        expires = manifest.expires_at
        if not isinstance(expires, datetime) or expires.tzinfo is None:
            return None
        tenant = _as_uuid(manifest.tenant_id)
        if tenant is None:
            return None
        strike = manifest.strike
        strike_expires: datetime | None = None
        arm_targets: dict[str, str] = {}
        graph_targets: dict[uuid.UUID, _GraphTarget] = {}
        escalation_sp: uuid.UUID | None = None
        marker_role: uuid.UUID | None = None
        if strike is not None and strike.escalation is not None:
            escalation_sp = _as_uuid(str(strike.escalation.service_principal))
            marker_role = _as_uuid(str(strike.escalation.marker_role_id))
            if escalation_sp is None or marker_role is None:
                return None
        if strike is not None:
            strike_expires = strike.expires_at
            if not isinstance(strike_expires, datetime) or strike_expires.tzinfo is None:
                return None
            for t in strike.targets:
                if t.kind == "arm":
                    found = data_resource(t.key)
                    if found is None:
                        return None
                    arm_targets[t.key] = found[0]
                else:
                    if t.display_name is None:
                        return None
                    graph_targets[uuid.UUID(t.key)] = _GraphTarget(
                        t.kind,
                        t.display_name,
                        None if t.application is None else _as_uuid(str(t.application)),
                    )
        test_identities = frozenset(
            u for i in manifest.test_identities if (u := _as_uuid(i.object_id))
        )
        if escalation_sp is not None:
            # Re-checked here because a forged manifest skips the model's validators.
            esc_target = graph_targets.get(escalation_sp)
            if (
                esc_target is None
                or esc_target.kind != "graph-service-principal"
                or esc_target.application is None
                or escalation_sp in test_identities
                or is_first_party(str(marker_role))
            ):
                return None
        return _Policy(
            tenant_id=tenant,
            subscriptions=frozenset(u for s in manifest.subscription_ids if (u := _as_uuid(s))),
            resource_groups=frozenset(
                ArmTarget.parse(rg).path.format() for rg in manifest.allowed_resource_groups
            ),
            test_identities=test_identities,
            operations=ops,
            data_objects=frozenset(
                (parse_arm_id(d.resource).format(), parse_operation(d.operation).key)
                for d in manifest.data_objects
            ),
            max_api_calls=int(manifest.budget.max_api_calls),
            max_seconds=float(manifest.budget.max_minutes) * 60.0,
            expires_at=expires,
            strike_expires_at=strike_expires,
            arm_targets=arm_targets,
            graph_targets=graph_targets,
            escalation_sp=escalation_sp,
            marker_role=marker_role,
        )
    except Exception:  # noqa: BLE001 - any oddity in the manifest means deny everything
        return None


class Gate:
    """Deny-by-default enforcement of one scope manifest for one run."""

    def __init__(
        self,
        manifest: ScopeManifest | None,
        *,
        signed_in_tenant: uuid.UUID | str,
        journal: JournalSink,
        clock: Clock | None = None,
        run_id: str | None = None,
        signed_in_principal: uuid.UUID | str | None = None,
        plan: PlanBinding | None = None,
    ) -> None:
        self._policy = _policy_from(manifest)
        self._plan = plan
        self._lab: dict[uuid.UUID, LabObject] = {}
        self._signed_in = _as_uuid(signed_in_tenant)
        self._principal = _as_uuid(signed_in_principal)
        self._journal = journal
        self._clock: Clock = clock or SystemClock()
        self._started = self._clock.monotonic()
        self._calls = 0
        self._seq = 0
        self.run_id = run_id or uuid.uuid4().hex

    @property
    def calls_used(self) -> int:
        return self._calls

    # -- decision ------------------------------------------------------------------

    def check(
        self,
        verb: str,
        operation: str,
        target: Target | str,
        tenant_id: uuid.UUID | str,
        principal_id: uuid.UUID | str | None = None,
        *,
        url: str | None = None,
        page_of: str | None = None,
    ) -> Decision:
        try:
            return self._check(verb, operation, target, tenant_id, principal_id, url, page_of)
        except Exception as exc:  # noqa: BLE001 - fail closed on any gate bug
            return Denied(DenyReason.INTERNAL_ERROR, f"{type(exc).__name__}")

    def _check(
        self,
        verb: object,
        operation: object,
        target: object,
        tenant_id: object,
        principal_id: object,
        url: object,
        page_of: object,
    ) -> Decision:
        p = self._policy
        if p is None:
            return Denied(DenyReason.NO_MANIFEST, "no valid scope manifest loaded")

        now = self._clock.now()
        if not isinstance(now, datetime) or now.tzinfo is None or now >= p.expires_at:
            return Denied(DenyReason.EXPIRED, f"scope expired at {p.expires_at.isoformat()}")

        call_tenant = _as_uuid(tenant_id)
        if self._signed_in is None or self._signed_in != p.tenant_id or call_tenant != p.tenant_id:
            return Denied(DenyReason.TENANT_MISMATCH, "tenant differs from scope.yaml")

        if not isinstance(verb, str) or verb not in KNOWN_VERBS or verb not in p.operations:
            return Denied(DenyReason.VERB_NOT_ALLOWED, f"verb {verb!r} not allowed by scope")

        try:
            op = parse_operation(operation)
        except OperationError:
            return Denied(DenyReason.MALFORMED_OPERATION, "operation outside the grammar")
        if op.is_data_plane and verb != DATA_PLANE_VERB:
            return Denied(
                DenyReason.DATA_PLANE_VERB_NOT_ALLOWED, f"{op.api} data plane is for prove only"
            )
        if op.key not in p.operations[verb]:
            return Denied(DenyReason.OPERATION_NOT_ALLOWED, f"{op.raw} not allowed for {verb}")
        if not op.is_read and verb in READ_ONLY_VERBS:
            return Denied(DenyReason.WRITE_BY_READ_ONLY_VERB, f"{verb} is read-only")
        if not op.is_read:
            return Denied(DenyReason.WRITE_ON_READ_PATH, "writes go through Gate.check_write")

        resolved: Target
        if isinstance(target, (ArmTarget, DirectoryTarget)):
            resolved = target
        elif isinstance(target, str):
            try:
                resolved = ArmTarget.parse(target)
            except TargetError as exc:
                return Denied(DenyReason.MALFORMED_TARGET, str(exc))
        else:
            return Denied(DenyReason.MALFORMED_TARGET, "target must be an ARM ID or directory")

        if (op.api != "graph") != isinstance(resolved, ArmTarget):
            return Denied(DenyReason.TARGET_KIND_MISMATCH, f"{op.api} operation on {resolved}")

        if isinstance(resolved, ArmTarget):
            denied = self._check_arm_scope(resolved, p)
            if denied is not None:
                return denied

        if op.is_data_plane and isinstance(resolved, ArmTarget):  # kind checked above
            denied = self._check_data_plane(op, resolved, p, url, page_of)
            if denied is not None:
                return denied
        elif url is not None or page_of is not None:
            if not isinstance(url, str):
                return Denied(DenyReason.BAD_URL, "page_of given without url")
            try:
                check_url(op.api, url, resolved)
                if page_of is not None:
                    if not isinstance(page_of, str):
                        return Denied(DenyReason.BAD_URL, "page_of must be a URL")
                    check_next_link(page_of, url)
            except TargetError as exc:
                return Denied(DenyReason.BAD_URL, str(exc))

        if verb == "strike":
            principal = _as_uuid(principal_id)
            if principal is None or principal not in p.test_identities:
                return Denied(
                    DenyReason.PRINCIPAL_NOT_ALLOWED, "strike must act as a test identity"
                )
            if self._principal is not None and principal != self._principal:
                return Denied(DenyReason.PRINCIPAL_MISMATCH, "principal differs from the token")
        if verb == "prove":
            if self._principal is None or self._principal not in p.test_identities:
                return Denied(
                    DenyReason.PRINCIPAL_NOT_ALLOWED,
                    "prove must be signed in as a test identity (token oid)",
                )
            if principal_id is not None and _as_uuid(principal_id) != self._principal:
                return Denied(DenyReason.PRINCIPAL_MISMATCH, "principal differs from the token")

        if self._calls >= p.max_api_calls:
            return Denied(DenyReason.BUDGET_CALLS, f"{p.max_api_calls} API calls used")
        if self._clock.monotonic() - self._started >= p.max_seconds:
            return Denied(DenyReason.BUDGET_TIME, "run time budget used")

        return Allowed(op, str(resolved))

    @staticmethod
    def _check_data_plane(
        op: Operation, target: ArmTarget, p: _Policy, url: object, page_of: object
    ) -> Denied | None:
        found = data_resource(str(target))
        if found is None or found[0] != op.api:
            return Denied(
                DenyReason.TARGET_KIND_MISMATCH, f"{op.api} operation on a non-{op.api} resource"
            )
        _, name = found
        resource = str(target)
        if op.path == "/secrets":
            bound = any(r == resource and k.startswith("kv:") for r, k in p.data_objects)
        else:
            bound = (resource, op.key) in p.data_objects
        if not bound:
            return Denied(
                DenyReason.DATA_OBJECT_NOT_ALLOWED, f"{op.raw} is not a data object of the target"
            )
        if not isinstance(url, str):
            return Denied(DenyReason.BAD_URL, "a data-plane call needs its exact URL")
        if page_of is not None:
            return Denied(DenyReason.BAD_URL, "no paging on the data plane")
        try:
            check_data_url(op.api, url, name, op.path)
        except TargetError as exc:
            return Denied(DenyReason.BAD_URL, str(exc))
        return None

    @staticmethod
    def _check_arm_scope(target: ArmTarget, p: _Policy) -> Denied | None:
        path = target.path
        level = path.level
        if level == "tenant":
            return Denied(
                DenyReason.TENANT_LEVEL_NOT_ALLOWED, "tenant-root ARM targets are out of scope"
            )
        if level == "managementGroup":
            return Denied(
                DenyReason.MG_NOT_ALLOWED, "management group targets are out of scope in M1"
            )
        if path.subscription_id not in p.subscriptions:
            return Denied(DenyReason.SUBSCRIPTION_NOT_ALLOWED, "subscription not in scope.yaml")
        if path.resource_group is None:
            # Subscription scope, or a provider resource directly on it (e.g. a role
            # definition). Reads only: writes are denied before this point in M1, and
            # when writes arrive they must be limited to resources inside allowed RGs.
            return None
        if path.resource_group_id not in p.resource_groups:
            return Denied(DenyReason.RG_NOT_ALLOWED, "resource group not in scope.yaml")
        return None

    # -- writes ----------------------------------------------------------------------

    def check_write(self, request: WriteRequest) -> Decision:
        """Decide one write. Deny by default; see the module docstring for the order."""
        return self._decide_write(request)[0]

    def _decide_write(self, request: object) -> tuple[Decision, str]:
        try:
            return self._check_write(request)
        except WriteRefusedError as exc:
            return Denied(_REFUSALS[exc.kind], exc.detail), ""
        except Exception as exc:  # noqa: BLE001 - fail closed on any gate bug
            return Denied(DenyReason.INTERNAL_ERROR, f"{type(exc).__name__}"), ""

    def _check_write(self, r: object) -> tuple[Decision, str]:
        if not isinstance(r, WriteRequest):
            return Denied(DenyReason.MALFORMED_OPERATION, "not a WriteRequest"), ""
        why = hard_deny(r.url, [r.operation, r.method, r.body])
        if why is not None:
            return Denied(DenyReason.HARD_DENY, why), ""

        p = self._policy
        if p is None:
            return Denied(DenyReason.NO_MANIFEST, "no valid scope manifest loaded"), ""
        now = self._clock.now()
        if not isinstance(now, datetime) or now.tzinfo is None or now >= p.expires_at:
            return Denied(DenyReason.EXPIRED, f"scope expired at {p.expires_at.isoformat()}"), ""
        if p.strike_expires_at is None:
            return Denied(DenyReason.NO_STRIKE_SCOPE, "the scope has no strike: block"), ""
        if now >= p.strike_expires_at:
            at = p.strike_expires_at.isoformat()
            return Denied(DenyReason.EXPIRED, f"strike scope expired at {at}"), ""
        call_tenant = _as_uuid(r.tenant_id)
        if self._signed_in is None or self._signed_in != p.tenant_id or call_tenant != p.tenant_id:
            return Denied(DenyReason.TENANT_MISMATCH, "tenant differs from scope.yaml"), ""

        if r.verb != "strike" or "strike" not in p.operations:
            return Denied(DenyReason.VERB_NOT_ALLOWED, "only strike writes"), ""
        if r.operation == TOKEN_OPERATION:
            return self._check_token(r, p)
        try:
            op = parse_operation(r.operation)
        except OperationError:
            return Denied(DenyReason.MALFORMED_OPERATION, "operation outside the grammar"), ""
        form = FORMS_BY_KEY.get(op.key)
        if form is None:
            return Denied(DenyReason.NOT_A_WRITE_FORM, f"{op.raw} is not a write form"), ""
        if op.key not in p.operations["strike"]:
            return Denied(DenyReason.OPERATION_NOT_ALLOWED, f"{op.raw} not listed for strike"), ""
        escalated = p.escalation_sp is not None and self._principal == p.escalation_sp
        reason = DenyReason.PRINCIPAL_NOT_ALLOWED
        if self._principal is None or not (escalated or self._principal in p.test_identities):
            return Denied(reason, "strike writes only signed in as a test identity"), ""
        if escalated and op.key not in _ESCALATED_KEYS:
            detail = "the escalated identity may only assign the marker role and remove it"
            return Denied(reason, detail), ""
        if not escalated and op.key in _ESCALATED_KEYS:
            return Denied(reason, "only the escalated identity (S4) assigns the marker role"), ""

        m = match_form(form, r.method, r.url, p.arm_targets)
        if escalated and m.sp != p.escalation_sp:
            reason = DenyReason.STRIKE_TARGET_NOT_ALLOWED
            return Denied(reason, "the escalated identity writes only to its own SP"), ""
        if m.arm_target is not None:
            denied = self._check_arm_scope(ArmTarget.parse(m.arm_target), p)
            if denied is not None:
                return denied, ""
        slots = ((m.app, "graph-application"), (m.sp, "graph-service-principal"))
        for slot, want in slots:
            if slot is None:
                continue
            target = p.graph_targets.get(slot)
            if target is None or target.kind != want:
                return Denied(DenyReason.STRIKE_TARGET_NOT_ALLOWED, f"{slot} is not a {want}"), ""
            if slot not in self._lab:
                reason = DenyReason.LAB_CHECK_FAILED
                return Denied(reason, f"{slot} has not passed the live lab check"), ""
        if m.principal is not None and m.principal not in p.test_identities:
            reason = DenyReason.STRIKE_TARGET_NOT_ALLOWED
            return Denied(reason, "the owner removed must be a test identity"), ""

        digest = sha256_hex(canonical_body(r.body))
        ctx = BodyContext(
            now=now,
            test_identities=p.test_identities,
            lab=dict(self._lab),
            sp_application={
                k: t.application for k, t in p.graph_targets.items() if t.application is not None
            },
            marker_role=p.marker_role,
        )
        check_body(form, r.body, m, ctx)

        return self._admit(r, p, digest, Allowed(op, m.target))

    def _admit(self, r: WriteRequest, p: _Policy, digest: str, ok: Allowed) -> tuple[Decision, str]:
        """The last two steps of every write: the approved plan, then the budget."""
        if self._plan is None:
            return Denied(DenyReason.NO_APPROVED_PLAN, "no approved strike plan"), digest
        if self._plan.admits(r, digest) is not True:
            return Denied(DenyReason.NOT_IN_APPROVED_PLAN, "not a step of the plan"), digest
        if self._calls >= p.max_api_calls:
            return Denied(DenyReason.BUDGET_CALLS, f"{p.max_api_calls} API calls used"), digest
        if self._clock.monotonic() - self._started >= p.max_seconds:
            return Denied(DenyReason.BUDGET_TIME, "run time budget used"), digest
        return ok, digest

    def _check_token(self, r: WriteRequest, p: _Policy) -> tuple[Decision, str]:
        """S4 step 1: the escalation target's client-credentials token request."""
        esc = p.escalation_sp
        if esc is None or p.marker_role is None:
            return Denied(DenyReason.NO_STRIKE_SCOPE, "the scope has no strike.escalation"), ""
        if self._principal is None or self._principal not in p.test_identities:
            reason = DenyReason.PRINCIPAL_NOT_ALLOWED
            return Denied(reason, "the token request is sent by a test identity"), ""
        if r.method != "POST" or r.url != token_url(p.tenant_id):
            detail = f"the token request is exactly POST {token_url(p.tenant_id)}"
            return Denied(DenyReason.BAD_URL, detail), ""
        target = p.graph_targets.get(esc)
        app = None if target is None else target.application
        lab_sp = self._lab.get(esc)
        lab_app = None if app is None else self._lab.get(app)
        if lab_sp is None or lab_app is None:
            reason = DenyReason.LAB_CHECK_FAILED
            return Denied(reason, "the escalation target has not passed the live lab check"), ""
        check_token_body(r.body, lab_app.app_id)
        digest = sha256_hex(canonical_body(r.body))
        op = Operation("graph", TOKEN_OPERATION, TOKEN_OPERATION, is_read=False)
        return self._admit(r, p, digest, Allowed(op, f"directory/{esc}"))

    def record_lab_check(self, object_id: uuid.UUID | str, observed: object) -> Denied | None:
        """Feed the gate a live ``GET`` of a Graph strike target (strike plan rule 5).

        Writes to a Graph target are denied until this passes. The first passing read
        is kept as the pre-state (an application's ``appRoles``); later reads are
        checked again but do not replace it.
        """
        try:
            p = self._policy
            if p is None:
                return Denied(DenyReason.NO_MANIFEST, "no valid scope manifest loaded")
            now = self._clock.now()
            if p.strike_expires_at is None:
                return Denied(DenyReason.NO_STRIKE_SCOPE, "the scope has no strike: block")
            if now >= p.expires_at or now >= p.strike_expires_at:
                return Denied(DenyReason.EXPIRED, "scope or strike scope expired")
            oid = _as_uuid(object_id)
            target = None if oid is None else p.graph_targets.get(oid)
            if oid is None or target is None:
                return Denied(DenyReason.STRIKE_TARGET_NOT_ALLOWED, "not a Graph strike target")
            app = None if target.application is None else self._lab.get(target.application)
            obj = check_lab_object(
                target.kind,
                oid,
                target.display_name,
                observed,
                tenant_id=p.tenant_id,
                application=app,
            )
            self._lab.setdefault(oid, obj)
            return None
        except WriteRefusedError as exc:
            return Denied(DenyReason.LAB_CHECK_FAILED, exc.detail)
        except Exception as exc:  # noqa: BLE001 - fail closed
            return Denied(DenyReason.INTERNAL_ERROR, f"{type(exc).__name__}")

    def call_write(self, request: WriteRequest, fn: Callable[[], T]) -> T:
        """Check, journal, reserve budget, then run ``fn``. Raises on denial.

        The journal row carries the method and the body's sha256, never the body.
        """
        decision, digest = self._decide_write(request)
        self._seq += 1
        seq = self._seq
        r = request if isinstance(request, WriteRequest) else None
        allowed = isinstance(decision, Allowed)
        record = GateRecord(
            run_id=self.run_id,
            seq=seq,
            verb=r.verb if r else "",
            operation=r.operation if r else "",
            target=decision.target if isinstance(decision, Allowed) else "",
            tenant_id=str(r.tenant_id) if r else "",
            principal_id=None if self._principal is None else str(self._principal),
            url=r.url if r else None,
            decision="allowed" if allowed else "denied",
            reason=None if isinstance(decision, Allowed) else decision.reason.value,
            detail=(
                f"{r.method} body sha256:{digest}"
                if r and isinstance(decision, Allowed)
                else getattr(decision, "detail", "")
            ),
            at=self._clock.now(),
        )
        try:
            self._journal.record_decision(record)
        except Exception as exc:
            raise ScopeDeniedError(
                Denied(DenyReason.JOURNAL_FAILED, f"journal unavailable: {type(exc).__name__}")
            ) from exc
        if isinstance(decision, Denied):
            raise ScopeDeniedError(decision)
        if r is None:  # an Allowed decision always has a WriteRequest
            raise ScopeDeniedError(Denied(DenyReason.INTERNAL_ERROR, "no request"))

        self._calls += 1  # reserved before the call so a crash cannot under-count
        try:
            result = fn()
        except BaseException as exc:
            self._journal.record_call_result(
                self.run_id, seq, "failed", type(exc).__name__, self._clock.now()
            )
            raise
        self._journal.record_call_result(self.run_id, seq, "succeeded", "", self._clock.now())
        return result

    # -- execution -------------------------------------------------------------------

    def call(
        self,
        verb: str,
        operation: str,
        target: Target | str,
        tenant_id: uuid.UUID | str,
        fn: Callable[[], T],
        *,
        url: str,
        principal_id: uuid.UUID | str | None = None,
        page_of: str | None = None,
    ) -> T:
        """Check, journal, reserve budget, then run ``fn``. Raises on denial."""
        decision = self.check(
            verb, operation, target, tenant_id, principal_id, url=url, page_of=page_of
        )
        self._seq += 1
        seq = self._seq
        record = GateRecord(
            run_id=self.run_id,
            seq=seq,
            verb=str(verb),
            operation=str(operation),
            target=str(target),
            tenant_id=str(tenant_id),
            principal_id=None if principal_id is None else str(principal_id),
            url=url,
            decision="allowed" if decision.allowed else "denied",
            reason=None if isinstance(decision, Allowed) else decision.reason.value,
            detail="" if isinstance(decision, Allowed) else decision.detail,
            at=self._clock.now(),
        )
        try:
            self._journal.record_decision(record)
        except Exception as exc:
            raise ScopeDeniedError(
                Denied(DenyReason.JOURNAL_FAILED, f"journal unavailable: {type(exc).__name__}")
            ) from exc
        if isinstance(decision, Denied):
            raise ScopeDeniedError(decision)

        self._calls += 1  # reserved before the call so a crash cannot under-count
        try:
            result = fn()
        except BaseException as exc:
            self._journal.record_call_result(
                self.run_id, seq, "failed", type(exc).__name__, self._clock.now()
            )
            raise
        self._journal.record_call_result(self.run_id, seq, "succeeded", "", self._clock.now())
        return result
