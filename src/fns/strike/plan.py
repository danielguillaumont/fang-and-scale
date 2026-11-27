"""Strike plans: the ordered writes, their undos, the hash the operator approves.

``fns strike plan`` writes a :class:`StrikePlan` and prints ``plan sha256:<hash>``.
``fns strike run --approve <hash>`` recomputes the hash and refuses any difference
(M4 strike plan, "Plan, approval, journal and cleanup"). The hash covers the whole
plan: every request and body, every undo, the pre-state the undos restore, the
scope file's digest, the run ID, the agent's object ID and the expiry.

Some undo requests need an ID the strike itself returns (``addPassword``'s
``keyId``). The plan carries a placeholder, ``{{learned:<write key>:<field>}}``;
the runner fills it from the journaled response, and :class:`ApprovedPlan` admits
the request only in that exact filled-in form.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, ClassVar, Final, Literal

from pydantic import Field

from fns.models.base import FnsModel, sha256_hex
from fns.models.ids import TzDatetime
from fns.scope.gate import WriteRequest
from fns.scope.writes import canonical_body

StrikeId = Literal["S1", "S2", "S3", "S4", "D-1", "D-2", "D-3", "D-4", "D-5", "D-6", "D-7"]
BEFORE_HARDEN: Final[tuple[StrikeId, ...]] = ("S1", "S2", "S3", "S4")
AFTER_HARDEN: Final[tuple[StrikeId, ...]] = ("D-1", "D-2", "D-3", "D-4", "D-5", "D-6", "D-7")
PLAN_LIFETIME: Final = timedelta(hours=1)
_LEARNED = re.compile(r"\{\{learned:([A-Za-z0-9/._-]+):([A-Za-z0-9_]+)\}\}")


class PlanError(ValueError):
    """The plan cannot be built, approved or rendered."""


class PlannedRequest(FnsModel):
    __omit_empty__: ClassVar[frozenset[str]] = frozenset({"acts_as"})

    operation: str
    """The write form (one of ``WRITE_FORM_OPERATIONS``), or S4's
    ``token:client_credentials``."""
    method: Literal["POST", "PATCH", "DELETE"]
    url: str
    body: Any = None
    learn: tuple[str, ...] = ()
    """Top-level response fields to journal (IDs only; secrets are stripped first)."""
    acts_as: Literal["escalated"] | None = None
    """``escalated``: sent as the escalation target, with S4's token, through a gate
    signed in as that identity. Absent: sent as the agent."""


class PlannedWrite(FnsModel):
    key: str = Field(pattern=r"^[A-Z0-9-]+/[a-z0-9-]+$")
    """``<strike>/<name>``, unique in the plan, and the journal's step key."""
    strike: StrikeId
    request: PlannedRequest
    expect: Literal["allowed", "denied"]
    """``denied``: an after-harden attempt (D6); success means the contract fails."""
    undo: tuple[PlannedRequest, ...] = ()
    """Sent in this order, after every later write's undo (reverse order overall)."""
    lab_objects: tuple[str, ...] = ()
    """Graph objects the gate must live-check before this write (an app before its SP)."""
    observes: tuple[str, ...] = ()
    """After-harden attempts: the contract items a denial is an observed result for
    (the strike plan's D6 table). Recorded only; verdicts don't read it yet."""


class StrikePlan(FnsModel):
    version: Literal[1] = 1
    run_id: str = Field(pattern=r"^[a-z0-9-]{8,40}$")
    tenant_id: str
    scope_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    agent_object_id: str
    created_at: TzDatetime
    expires_at: TzDatetime
    strikes: tuple[StrikeId, ...] = Field(min_length=1)
    targets: dict[str, str]
    """The lab objects by role (``payroll``, ``vault``, ``escalation_app``...), from
    the scope's ``strike.targets``."""
    pre_state: dict[str, Any]
    """What the scout read before planning, by object; the verification compares
    against it, and the run refuses to start if it changed."""
    writes: tuple[PlannedWrite, ...] = Field(min_length=1)

    def plan_hash(self) -> str:
        return sha256_hex(self.canonical_json())

    def write(self, key: str) -> PlannedWrite:
        for w in self.writes:
            if w.key == key:
                return w
        raise PlanError(f"no write {key!r} in the plan")


def new_run_id(now: datetime) -> str:
    return f"{now:%Y%m%d%H%M}-{uuid.uuid4().hex[:6]}"


# --- rendering learned values -------------------------------------------------------


class UnresolvedError(PlanError):
    """An undo needs an ID the journal does not have (the strike's answer was lost)."""


def _fill(text: str, learned: Mapping[str, Mapping[str, str]]) -> str:
    def one(m: re.Match[str]) -> str:
        value = learned.get(m[1], {}).get(m[2])
        if not isinstance(value, str) or not value:
            raise UnresolvedError(f"{m[1]} did not return {m[2]}")
        return value

    return _LEARNED.sub(one, text)


def render(value: object, learned: Mapping[str, Mapping[str, str]]) -> Any:
    if isinstance(value, str):
        return _fill(value, learned)
    if isinstance(value, Mapping):
        return {str(k): render(v, learned) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [render(v, learned) for v in value]
    return value


def needs(value: object) -> set[str]:
    """The write keys whose answers ``value`` depends on."""
    if isinstance(value, str):
        return {m[1] for m in _LEARNED.finditer(value)}
    if isinstance(value, Mapping):
        return {k for v in value.values() for k in needs(v)}
    if isinstance(value, list | tuple):
        return {k for v in value for k in needs(v)}
    return set()


@dataclass(frozen=True, slots=True)
class Rendered:
    operation: str
    method: str
    url: str
    body: object

    @property
    def body_digest(self) -> str:
        return sha256_hex(canonical_body(self.body))


def render_request(request: PlannedRequest, learned: Mapping[str, Mapping[str, str]]) -> Rendered:
    return Rendered(
        request.operation,
        request.method,
        render(request.url, learned),
        render(request.body, learned),
    )


# --- approval -----------------------------------------------------------------------


class PlanRejectedError(PlanError):
    """The approved hash does not match the plan, or the plan expired."""


@dataclass
class ApprovedPlan:
    """The gate's :class:`~fns.scope.gate.PlanBinding` for one approved plan.

    The runner *arms* the one request it is about to send; :meth:`admits` accepts
    exactly that request, once. Anything else, including a planned request sent
    twice or out of turn, is refused by the gate as ``not-in-approved-plan``.
    """

    plan: StrikePlan
    approved_hash: str
    _armed: Rendered | None = field(default=None, init=False)
    _sent: list[Rendered] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        actual = self.plan.plan_hash()
        if self.approved_hash.removeprefix("sha256:") != actual:
            raise PlanRejectedError(f"--approve does not match this plan (plan sha256:{actual})")
        self._planned = {
            (r.operation, r.method) for w in self.plan.writes for r in (w.request, *w.undo)
        }

    def check_fresh(self, now: datetime) -> None:
        if now >= self.plan.expires_at:
            raise PlanRejectedError(f"the plan expired at {self.plan.expires_at.isoformat()}")

    def arm(self, request: Rendered) -> None:
        if (request.operation, request.method) not in self._planned:
            raise PlanRejectedError("arming a request that is not in the plan")
        self._armed = request

    def disarm(self) -> None:
        self._armed = None

    def admits(self, request: WriteRequest, body_digest: str) -> bool:
        armed = self._armed
        if armed is None:
            return False
        same = (
            request.operation == armed.operation
            and request.method == armed.method
            and request.url == armed.url
            and body_digest == armed.body_digest
        )
        if same:
            self._armed = None
            self._sent.append(armed)
        return same

    @property
    def sent(self) -> tuple[Rendered, ...]:
        return tuple(self._sent)
