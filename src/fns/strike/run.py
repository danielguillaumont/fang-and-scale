"""Run an approved strike plan, undo everything, verify, and clean up after a crash.

Order for ``fns strike run`` (M4 strike plan, "Plan, approval, journal and cleanup"):

1. the approved hash must equal the plan's, the plan must be fresh, the signed-in
   principal must be the plan's agent, and the scope file must be the one planned;
2. the scout re-reads the pre-state; any change since planning stops the run
   before the first write;
3. for each planned write: the live lab check of its Graph objects, an
   ``intent`` journal row, the gated write, a ``result`` row (status and the IDs it
   returned; the transport has already stripped the secrets);
4. **in a ``finally``**, the undo of every write that may have happened, in reverse
   order, each journaled the same way. That covers a failed step, a gate denial,
   a transport error and Ctrl-C. An undo that needs an ID the journal lacks (the
   answer was lost) finds it by the run's credential name instead, as the scout.
   An after-harden attempt (``expect: denied``) that succeeds is undone at once;
5. verification: the scout reads every object back and compares it with the
   pre-state.

S4 (approved 2026-11-27) runs only right after S3's password went through. Its
token request goes through the agent's gate and the :class:`Escalation`'s token
transport. The token's claims must show the capability (``oid`` is the escalation
target, ``roles`` has ``AppRoleAssignment.ReadWrite.All``, and ``tid`` and
``appid`` match), or S4 stops there. That check reads the claims without verifying
the token's signature, so it is a **safety stop only** (approved 2026-11-27): it
decides whether S4 may go on, and is never verdict evidence. Its result is
journaled as ``safety_stop`` for the operator, never written to
``strike-run.json``, and ``fns prove --after-strike`` counts no S4 write. Either
way S3's password is removed at once, before anything else is sent. Only ``oid``
and ``roles`` are journaled; the token stays in the secret holder. The assignment
and its undo go through a second gate, signed in as the token's ``oid``.
:func:`cleanup` has no token, so it can't undo the assignment: it says so, and the
verification fails (exit 5) until the runbook's emergency cleanup removes it.

Exit codes: 0 clean; 1 an after-harden attempt succeeded (the contract fails); 4
the gate denied a planned write; 5 the verification found a difference (the
runbook's emergency cleanup applies). 5 wins over 4, and 4 over 1.

:func:`cleanup` is the resume path: it reads the journal, finds every write without
a successful undo, and runs those undos and the verification.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final, Literal, Protocol

from fns.adapters.azure.http import TransportError
from fns.exitcodes import ExitCode
from fns.journal.sqlite import StrikePhase
from fns.scope.credentials import CredentialError, TokenProvider, token_claims
from fns.scope.gate import Clock, Gate, ScopeDeniedError, SystemClock, WriteRequest
from fns.scope.writes import CAPABILITY_ROLE, CREDENTIAL_PREFIX, TOKEN_OPERATION
from fns.strike.plan import (
    ApprovedPlan,
    PlannedRequest,
    PlannedWrite,
    Rendered,
    StrikePlan,
    UnresolvedError,
    needs,
    render_request,
)
from fns.strike.reader import LabReader, ReadError
from fns.strike.secrets import ACCESS_TOKEN, HeldToken, SecretHolder
from fns.strike.strikes import ASSIGN_KEY, S3_KEY, TOKEN_KEY, LabTargets, read_pre_state
from fns.strike.transport import (
    StrikeRequest,
    StrikeResponse,
    StrikeTransport,
    TokenTransport,
    TokenWire,
)

Outcome = Literal[
    "succeeded",  # an expected-allowed write went through: capability observed
    "denied",  # 401 or 403: an observed denial
    "unexpected-success",  # an expected-denied write went through: the contract fails
    "failed",  # another status: neither allowed nor denied
    "gate-denied",  # the scope gate refused it: never sent
    "unknown",  # sent, but no answer (transport error, interrupt)
    "not-run",
]
MAX_DETAIL: Final = 300
JournalEvent = tuple[str, StrikePhase, Mapping[str, object]]


class StrikeJournal(Protocol):
    def begin_run(self, run_id: str, verb: str, mode: Literal["LIVE", "FIXTURE"]) -> None: ...
    def has_run(self, run_id: str) -> bool: ...
    def strike_event(
        self, run_id: str, write_key: str, phase: StrikePhase, detail: dict[str, object]
    ) -> None: ...
    def strike_events(self, run_id: str) -> list[tuple[str, StrikePhase, dict[str, object]]]: ...


class StrikeStartError(RuntimeError):
    """Nothing was sent: wrong identity, changed scope, changed pre-state."""


@dataclass(frozen=True)
class Escalation:
    """What S4 needs besides the agent's gate and transport."""

    token_transport: TokenTransport
    gate_factory: Callable[[ApprovedPlan, str], Gate]
    """A gate signed in as the given principal (the proven token's ``oid``)."""
    transport_factory: Callable[[TokenProvider], StrikeTransport]
    """A write transport that authorises with the given provider (S4's token)."""


def token_proof(claims: Mapping[str, object], plan: StrikePlan) -> str | None:
    """Why S4 must stop here, or None when it may go on.

    A safety stop only: the signature is not verified (the token came straight
    from the issuer over TLS), so the answer is never verdict evidence."""
    t = plan.targets
    roles = claims.get("roles")
    if str(claims.get("tid", "")).lower() != plan.tenant_id:
        return "the token is for another tenant"
    if str(claims.get("oid", "")).lower() != t.get("escalation_sp"):
        return "the token's oid is not app-escalation-target's service principal"
    app = claims.get("appid") or claims.get("azp") or ""  # v1 tokens: appid; v2: azp
    if str(app).lower() != t.get("escalation_app_id"):
        return "the token's appid is not app-escalation-target's"
    if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
        return "the token has no roles claim"
    if CAPABILITY_ROLE not in roles:
        return f"the token's roles do not include {CAPABILITY_ROLE}"
    return None


def recorded_claims(claims: Mapping[str, object]) -> dict[str, object]:
    """The only token content ever journaled: ``oid`` and ``roles``."""
    roles = claims.get("roles")
    return {
        "oid": str(claims.get("oid", "")).lower()[:64],
        "roles": sorted(str(r)[:128] for r in roles)[:50] if isinstance(roles, list) else [],
    }


@dataclass
class WriteOutcome:
    key: str
    strike: str
    expect: str
    outcome: Outcome = "not-run"
    status: int | None = None
    undo: list[str] = field(default_factory=list)
    observes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Check:
    what: str
    ok: bool
    detail: str


@dataclass
class StrikeRun:
    run_id: str
    plan_hash: str
    writes: list[WriteOutcome]
    checks: list[Check] = field(default_factory=list)
    aborted: str | None = None

    @property
    def verified(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks)

    @property
    def exit_code(self) -> ExitCode:
        if not self.verified:
            return ExitCode.EVIDENCE_INVALID
        if any(w.outcome == "gate-denied" for w in self.writes):
            return ExitCode.SCOPE_DENIED
        if any(w.outcome == "unexpected-success" for w in self.writes):
            return ExitCode.CONTRACT_FAILED
        return ExitCode.OK

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "plan_hash": f"sha256:{self.plan_hash}",
            "aborted": self.aborted,
            "writes": [
                {
                    "key": w.key,
                    "strike": w.strike,
                    "expect": w.expect,
                    "outcome": w.outcome,
                    "status": w.status,
                    "undo": list(w.undo),
                    "observes": list(w.observes),
                }
                for w in self.writes
            ],
            "verification": [{"what": c.what, "ok": c.ok, "detail": c.detail} for c in self.checks],
            "exit_code": int(self.exit_code),
        }


def _api(operation: str) -> Literal["arm", "graph"]:
    return "arm" if operation.startswith("arm:") else "graph"


def _short(text: str) -> str:
    return text if len(text) <= MAX_DETAIL else text[:MAX_DETAIL] + "..."


def _is_2xx(value: object) -> bool:
    return isinstance(value, int) and 200 <= value < 300


@dataclass
class _Engine:
    plan: StrikePlan
    binding: ApprovedPlan
    gate: Gate
    transport: StrikeTransport
    reader: LabReader
    journal: StrikeJournal
    holder: SecretHolder = field(default_factory=SecretHolder)
    learned: dict[str, dict[str, str]] = field(default_factory=dict)
    checked: dict[int, set[str]] = field(default_factory=dict)
    escalation: Escalation | None = None
    esc_gate: Gate | None = None
    esc_transport: StrikeTransport | None = None

    def event(self, key: str, phase: StrikePhase, **detail: object) -> None:
        self.journal.strike_event(self.plan.run_id, key, phase, dict(detail))

    def lab_check(self, w: PlannedWrite, gate: Gate | None = None) -> None:
        gate = gate or self.gate
        done = self.checked.setdefault(id(gate), set())
        for oid in w.lab_objects:
            if oid in done:
                continue
            if oid == self.plan.targets.get("escalation_sp"):
                observed = self.reader.service_principal(oid)
            else:
                observed = self.reader.application(oid)
            denied = gate.record_lab_check(oid, observed)
            if denied is not None:
                raise ScopeDeniedError(denied)
            done.add(oid)

    def _request(self, r: Rendered) -> WriteRequest:
        return WriteRequest(
            verb="strike",
            operation=r.operation,
            method=r.method,
            url=r.url,
            body=r.body,
            tenant_id=self.plan.tenant_id,
        )

    def send(self, key: str, r: Rendered, *, escalated: bool = False) -> StrikeResponse:
        gate, transport = self.gate, self.transport
        if escalated:
            if self.esc_gate is None or self.esc_transport is None:
                raise UnresolvedError(f"{key}: the escalated identity is not signed in")
            gate, transport = self.esc_gate, self.esc_transport
        wire = StrikeRequest(_api(r.operation), r.method, r.url, r.body)
        self.binding.arm(r)
        try:
            return gate.call_write(self._request(r), lambda: transport.send(wire, self.holder, key))
        finally:
            self.binding.disarm()

    def token(self, w: PlannedWrite, out: WriteOutcome) -> bool:
        """S4 step 1: S3's password for a token, then the safety stop on its claims."""
        r = render_request(w.request, self.learned)
        secret = self.holder.get(S3_KEY, "/secretText")
        if self.escalation is None or not isinstance(secret, str) or not secret:
            out.outcome = "not-run"
            self.event(w.key, "error", kind="not-run", detail="S3's password is not held")
            return False
        esc = self.escalation
        self.event(w.key, "intent", method=r.method, url=r.url, body_sha256=r.body_digest)
        form = {str(k): str(v) for k, v in dict(r.body).items()} if isinstance(r.body, dict) else {}
        try:
            self.lab_check(w)
            self.binding.arm(r)
            try:
                resp = self.gate.call_write(
                    self._request(r),
                    lambda: esc.token_transport.send_token(
                        TokenWire(r.url, form), secret, self.holder, w.key
                    ),
                )
            finally:
                self.binding.disarm()
        except ScopeDeniedError as exc:
            out.outcome = "gate-denied"
            self.event(w.key, "error", kind="gate-denied", detail=_short(str(exc)))
            raise
        except BaseException as exc:
            out.outcome = "unknown"
            self.event(w.key, "error", kind="unknown", detail=type(exc).__name__)
            raise
        secret = ""  # this frame's reference; the holder dropped S3's copy (_remove_s3_now)
        claims: dict[str, object] = {}
        held = self.holder.get(w.key, ACCESS_TOKEN)
        if resp.ok and isinstance(held, str):
            try:
                claims = token_claims(held)
            except CredentialError:
                claims = {}
        del held
        why = (
            (token_proof(claims, self.plan) if claims else "no readable token") if resp.ok else None
        )
        out.status = resp.status
        if resp.ok and why is None:
            out.outcome = "succeeded"
        else:
            out.outcome = "denied" if resp.denied else "failed"
            self.holder.drop(w.key)  # a token that proves nothing is not kept
        self.event(
            w.key,
            "result",
            status=resp.status,
            outcome=out.outcome,
            learned={},
            claims=recorded_claims(claims),
            safety_stop="passed" if out.outcome == "succeeded" else _short(why or "no token"),
            request_id=resp.request_id,
            secrets_removed=resp.secrets_removed,
        )
        if out.outcome == "succeeded":
            oid = str(claims["oid"]).lower()
            self.esc_gate = esc.gate_factory(self.binding, oid)
            self.esc_transport = esc.transport_factory(HeldToken(self.holder, w.key))
        return out.outcome == "succeeded"

    def write(self, w: PlannedWrite, out: WriteOutcome) -> bool:
        """Send one planned write. Returns True when it went through."""
        if w.request.operation == TOKEN_OPERATION:
            return self.token(w, out)
        escalated = w.request.acts_as == "escalated"
        if escalated and self.esc_gate is None:
            out.outcome = "not-run"
            self.event(w.key, "error", kind="not-run", detail="S4's token did not prove it")
            return False
        r = render_request(w.request, self.learned)
        self.event(w.key, "intent", method=r.method, url=r.url, body_sha256=r.body_digest)
        try:
            self.lab_check(w, self.esc_gate if escalated else None)
            resp = self.send(w.key, r, escalated=escalated)
        except ScopeDeniedError as exc:
            out.outcome = "gate-denied"
            self.event(w.key, "error", kind="gate-denied", detail=_short(str(exc)))
            raise
        except BaseException as exc:
            out.outcome = "unknown"
            self.event(w.key, "error", kind="unknown", detail=type(exc).__name__)
            raise
        learned = {f: v for f in w.request.learn if isinstance(v := resp.body.get(f), str) and v}
        if resp.ok and learned:
            self.learned[w.key] = learned
        out.status = resp.status
        if resp.ok:
            out.outcome = "succeeded" if w.expect == "allowed" else "unexpected-success"
        else:
            out.outcome = "denied" if resp.denied else "failed"
        self.event(
            w.key,
            "result",
            status=resp.status,
            outcome=out.outcome,
            learned=learned,
            request_id=resp.request_id,
            secrets_removed=resp.secrets_removed,
        )
        return resp.ok

    def resolve(self, w: PlannedWrite) -> list[dict[str, str]]:
        """The learned values for ``w``'s undo: from the journal, else found by name."""
        if w.key in self.learned:
            return [self.learned[w.key]]
        if not any(needs(u.model_dump()) for u in w.undo):
            return [{}]
        if w.request.operation.endswith("/addPassword") and w.lab_objects:
            name = f"{CREDENTIAL_PREFIX}{self.plan.run_id}"
            creds = self.reader.application(w.lab_objects[0]).get("passwordCredentials")
            return [
                {"keyId": str(c["keyId"])}
                for c in (creds if isinstance(creds, list) else [])
                if isinstance(c, dict) and c.get("displayName") == name and c.get("keyId")
            ]
        if w.key == ASSIGN_KEY:
            t = self.plan.targets
            return [
                {"id": a["id"]}
                for a in self.reader.assigned_to(t["escalation_sp"])
                if a["principalId"] == self.plan.agent_object_id
                and a["appRoleId"] == t["marker_role"]
            ]
        raise UnresolvedError(f"{w.key}: cannot find what to undo")

    def undo(self, w: PlannedWrite, out: WriteOutcome) -> None:
        if any(u.acts_as == "escalated" for u in w.undo) and self.esc_gate is None:
            out.undo.append("needs-emergency-cleanup")
            self.event(
                w.key,
                "undo-error",
                kind="no-escalated-identity",
                detail="the escalated token is gone: run the runbook's emergency cleanup",
            )
            return
        try:
            found = self.resolve(w)
        except (UnresolvedError, ReadError, ScopeDeniedError, TransportError) as exc:
            out.undo.append("unresolved")
            self.event(w.key, "undo-error", kind="unresolved", detail=_short(str(exc)))
            return
        if not found:
            out.undo.append("nothing-to-undo")
            self.event(w.key, "undo-result", outcome="nothing-to-undo")
            return
        for values in found:
            for u in w.undo:
                self._undo_one(w, u, values, out)

    def _undo_one(
        self, w: PlannedWrite, u: PlannedRequest, values: dict[str, str], out: WriteOutcome
    ) -> None:
        try:
            r = render_request(u, {**self.learned, w.key: values})
            self.event(w.key, "undo-intent", method=r.method, url=r.url, body_sha256=r.body_digest)
            escalated = u.acts_as == "escalated"
            self.lab_check(w, self.esc_gate if escalated else None)
            resp = self.send(w.key, r, escalated=escalated)
        except Exception as exc:  # noqa: BLE001 - one failed undo must not stop the others
            out.undo.append("error")
            self.event(w.key, "undo-error", kind=type(exc).__name__, detail=_short(str(exc)))
            return
        out.undo.append(str(resp.status))
        self.event(w.key, "undo-result", status=resp.status, request_id=resp.request_id)


# --- verification -------------------------------------------------------------------


def _later(now: object, before: object) -> bool:
    try:
        a = datetime.fromisoformat(str(now).replace("Z", "+00:00"))
        b = datetime.fromisoformat(str(before).replace("Z", "+00:00"))
    except ValueError:
        return False
    return a > b


def _key_times(body: Mapping[str, Any]) -> dict[str, str]:
    props = body.get("properties")
    times = props.get("keyCreationTime") if isinstance(props, dict) else None
    return {str(k): str(v) for k, v in times.items()} if isinstance(times, dict) else {}


def _check_keys(oid: str, now: dict[str, str], was: dict[str, str], sent: bool) -> Check:
    if sent:
        bad = [k for k in ("key1", "key2") if not _later(now.get(k), was[k])]
        return Check(f"keys {oid}", not bad, "both regenerated" if not bad else f"not: {bad}")
    bad = [k for k in ("key1", "key2") if now.get(k) != was[k]]
    return Check(f"keys {oid}", not bad, "unchanged (listKeys not sent)" if not bad else "changed")


def _check_credentials(oid: str, body: Mapping[str, Any], before: Any, name: str) -> Check:
    creds = body.get("passwordCredentials")
    items = [c for c in (creds if isinstance(creds, list) else []) if isinstance(c, dict)]
    ids = sorted(str(c.get("keyId")).lower() for c in items)
    ours = [c for c in items if c.get("displayName") == name]
    ok = ids == [c["keyId"] for c in before["passwordCredentials"]] and not ours
    detail = "as before" if ok else "a strike credential remains, or one is missing"
    return Check(f"credentials {oid}", ok, detail)


def _same(what: str, ok: bool) -> Check:
    return Check(what, ok, "as before" if ok else "differ from the pre-state")


def verify(plan: StrikePlan, reader: LabReader, exposed: set[str]) -> list[Check]:
    """Read every strike object back as the scout and compare it with the pre-state.

    ``exposed`` is the set of write keys that went through or may have: when S1's
    ``listKeys`` did, both keys must be newer than the pre-state (regenerated);
    when it did not, they must be unchanged.
    """
    checks: list[Check] = []
    name = f"{CREDENTIAL_PREFIX}{plan.run_id}"
    s1_sent = any(k.startswith("S1/") for k in exposed)
    for obj, before in sorted(plan.pre_state.items()):
        kind, _, oid = obj.partition(":")
        try:
            if kind == "arm" and "keyCreationTime" in before:
                now = _key_times(reader.storage_account(oid))
                checks.append(_check_keys(oid, now, before["keyCreationTime"], s1_sent))
            elif kind == "arm":
                tags = reader.vault(oid).get("tags") or {}
                checks.append(_same(f"tags {oid}", tags == before["tags"]))
            elif kind == "app":
                checks.append(_check_credentials(oid, reader.application(oid), before, name))
            elif kind == "owners":
                checks.append(_same(f"owners {oid}", reader.app_owners(oid) == before["owners"]))
            elif kind == "assigned":
                same = reader.assigned_to(oid) == before["assignments"]
                checks.append(_same(f"app role assignments {oid}", same))
            else:
                checks.append(Check(obj, False, "unknown pre-state entry"))
        except (ReadError, ScopeDeniedError, TransportError) as exc:
            checks.append(Check(obj, False, f"could not read it back: {_short(str(exc))}"))
    return checks


# --- run, cleanup -------------------------------------------------------------------


def _start(
    plan: StrikePlan,
    binding: ApprovedPlan,
    signed_in_principal: str,
    scope_sha256: str,
    reader: LabReader,
    clock: Clock,
) -> None:
    binding.check_fresh(clock.now())
    if signed_in_principal.lower() != plan.agent_object_id:
        raise StrikeStartError("signed in as another identity than the plan's agent")
    if scope_sha256 != plan.scope_sha256:
        raise StrikeStartError("the scope file changed since the plan was made")
    try:
        now = read_pre_state(plan.strikes, LabTargets.from_dict(plan.targets), reader)
    except (ReadError, ScopeDeniedError, TransportError) as exc:
        raise StrikeStartError(f"could not re-read the pre-state: {exc}") from exc
    if now != plan.pre_state:
        raise StrikeStartError("the lab changed since the plan was made: plan again")


def _record_checks(engine: _Engine, checks: Sequence[Check]) -> None:
    for c in checks:
        engine.event("verify", "verify", what=c.what, ok=c.ok, detail=c.detail)


EXPOSED: Final = frozenset({"succeeded", "unexpected-success", "unknown"})


def run_plan(
    plan: StrikePlan,
    approved_hash: str,
    *,
    gate_factory: Callable[[ApprovedPlan], Gate],
    signed_in_principal: str,
    scope_sha256: str,
    transport: StrikeTransport,
    reader: LabReader,
    journal: StrikeJournal,
    mode: Literal["LIVE", "FIXTURE"],
    clock: Clock | None = None,
    escalation: Escalation | None = None,
) -> StrikeRun:
    """Run every planned write, always undo, then verify. See the module docstring."""
    clock = clock or SystemClock()
    binding = ApprovedPlan(plan, approved_hash)  # PlanRejectedError on a mismatch
    if journal.has_run(plan.run_id):
        raise StrikeStartError("this plan already ran: use fns strike cleanup, or plan again")
    if "S4" in plan.strikes and escalation is None:
        raise StrikeStartError("S4 needs the token transport and the escalated gate")
    _start(plan, binding, signed_in_principal, scope_sha256, reader, clock)
    journal.begin_run(plan.run_id, "strike", mode)
    engine = _Engine(
        plan, binding, gate_factory(binding), transport, reader, journal, escalation=escalation
    )
    outcomes = [WriteOutcome(w.key, w.strike, w.expect, observes=w.observes) for w in plan.writes]
    run = StrikeRun(plan.run_id, plan.plan_hash(), outcomes)
    to_undo: list[tuple[PlannedWrite, WriteOutcome]] = []
    try:
        for w, out in zip(plan.writes, outcomes, strict=True):
            try:
                wrote = engine.write(w, out)
            finally:
                if out.outcome == "unknown" and w.undo:
                    to_undo.append((w, out))
                if w.key == TOKEN_KEY:
                    _remove_s3_now(engine, to_undo)
            if wrote and w.expect == "denied":
                engine.undo(w, out)  # D6: an attempt that should have failed, undone at once
            elif wrote and w.undo:
                to_undo.append((w, out))
    except ScopeDeniedError as exc:
        run.aborted = f"the gate denied a planned write: {exc.decision.reason.value}"
    except (TransportError, UnresolvedError) as exc:
        run.aborted = f"{type(exc).__name__}: {_short(str(exc))}"
    finally:
        for w, out in reversed(to_undo):
            engine.undo(w, out)
        engine.holder.wipe()
    run.checks = verify(plan, reader, {o.key for o in outcomes if o.outcome in EXPOSED})
    _record_checks(engine, run.checks)
    return run


def _remove_s3_now(engine: _Engine, to_undo: list[tuple[PlannedWrite, WriteOutcome]]) -> None:
    """S4 holds its token (or failed to get one): S3's password goes now, before
    anything else is sent, in Entra and in memory."""
    engine.holder.drop(S3_KEY)
    for item in [x for x in to_undo if x[0].key == S3_KEY]:
        to_undo.remove(item)
        engine.undo(*item)


def _rows(
    events: Sequence[JournalEvent], key: str
) -> list[tuple[StrikePhase, Mapping[str, object]]]:
    return [(ph, d) for k, ph, d in events if k == key]


def _exposed(rows: Sequence[tuple[StrikePhase, Mapping[str, object]]]) -> bool:
    if not any(ph == "intent" for ph, _ in rows):
        return False  # never attempted
    results = [d for ph, d in rows if ph == "result"]
    return not results or _is_2xx(results[-1].get("status"))


def exposed_writes(plan: StrikePlan, events: Sequence[JournalEvent]) -> set[str]:
    """Writes that went through or may have: an intent without a refusing answer."""
    return {w.key for w in plan.writes if _exposed(_rows(events, w.key))}


def pending_undos(plan: StrikePlan, events: Sequence[JournalEvent]) -> list[PlannedWrite]:
    """Exposed writes without a complete undo (the resume path)."""
    out: list[PlannedWrite] = []
    for w in plan.writes:
        rows = _rows(events, w.key)
        if not _exposed(rows):
            continue
        done = [d for ph, d in rows if ph == "undo-result"]
        if any(d.get("outcome") == "nothing-to-undo" for d in done):
            continue
        if sum(_is_2xx(d.get("status")) for d in done) >= len(w.undo):
            continue
        out.append(w)
    return out


def cleanup(
    plan: StrikePlan,
    approved_hash: str,
    *,
    gate_factory: Callable[[ApprovedPlan], Gate],
    signed_in_principal: str,
    transport: StrikeTransport,
    reader: LabReader,
    journal: StrikeJournal,
) -> StrikeRun:
    """Run every missing undo from the journal, then verify (the resume path).

    It needs the same approved hash as the run. It skips the plan's own expiry
    check, since it sends only the plan's undo requests; the gate still applies
    the scope's expiry.
    """
    binding = ApprovedPlan(plan, approved_hash)
    if signed_in_principal.lower() != plan.agent_object_id:
        raise StrikeStartError("signed in as another identity than the plan's agent")
    if not journal.has_run(plan.run_id):
        raise StrikeStartError("the journal has no run for this plan")
    events = journal.strike_events(plan.run_id)
    engine = _Engine(plan, binding, gate_factory(binding), transport, reader, journal)
    for key, phase, detail in events:
        learned = detail.get("learned")
        if phase == "result" and isinstance(learned, dict) and learned:
            engine.learned[key] = {str(k): str(v) for k, v in learned.items()}
    run = StrikeRun(plan.run_id, plan.plan_hash(), [])
    try:
        for w in reversed(pending_undos(plan, events)):
            out = WriteOutcome(w.key, w.strike, w.expect, outcome="unknown", observes=w.observes)
            run.writes.append(out)
            engine.undo(w, out)
    finally:
        engine.holder.wipe()
    run.checks = verify(plan, reader, exposed_writes(plan, events))
    _record_checks(engine, run.checks)
    return run
