"""CLI handlers for ``fns strike plan | run | cleanup`` (M4 strike plan).

Two modes, never mixed:

- ``--fixture DIR``: replay a recorded run (labelled FIXTURE). The scope, the time
  and the run ID come from the recording; nothing leaves the process.
- live: ``--scope`` plus Azure CLI config dirs. ``plan`` needs only the scout
  (``--scout-config``); ``run`` and ``cleanup`` need the agent too
  (``--agent-config``). Every write still needs the scope file, the approved
  plan hash and the gate's live lab check.

Exit codes: 0 ok; 1 an after-harden attempt succeeded; 2 bad input; 4 refused
before anything was sent (hash, identity, scope, changed lab) or a gate denial
during the run; 5 the verification found a difference (see the runbook's
emergency cleanup).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from fns.console import FixtureConsole
from fns.exitcodes import ExitCode
from fns.models.base import sha256_hex
from fns.yamlio import YamlError

Out = Console | FixtureConsole
PLAN_FILE = "plan.json"
RUN_FILE = "strike-run.json"


class _UsageError(ValueError):
    pass


@dataclass
class _Session:
    """What a strike command needs, live or replayed."""

    mode: Literal["LIVE", "FIXTURE"]
    manifest: Any
    scope_sha256: str
    now: datetime
    clock: Any
    run_id: str | None
    tenant_id: str
    scout_oid: str
    agent_oid: str | None
    read_transport: Any
    write_transport: Any | None


def _scope_digest(path: Path) -> str:
    return sha256_hex(path.read_bytes().decode("utf-8"))


def _fixture_session(
    fixture: Path, strikes: tuple[str, ...] | None, phase: Literal["plan", "run", "after"]
) -> _Session:
    from fns.models.scope import load_scope
    from fns.scope.gate import FrozenClock
    from fns.strike.plan import AFTER_HARDEN
    from fns.strike.replay import SCOPE_FILE, ReplayReads, ReplayWrites, load_recording

    if strikes is not None and "S4" in strikes:
        raise _UsageError(
            "S4 runs live only: a recording can't replay its token exchange without the token"
        )
    after = bool(strikes) and all(s in AFTER_HARDEN for s in strikes or ())
    rec = load_recording(fixture, "after-harden" if after else "before-harden")
    if strikes is not None and tuple(strikes) != rec.strikes:
        raise _UsageError(f"this recording has strikes {', '.join(rec.strikes)}")
    scope_path = fixture / SCOPE_FILE
    manifest = load_scope(scope_path, now=rec.now)
    return _Session(
        mode="FIXTURE",
        manifest=manifest,
        scope_sha256=_scope_digest(scope_path),
        now=rec.now,
        clock=FrozenClock(rec.now),
        run_id=rec.run_id,
        tenant_id=str(manifest.tenant_id),
        scout_oid=rec.scout_object_id,
        agent_oid=rec.agent_object_id,
        read_transport=ReplayReads(rec, phase),
        write_transport=ReplayWrites(rec),
    )


def _live_session(scope: Path, scout_config: Path | None, agent_config: Path | None) -> _Session:
    from fns.adapters.azure.live import HttpTransport
    from fns.models.scope import load_scope
    from fns.scope.credentials import ConfigDirSource, PinnedTokens
    from fns.scope.gate import SystemClock
    from fns.strike.live import StrikeIdentityError, cli_identities
    from fns.strike.transport import HttpStrikeTransport

    if scout_config is None:
        raise _UsageError("live mode needs --scout-config (the scout's Azure CLI config dir)")
    now = datetime.now(UTC)
    manifest = load_scope(scope, now=now)
    if manifest.strike is None:
        raise _UsageError("the scope has no strike: block (see lab/README.md, Strikes)")
    tenant = str(manifest.tenant_id)
    if agent_config is None:  # plan: the scout only
        tokens = PinnedTokens(tenant, ConfigDirSource(tenant, scout_config))
        signed_in = tokens.signed_in_tenant()
        scout = tokens.signed_in_identity()
        if any(str(i.object_id) == scout.object_id for i in manifest.test_identities):
            raise StrikeIdentityError("the scout must not be a test identity")
        return _Session(
            "LIVE", manifest, _scope_digest(scope), now, SystemClock(), None, signed_in,
            scout.object_id, None, HttpTransport(tokens), None,
        )  # fmt: skip
    ids = cli_identities(manifest, agent_config, scout_config)
    return _Session(
        "LIVE", manifest, _scope_digest(scope), now, SystemClock(), None, ids.tenant_id,
        ids.scout.object_id, ids.agent.object_id, HttpTransport(ids.scout_tokens),
        HttpStrikeTransport(ids.agent_tokens),
    )  # fmt: skip


def _reader(s: _Session, journal: Any, run_id: str) -> Any:
    from fns.scope.gate import Gate
    from fns.strike.reader import ScoutReader

    gate = Gate(
        s.manifest,
        signed_in_tenant=s.tenant_id,
        journal=journal,
        clock=s.clock,
        run_id=f"{run_id}-scout",
        signed_in_principal=s.scout_oid,
    )
    return ScoutReader(gate, s.read_transport, s.tenant_id)


def _guard(err: Console, fn: Callable[[], int]) -> int:
    """Map every expected failure to an exit code, before or during a command."""
    from fns.adapters.azure.http import TransportError
    from fns.journal.sqlite import JournalError
    from fns.models.scope import ScopeExpiredError
    from fns.scope.credentials import CredentialError, PrincipalMismatchError, TenantMismatchError
    from fns.scope.gate import ScopeDeniedError
    from fns.strike.live import StrikeIdentityError
    from fns.strike.plan import PlanError, PlanRejectedError
    from fns.strike.reader import ReadError
    from fns.strike.run import StrikeStartError

    def fail(msg: str, code: ExitCode) -> int:
        err.print(msg, style="fns.fail", markup=False)
        return int(code)

    try:
        return fn()
    except _UsageError as exc:
        return fail(str(exc), ExitCode.USAGE)
    except (
        PlanRejectedError,
        StrikeStartError,
        StrikeIdentityError,
        TenantMismatchError,
        PrincipalMismatchError,
        ScopeDeniedError,
    ) as exc:
        return fail(f"refused: {exc}. No write was sent.", ExitCode.SCOPE_DENIED)
    except PlanError as exc:
        return fail(f"cannot plan: {exc}", ExitCode.INVALID_INPUT)
    except (ReadError, TransportError) as exc:
        return fail(f"a read failed: {exc}. No write was sent.", ExitCode.INVALID_INPUT)
    except CredentialError as exc:
        return fail(f"{exc}. See docs/runbooks/m4-live-run.md", ExitCode.INVALID_INPUT)
    except FileNotFoundError as exc:
        return fail(f"not found: {exc.filename}", ExitCode.INVALID_INPUT)
    except (ScopeExpiredError, ValidationError, YamlError, ValueError) as exc:
        return fail(f"invalid input: {exc}", ExitCode.INVALID_INPUT)
    except (JournalError, OSError) as exc:
        return fail(f"failed: {type(exc).__name__}: {exc}", ExitCode.INVALID_INPUT)


def _labelled(con: Console, mode: str) -> Out:
    return FixtureConsole(con) if mode == "FIXTURE" else con


def _short(url: str) -> str:
    path = url.split("?", 1)[0]
    for base in ("https://management.azure.com", "https://graph.microsoft.com/v1.0"):
        path = path.removeprefix(base)
    parts = path.split("/")
    return "/".join(p if len(p) < 40 else p[:8] + "..." for p in parts)[-70:]


def _mode_args(fixture: Path | None, scope: Path) -> str:
    return f"--fixture {fixture.as_posix()}" if fixture else f"--scope {scope.as_posix()}"


# --- plan ---------------------------------------------------------------------------


def plan(
    con: Console,
    err: Console,
    *,
    strikes: str,
    fixture: Path | None,
    scope: Path,
    scout_config: Path | None,
    out: Path,
) -> int:
    def go() -> int:
        from fns.journal.sqlite import SqliteJournal
        from fns.strike.plan import new_run_id
        from fns.strike.strikes import build_plan

        wanted = tuple(x.strip() for x in strikes.split(",") if x.strip())
        if not wanted:
            raise _UsageError("--strikes needs at least one strike, like S1,S2,S3 or D-1,...,D-5")
        s = (
            _fixture_session(fixture, wanted, "plan")
            if fixture
            else _live_session(scope, scout_config, None)
        )
        run_id = s.run_id or new_run_id(s.now)
        run_dir = out / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        jpath = run_dir / (
            f"plan-{uuid.uuid4().hex[:8]}.sqlite" if s.mode == "FIXTURE" else "plan.sqlite"
        )
        with SqliteJournal(jpath) as journal:
            p = build_plan(
                wanted,  # type: ignore[arg-type]  # build_plan refuses unknown IDs
                s.manifest,
                s.scope_sha256,
                _reader(s, journal, run_id),
                s.now,
                run_id=run_id,
            )
        path = run_dir / PLAN_FILE
        path.write_text(json.dumps(json.loads(p.canonical_json()), indent=2, sort_keys=True) + "\n")
        _print_plan(_labelled(con, s.mode), p)
        h = p.plan_hash()
        o = _labelled(con, s.mode)
        o.print(f"plan sha256:{h}", style="bold", markup=False)
        o.print(f"written {path.as_posix()}", style="fns.muted", markup=False)
        o.print(
            f"to run it: fns strike run --plan {path.as_posix()} --approve sha256:{h} "
            f"{_mode_args(fixture, scope)}"
            + ("" if fixture else " --agent-config <dir> --scout-config <dir>"),
            markup=False,
        )
        return int(ExitCode.OK)

    return _guard(err, go)


def _print_plan(o: Out, p: Any) -> None:
    o.print(
        f"strike plan {p.run_id}: {', '.join(p.strikes)} "
        f"(as {p.agent_object_id}, expires {p.expires_at.isoformat()})",
        style="fns.brand",
        markup=False,
    )
    t = Table("#", "write", "request", "expect", "undo", show_lines=False)
    for i, w in enumerate(p.writes, 1):
        undo = "; ".join(f"{u.method} {_short(u.url)}" for u in w.undo) or "none"
        t.add_row(str(i), w.key, f"{w.request.method} {_short(w.request.url)}", w.expect, undo)
    o.print(t)


# --- run and cleanup ----------------------------------------------------------------


def _load_plan(path: Path) -> Any:
    from fns.strike.plan import StrikePlan

    return StrikePlan.model_validate_json(path.read_bytes())


def _gate_factory(s: _Session, journal: Any) -> Callable[..., Any]:
    from fns.scope.gate import Gate

    def make(binding: Any, principal: str | None = None) -> Gate:
        return Gate(
            s.manifest,
            signed_in_tenant=s.tenant_id,
            journal=journal,
            clock=s.clock,
            run_id=binding.plan.run_id,
            signed_in_principal=principal or s.agent_oid,
            plan=binding,
        )

    return make


def _escalation(s: _Session, journal: Any) -> Any:
    """S4's live pieces: the token request, then a gate and a transport signed in as
    the proven token's ``oid``, with that token only."""
    from fns.strike.run import Escalation
    from fns.strike.transport import HttpStrikeTransport, HttpTokenTransport

    if s.mode != "LIVE":
        raise _UsageError("S4 runs live only")
    make = _gate_factory(s, journal)
    return Escalation(
        token_transport=HttpTokenTransport(),
        gate_factory=lambda binding, principal: make(binding, principal),
        transport_factory=HttpStrikeTransport,
    )


def run(
    con: Console,
    err: Console,
    *,
    plan_path: Path,
    approve: str,
    fixture: Path | None,
    scope: Path,
    agent_config: Path | None,
    scout_config: Path | None,
    journal_path: Path | None,
    cleanup_only: bool = False,
) -> int:
    def go() -> int:
        from fns.journal.sqlite import SqliteJournal
        from fns.strike.run import cleanup, run_plan

        p = _load_plan(plan_path)
        if fixture:
            s = _fixture_session(fixture, tuple(p.strikes), "after" if cleanup_only else "run")
        else:
            if agent_config is None:
                raise _UsageError("live mode needs --agent-config and --scout-config")
            s = _live_session(scope, scout_config, agent_config)
        if s.agent_oid is None or s.write_transport is None:
            raise _UsageError("this command needs the agent's sign-in (--agent-config)")
        jpath = journal_path or plan_path.parent / (
            f"journal-{uuid.uuid4().hex[:8]}.sqlite" if s.mode == "FIXTURE" else "journal.sqlite"
        )
        with SqliteJournal(jpath) as journal:
            reader = _reader(s, journal, p.run_id)
            common: dict[str, Any] = {
                "gate_factory": _gate_factory(s, journal),
                "signed_in_principal": s.agent_oid,
                "transport": s.write_transport,
                "reader": reader,
                "journal": journal,
            }
            if cleanup_only:
                result = cleanup(p, approve, **common)
            else:
                esc = _escalation(s, journal) if "S4" in p.strikes else None
                result = run_plan(
                    p,
                    approve,
                    scope_sha256=s.scope_sha256,
                    mode=s.mode,
                    clock=s.clock,
                    escalation=esc,
                    **common,
                )
        o = _labelled(con, s.mode)
        _print_run(o, result, cleanup_only)
        out_file = plan_path.parent / ("cleanup.json" if cleanup_only else RUN_FILE)
        data = {"mode": s.mode, **result.to_dict(), "journal": jpath.as_posix()}
        out_file.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        o.print(f"written {out_file.as_posix()}", style="fns.muted", markup=False)
        return int(result.exit_code)

    return _guard(err, go)


_STYLE = {
    "succeeded": "fns.warn",
    "denied": "fns.pass",
    "unexpected-success": "fns.fail",
    "gate-denied": "fns.fail",
    "unknown": "fns.fail",
    "failed": "fns.warn",
    "not-run": "fns.muted",
}


def _print_run(o: Out, r: Any, cleanup_only: bool) -> None:
    what = "cleanup" if cleanup_only else "strike run"
    o.print(f"{what} {r.run_id} (plan sha256:{r.plan_hash})", style="fns.brand", markup=False)
    t = Table("write", "expect", "outcome", "status", "undo")
    for w in r.writes:
        t.add_row(
            w.key,
            w.expect,
            f"[{_STYLE.get(w.outcome, '')}]{w.outcome}[/]",
            "" if w.status is None else str(w.status),
            ", ".join(w.undo) or "-",
        )
    o.print(t)
    if r.aborted:
        o.print(f"stopped early: {r.aborted}", style="fns.fail", markup=False)
    for c in r.checks:
        mark = "ok  " if c.ok else "FAIL"
        o.print(f"verify {mark} {c.what}: {c.detail}", markup=False)
    code = r.exit_code
    note = {
        0: "clean: every write undone and verified",
        1: "an after-harden attempt succeeded: the contract fails (it was undone)",
        4: "the gate denied a planned write (everything before it was undone)",
        5: "verification found a difference: follow the emergency cleanup in the runbook",
    }.get(int(code), "")
    o.print(f"exit {int(code)}: {note}", style="bold", markup=False)
