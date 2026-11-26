"""Rung 3: a non-destructive data-plane read as the test identity (M3 P5).

What each probe sends (``docs/milestones/M3-live-plan.md``, section 1):

- ``secrets/get``: ``GET https://<vault>.vault.azure.net/secrets/<name>?api-version=7.4``,
  but only after a gated ARM read of the secret's *metadata* (no value) shows it is
  tagged ``fns-data = synthetic`` and has the one name the scope lists (V6);
- ``secrets/list``: ``GET https://<vault>.vault.azure.net/secrets?api-version=7.4``;
- ``blob/read``: ``HEAD https://<account>.blob.core.windows.net/<container>/<blob>`` (V2).

Every request goes through the scope gate under ``prove``, as the pinned test
identity, at the exact URL the scope's ``data_objects`` allow.

Outcome rule (V5): ``allowed`` only on 2xx; ``denied`` only on 403 with a
documented authorization code (:data:`AUTH_DENIALS`); everything else, including
401, 404, 429, 5xx, firewall denials and unrecognized codes, is ``unknown``.
A response body is never kept (see ``fns.adapters.azure.dataplane``).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Final, Literal, Protocol

from fns.adapters.azure.dataplane import DataApi, DataRequest, DataResponse
from fns.adapters.azure.http import ApiRequest, ApiResponse, Transport, TransportError
from fns.models.armid import parse_arm_id
from fns.models.assertions import ProbeObservation, ProbeSpec
from fns.models.evidence import Outcome
from fns.models.operations import parse_operation
from fns.models.scope import ScopeManifest, data_resource
from fns.probes.base import Probe, ProbeUnavailableError, observation
from fns.scope.gate import Gate, ScopeDeniedError
from fns.scope.targets import KV_API_VERSION, ArmTarget

METADATA_READ: Final = "arm:Microsoft.KeyVault/vaults/secrets/read"
KV_ARM_API_VERSION: Final = "2023-07-01"
SYNTHETIC_TAG: Final = ("fns-data", "synthetic")
"""The tag a secret must carry before the probe may ``GET`` it (V6)."""

ACTIONS: Final[dict[str, DataApi]] = {
    "secrets/get": "kv",
    "secrets/list": "kv",
    "blob/read": "blob",
}

AUTH_DENIALS: Final[dict[str, frozenset[tuple[str | None, str | None]]]] = {
    # Key Vault: RBAC denial, or access-policy denial.
    "kv": frozenset({("Forbidden", "ForbiddenByRbac"), ("Forbidden", "AccessDenied")}),
    # Storage with a bearer token and no data role.
    "blob": frozenset({("AuthorizationPermissionMismatch", None)}),
}


class DataTransport(Protocol):
    def fetch(self, request: DataRequest) -> DataResponse: ...


def classify(api: str, resp: DataResponse) -> tuple[Outcome, str]:
    """The V5 rule. Only an authorization answer is a denial."""
    codes = "/".join(c for c in (resp.error_code, resp.inner_code) if c)
    label = f"HTTP {resp.status}" + (f" {codes}" if codes else "")
    if 200 <= resp.status < 300:
        return "allowed", label
    if resp.status == 403 and (resp.error_code, resp.inner_code) in AUTH_DENIALS.get(api, ()):
        return "denied", f"{label} (authorization denied)"
    return "unknown", f"{label}: not an authorization answer"


def _object_path(manifest: ScopeManifest, target: str, api: str) -> str:
    """The one data object the scope binds to ``target`` for ``api``."""
    canon = parse_arm_id(target).format()
    paths = sorted(
        op.path
        for d in manifest.data_objects
        if parse_arm_id(d.resource).format() == canon
        and (op := parse_operation(d.operation)).api == api
    )
    if len(paths) != 1:
        raise ProbeUnavailableError(
            f"the scope binds {len(paths)} {api} object(s) to this resource; need exactly one"
        )
    return paths[0]


class DataReadProbe:
    def __init__(
        self,
        *,
        gate: Gate,
        transport: DataTransport,
        arm_transport: Transport,
        manifest: ScopeManifest,
        tenant_id: str,
        principal_id: str,
        now: Callable[[], datetime],
        mode: Literal["LIVE", "FIXTURE"] = "LIVE",
    ) -> None:
        self.gate = gate
        self.transport = transport
        self.arm_transport = arm_transport
        self.manifest = manifest
        self.tenant_id = tenant_id
        self.principal_id = principal_id
        self.now = now
        self.mode: Literal["LIVE", "FIXTURE"] = mode

    def observe(self, spec: ProbeSpec, finding_id: str) -> ProbeObservation:
        if spec.kind != "data-read":
            raise ProbeUnavailableError(f"{spec.kind} is not a data-read probe")
        api = ACTIONS.get(spec.action.lower())
        found = data_resource(spec.target)
        if api is None or found is None or found[0] != api:
            raise ProbeUnavailableError(f"no data-plane read for {spec.action} on this target")
        _, name = found
        target = ArmTarget.parse(spec.target)
        if spec.action.lower() == "secrets/list":
            path = "/secrets"
        else:
            path = _object_path(self.manifest, spec.target, api)
        if spec.action.lower() == "secrets/get":
            self._check_synthetic(str(target), path.rsplit("/", 1)[-1])
        if api == "kv":
            operation = f"kv:GET {path}"
            url = f"https://{name}.vault.azure.net{path}?api-version={KV_API_VERSION}"
        else:
            operation = f"blob:HEAD {path}"
            url = f"https://{name}.blob.core.windows.net{path}"
        request = DataRequest(api=api, operation=operation, target=target, url=url)
        resp = self._call(operation, target, url, lambda: self.transport.fetch(request))
        outcome, detail = classify(api, resp)
        return observation(
            spec,
            finding_id,
            mode=self.mode,
            outcome=outcome,
            detail=detail,
            at=self.now(),
            http_status=resp.status,
            request_id=resp.request_id,
        )

    def _call[T](self, operation: str, target: ArmTarget, url: str, fn: Callable[[], T]) -> T:
        try:
            return self.gate.call(
                "prove",
                operation,
                target,
                self.tenant_id,
                fn,
                url=url,
                principal_id=self.principal_id,
            )
        except ScopeDeniedError as exc:
            raise ProbeUnavailableError(f"scope denied: {exc.decision.reason.value}") from None
        except TransportError:
            raise ProbeUnavailableError("transport error") from None

    def _check_synthetic(self, vault: str, secret: str) -> None:
        """V6: the secret's ARM metadata (never its value) must say it is synthetic."""
        secret_id = f"{vault}/secrets/{secret}"
        url = f"https://management.azure.com{secret_id}?api-version={KV_ARM_API_VERSION}"
        target = ArmTarget.parse(secret_id)
        req = ApiRequest(api="arm", operation=METADATA_READ, target=target, url=url)

        def fetch_metadata() -> ApiResponse:
            return self.arm_transport.fetch(req)

        resp = self._call(METADATA_READ, target, url, fetch_metadata)
        if not resp.ok:
            raise ProbeUnavailableError(
                f"pre-flight HTTP {resp.status}: cannot confirm the secret is synthetic"
            )
        tags = resp.body.get("tags")
        body_name = resp.body.get("name")
        key, value = SYNTHETIC_TAG
        if not isinstance(tags, dict) or tags.get(key) != value:
            raise ProbeUnavailableError(f"the secret is not tagged {key}={value}; not read")
        if not isinstance(body_name, str) or body_name.lower() != secret.lower():
            raise ProbeUnavailableError("the secret's name is not the one the scope lists")


class RoutedProbe:
    """Send each spec to the probe registered for its kind."""

    def __init__(self, by_kind: dict[str, Probe], *, mode: Literal["LIVE", "FIXTURE"]) -> None:
        self._by_kind = by_kind
        self.mode: Literal["LIVE", "FIXTURE"] = mode

    def observe(self, spec: ProbeSpec, finding_id: str) -> ProbeObservation:
        probe = self._by_kind.get(spec.kind)
        if probe is None:
            raise ProbeUnavailableError(f"no probe for {spec.kind}")
        return probe.observe(spec, finding_id)
