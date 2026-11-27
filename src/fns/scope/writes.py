"""Write forms for ``fns strike``: what a write may look like, and what it never may be.

The rules are in ``docs/milestones/M4-strikes-plan.md``, "Lab objects only". This
module is pure: it reads no clock, holds no state and makes no call. The
:class:`~fns.scope.gate.Gate` applies it in ``check_write``, in this order:

1. :func:`hard_deny`: a fixed denylist that no scope can lift. It runs before the
   manifest is even looked at. It covers:
   - directory role and permission-grant endpoints (``/roleManagement/``,
     ``/directoryRoles/``, ``/directory/``, ``oauth2PermissionGrants``,
     ``appRoleAssignments``, ``$batch``);
   - ARM authorization, Key Vault access policies, and the logging and detection
     providers;
   - any Microsoft first-party ID anywhere in the URL or the body.
   It decodes percent-encoding repeatedly and ignores case, so an encoded or
   re-cased form of a denied path is still denied.
2. :func:`match_form`: the request is exactly one listed form (method, host,
   exact path, pinned query). It never normalizes a request into a match:
   ``%``, ``;``, ``//``, ``..``, a trailing slash, a fragment or a port is
   refused.
3. :func:`check_body`: only the keys and values the form allows, with every
   object ID in the body bound to a lab target or a test identity.

S4 (approved 2026-11-27) adds one request that is not a Graph or ARM write: the
client-credentials token request for the escalation target
(:data:`TOKEN_OPERATION`, :func:`token_url`, :func:`check_token_body`). Its body
here never holds the secret; the token transport adds it from memory.

Case: ARM paths compare case-insensitively (ARM is). Graph literal segments
compare exactly: ``/Applications/`` is refused, not folded.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Literal
from urllib.parse import unquote, urlsplit

from fns.models.armid import GUID_RE, parse_arm_id
from fns.models.firstparty import is_first_party
from fns.models.operations import WRITE_FORM_OPERATIONS, parse_operation

ARM_HOST: Final = "management.azure.com"
GRAPH_HOST: Final = "graph.microsoft.com"
GRAPH_WRITE_VERSION: Final = "v1.0"
ARM_API_VERSIONS: Final[dict[str, str]] = {
    "blob": "2023-05-01",  # Microsoft.Storage
    "kv": "2023-07-01",  # Microsoft.KeyVault
}
"""The one api-version per provider a strike write may use (pinned, like Key Vault's)."""

LAB_TAGS: Final[frozenset[str]] = frozenset({"project=fang-and-scale", "purpose=lab"})
"""``local.ad_tags`` in ``lab/main.tf``: every lab Entra object carries both."""
CREDENTIAL_PREFIX: Final = "fns-strike-"
MAX_CREDENTIAL_LIFETIME: Final = timedelta(hours=1)
MARKER_VALUE: Final = "fns.strike.marker"
MARKER_DESCRIPTION: Final = "Grants nothing"
MARKER_NAME_PREFIX: Final = "Fang & Scale strike marker"
TOKEN_HOST: Final = "login.microsoftonline.com"  # noqa: S105 - a host name
TOKEN_OPERATION: Final = "token:client_credentials"  # noqa: S105 - a form name
"""S4 step 1. Not an ``allowed_operations`` entry: the ``strike.escalation`` block
authorises it, and only for the escalation target."""
TOKEN_SCOPE: Final = "https://graph.microsoft.com/.default"  # noqa: S105 - a scope
CAPABILITY_ROLE: Final = "AppRoleAssignment.ReadWrite.All"
"""The ``roles`` claim S4's token must carry: the capability S4 proves."""
MAX_BODY_BYTES: Final = 65_536
MAX_TAGS: Final = 50

# --- 1. the hard denylist -----------------------------------------------------------

DENIED_TOKENS: Final[frozenset[str]] = frozenset(
    {
        # Directory roles: no strike ever assigns or touches one (D4).
        "rolemanagement",
        "rolemanagementpolicies",
        "rolemanagementpolicyassignments",
        "directoryroles",
        "directoryroletemplates",
        "directory",
        "privilegedaccess",
        # Permission grants: delegated and application.
        "oauth2permissiongrants",
        "approleassignments",
        # A batch request can carry any other request.
        "$batch",
        # Credentials with no expiry limit the gate could check.
        "federatedidentitycredentials",
        # ARM: Key Vault access policies, and elevating access.
        "accesspolicies",
        "elevateaccess",
    }
)
"""Path or body tokens (between non-alphanumeric characters) that deny a write."""

DENIED_PROVIDERS: Final[tuple[str, ...]] = (
    "microsoft.authorization",  # role assignments and definitions, locks, policy
    "microsoft.aadiam",  # Entra diagnostic settings: switching off the logs
    "microsoft.insights",  # Azure Monitor diagnostic settings and alert rules
    "microsoft.operationalinsights",  # the Log Analytics workspace
    "microsoft.securityinsights",  # Sentinel rules
)
"""ARM providers a strike never writes to: access control, and the detection path."""

_TOKEN_SPLIT = re.compile(r"[^a-z0-9$]+")
_GUID_FIND = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


class WriteRefusedError(ValueError):
    """A write the rules refuse. ``kind`` maps to a gate deny reason."""

    def __init__(
        self,
        kind: Literal["hard-deny", "url", "target", "lab-check", "body"],
        detail: str,
    ) -> None:
        super().__init__(detail)
        self.kind = kind
        self.detail = detail


def _decoded(text: str) -> str:
    """Percent-decode until stable (at most 16 rounds), then lowercase."""
    for _ in range(16):
        nxt = unquote(text.replace("+", " "))
        if nxt == text:
            break
        text = nxt
    return text.lower()


def _strings(value: object, depth: int = 0) -> list[str]:
    if depth > 32:
        raise WriteRefusedError("body", "body nests too deeply")
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        out: list[str] = []
        for k, v in value.items():
            out.append(str(k))
            out.extend(_strings(v, depth + 1))
        return out
    if isinstance(value, (list, tuple)):
        return [s for item in value for s in _strings(item, depth + 1)]
    return []


def hard_deny(url: object, body: object) -> str | None:
    """Why the denylist refuses this write, or None. No scope is consulted."""
    texts = ([url] if isinstance(url, str) else []) + _strings(body)
    for raw in texts:
        text = _decoded(raw)
        hit = sorted(set(_TOKEN_SPLIT.split(text)) & DENIED_TOKENS)
        if hit:
            return f"{hit[0]!r} is on the hard denylist"
        for provider in DENIED_PROVIDERS:
            if provider in text:
                return f"{provider} is on the hard denylist"
        for guid in _GUID_FIND.findall(text):
            if is_first_party(guid):
                return f"{guid} is a Microsoft first-party ID"
    return None


# --- 2. forms -------------------------------------------------------------------------

Slot = Literal["app", "sp", "principal", "assignment"]
BodyRule = Literal[
    "none",
    "list-keys",
    "regenerate-key",
    "vault-tags",
    "add-password",
    "remove-password",
    "app-roles",
    "assign-marker",
    "add-owner",
]


@dataclass(frozen=True, slots=True)
class WriteForm:
    operation: str
    """As listed in a scope (``WRITE_FORM_OPERATIONS``)."""
    method: str
    body: BodyRule
    arm_resource: Literal["kv", "blob"] | None = None
    """ARM: the target's resource type (a ``data_resource`` kind)."""
    arm_suffix: str | None = None
    """ARM: the action after the resource ID (``listKeys``), or None for the resource."""
    graph_path: tuple[str, ...] = ()
    """Graph: the path after ``/v1.0``; ``{app}`` and the like are slots."""

    @property
    def key(self) -> str:
        return parse_operation(self.operation).key

    @property
    def api(self) -> Literal["arm", "graph"]:
        return "arm" if self.arm_resource is not None else "graph"


FORMS: Final[tuple[WriteForm, ...]] = (
    WriteForm(WRITE_FORM_OPERATIONS[0], "POST", "list-keys", "blob", "listKeys"),
    WriteForm(WRITE_FORM_OPERATIONS[1], "POST", "regenerate-key", "blob", "regenerateKey"),
    WriteForm(WRITE_FORM_OPERATIONS[2], "PATCH", "vault-tags", "kv"),
    WriteForm(
        WRITE_FORM_OPERATIONS[3],
        "POST",
        "add-password",
        graph_path=("applications", "{app}", "addPassword"),
    ),
    WriteForm(
        WRITE_FORM_OPERATIONS[4],
        "POST",
        "remove-password",
        graph_path=("applications", "{app}", "removePassword"),
    ),
    WriteForm(WRITE_FORM_OPERATIONS[5], "PATCH", "app-roles", graph_path=("applications", "{app}")),
    WriteForm(
        WRITE_FORM_OPERATIONS[6],
        "POST",
        "assign-marker",
        graph_path=("servicePrincipals", "{sp}", "appRoleAssignedTo"),
    ),
    WriteForm(
        WRITE_FORM_OPERATIONS[7],
        "DELETE",
        "none",
        graph_path=("servicePrincipals", "{sp}", "appRoleAssignedTo", "{assignment}"),
    ),
    WriteForm(
        WRITE_FORM_OPERATIONS[8],
        "POST",
        "add-owner",
        graph_path=("applications", "{app}", "owners", "$ref"),
    ),
    WriteForm(
        WRITE_FORM_OPERATIONS[9],
        "DELETE",
        "none",
        graph_path=("applications", "{app}", "owners", "{principal}", "$ref"),
    ),
)
FORMS_BY_KEY: Final[dict[str, WriteForm]] = {f.key: f for f in FORMS}

_PATH_RE = re.compile(r"^(?:/[A-Za-z0-9._\-$]+)+$")
_ASSIGNMENT_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


@dataclass(frozen=True, slots=True)
class Matched:
    """A request that fits its form: the target and the IDs from the path."""

    target: str
    """The ARM ID (lowercased) or ``directory/<object id>``."""
    arm_target: str | None = None
    app: uuid.UUID | None = None
    sp: uuid.UUID | None = None
    principal: uuid.UUID | None = None
    assignment: str | None = None


def _split_strict(url: object, host: str) -> tuple[list[str], str, bool]:
    if not isinstance(url, str) or not url.isascii():
        raise WriteRefusedError("url", "URL must be an ASCII string")
    if any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in url) or "\\" in url:
        raise WriteRefusedError("url", "URL has whitespace, control characters or a backslash")
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise WriteRefusedError("url", "URL must use https")
    if parts.netloc != host:
        raise WriteRefusedError("url", f"host must be exactly {host!r}")
    if parts.fragment or "#" in url:
        raise WriteRefusedError("url", "URL must not have a fragment")
    if not _PATH_RE.fullmatch(parts.path):
        raise WriteRefusedError(
            "url", "path has a character outside [A-Za-z0-9._-$], an empty segment or a trailing /"
        )
    segs = parts.path[1:].split("/")
    if any(s in {".", ".."} for s in segs):
        raise WriteRefusedError("url", "path has a dot segment")
    if any("$" in s and s != "$ref" for s in segs):
        raise WriteRefusedError("url", "'$' appears only in a final '$ref'")
    return segs, parts.query, "?" in url


def _guid(seg: str, what: str) -> uuid.UUID:
    if not GUID_RE.fullmatch(seg):
        raise WriteRefusedError("url", f"{what} must be an object ID")
    return uuid.UUID(seg)


def match_form(
    form: WriteForm,
    method: object,
    url: object,
    arm_targets: Mapping[str, str],
) -> Matched:
    """Check method, host, path and query against ``form``.

    ``arm_targets`` maps each ARM strike target (lowercased ID) to its
    ``data_resource`` kind. Graph slots are returned for the caller to bind.
    """
    if method != form.method:
        raise WriteRefusedError("url", f"{form.operation} is sent as {form.method}, not {method!r}")
    if form.api == "arm":
        segs, query, has_q = _split_strict(url, ARM_HOST)
        version = ARM_API_VERSIONS[str(form.arm_resource)]
        if query != f"api-version={version}" or not has_q:
            raise WriteRefusedError("url", f"ARM query must be exactly api-version={version}")
        path = "/" + "/".join(segs).lower()
        suffix = f"/{form.arm_suffix.lower()}" if form.arm_suffix else ""
        if suffix and not path.endswith(suffix):
            raise WriteRefusedError("url", f"path does not end in {form.arm_suffix}")
        resource = path[: len(path) - len(suffix)]
        try:
            resource = parse_arm_id(resource).format()
        except ValueError as exc:
            raise WriteRefusedError("url", f"not an ARM resource path: {exc}") from exc
        if resource + suffix != path:
            raise WriteRefusedError("url", "ARM path is not canonical")
        kind = arm_targets.get(resource)
        if kind is None:
            raise WriteRefusedError("target", "ARM resource is not a strike target")
        if kind != form.arm_resource:
            raise WriteRefusedError("target", f"{form.operation} on the wrong kind of resource")
        return Matched(target=resource, arm_target=resource)

    segs, _query, has_q = _split_strict(url, GRAPH_HOST)
    if has_q:
        raise WriteRefusedError("url", "a Graph write has no query string")
    if not segs or segs[0] != GRAPH_WRITE_VERSION:
        raise WriteRefusedError("url", f"a Graph write uses /{GRAPH_WRITE_VERSION}/ only")
    rest = segs[1:]
    if len(rest) != len(form.graph_path):
        raise WriteRefusedError("url", f"path is not {form.operation}")
    slots: dict[str, uuid.UUID | str] = {}
    for seg, want in zip(rest, form.graph_path, strict=True):
        if want in {"{app}", "{sp}", "{principal}"}:
            slots[want[1:-1]] = _guid(seg, want)
        elif want == "{assignment}":
            if not _ASSIGNMENT_RE.fullmatch(seg):
                raise WriteRefusedError("url", "assignment ID is malformed")
            slots["assignment"] = seg
        elif seg != want:
            raise WriteRefusedError("url", f"segment {seg!r} is not {want!r} (exact case)")
    obj = slots.get("app") or slots.get("sp")
    app = slots.get("app")
    sp = slots.get("sp")
    principal = slots.get("principal")
    assignment = slots.get("assignment")
    return Matched(
        target=f"directory/{obj}",
        app=app if isinstance(app, uuid.UUID) else None,
        sp=sp if isinstance(sp, uuid.UUID) else None,
        principal=principal if isinstance(principal, uuid.UUID) else None,
        assignment=assignment if isinstance(assignment, str) else None,
    )


# --- 3. bodies ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LabObject:
    """A Graph target that passed the live check."""

    object_id: uuid.UUID
    kind: Literal["graph-application", "graph-service-principal"]
    app_id: uuid.UUID
    app_roles: tuple[Mapping[str, object], ...] = ()
    """Applications: ``appRoles`` as the live check read them (the pre-state)."""


@dataclass(frozen=True, slots=True)
class BodyContext:
    now: datetime
    test_identities: frozenset[uuid.UUID]
    lab: Mapping[uuid.UUID, LabObject]
    sp_application: Mapping[uuid.UUID, uuid.UUID]
    marker_role: uuid.UUID | None = None
    """``strike.escalation.marker_role_id``: the one role S4 may assign."""


def canonical_body(body: object) -> str:
    """Canonical JSON of a request body (sorted keys, no whitespace); '' for none."""
    if body is None:
        return ""
    _json_only(body)
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if len(text.encode()) > MAX_BODY_BYTES:
        raise WriteRefusedError("body", f"body is over {MAX_BODY_BYTES} bytes")
    return text


def _json_only(value: object, depth: int = 0) -> None:
    if depth > 32:
        raise WriteRefusedError("body", "body nests too deeply")
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, Mapping):
        for k, v in value.items():
            if not isinstance(k, str):
                raise WriteRefusedError("body", "body keys are strings")
            _json_only(v, depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _json_only(item, depth + 1)
        return
    raise WriteRefusedError("body", f"body holds a {type(value).__name__}, not JSON")


def _exact_keys(body: object, keys: set[str], what: str) -> Mapping[str, object]:
    if not isinstance(body, Mapping) or set(body) != keys:
        raise WriteRefusedError("body", f"{what} is exactly {sorted(keys)}")
    return body


def _body_guid(value: object, what: str) -> uuid.UUID:
    if not isinstance(value, str) or not GUID_RE.fullmatch(value):
        raise WriteRefusedError("body", f"{what} must be an object ID")
    return uuid.UUID(value)


_TIME_RE = re.compile(
    r"(?P<head>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d{1,7}))?"
    r"(?P<zone>Z|[+-]\d{2}:\d{2})"
)


def _parse_time(value: object) -> datetime:
    """ISO 8601 with a zone; Graph sends up to 7 fraction digits, Python takes 6."""
    m = _TIME_RE.fullmatch(value) if isinstance(value, str) else None
    if m is None:
        raise WriteRefusedError("body", "endDateTime must be an ISO 8601 time with a zone")
    frac = (m["frac"] or "")[:6].ljust(6, "0")
    zone = "+00:00" if m["zone"] == "Z" else m["zone"]
    try:
        return datetime.fromisoformat(f"{m['head']}.{frac}{zone}")
    except ValueError as exc:
        raise WriteRefusedError("body", "endDateTime is not a real time") from exc


def _role_key(role: Mapping[str, object]) -> str:
    return json.dumps(role, sort_keys=True, separators=(",", ":"))


def _check_marker(role: Mapping[str, object], taken: set[str]) -> uuid.UUID:
    keys = {"id", "value", "allowedMemberTypes", "isEnabled", "displayName", "description"}
    if set(role) != keys:
        raise WriteRefusedError("body", f"a marker role is exactly {sorted(keys)}")
    rid = _body_guid(role["id"], "marker role id")
    if str(rid) in taken:
        raise WriteRefusedError("body", "the marker role reuses an existing role id")
    name = role["displayName"]
    if (
        role["allowedMemberTypes"] != ["Application"]
        or role["description"] != MARKER_DESCRIPTION
        or not isinstance(role["isEnabled"], bool)
        or not isinstance(name, str)
        or not name.startswith(MARKER_NAME_PREFIX)
        or len(name) > 120
    ):
        raise WriteRefusedError(
            "body", "the marker role must be the plan's marker, granting nothing"
        )
    return rid


def check_defined_marker(app_roles: Sequence[Mapping[str, object]], role_id: uuid.UUID) -> None:
    """Raise unless ``role_id`` is an enabled marker role among ``app_roles`` (the
    application's roles as the live check read them), granting nothing.

    The marker is defined by Terraform (``lab/identities.tf``), never by a strike.
    """
    found = [r for r in app_roles if _maybe_guid(r.get("id")) == role_id]
    if len(found) != 1:
        raise WriteRefusedError(
            "body", "the marker role is not defined on the service principal's lab application"
        )
    role = found[0]
    name = role.get("displayName")
    if (
        role_id not in marker_roles({"appRoles": list(app_roles)})
        or role.get("allowedMemberTypes") != ["Application"]
        or role.get("description") != MARKER_DESCRIPTION
        or not isinstance(name, str)
        or not name.startswith(MARKER_NAME_PREFIX)
    ):
        raise WriteRefusedError(
            "body", "the marker role must be enabled, for applications only, and grant nothing"
        )


def token_url(tenant_id: uuid.UUID) -> str:
    return f"https://{TOKEN_HOST}/{tenant_id}/oauth2/v2.0/token"


def token_body(client_id: str) -> dict[str, str]:
    """The token request's form fields, without the secret (added in transport)."""
    return {"client_id": client_id, "grant_type": "client_credentials", "scope": TOKEN_SCOPE}


def check_token_body(body: object, client_id: uuid.UUID) -> None:
    """Exactly :func:`token_body` for the escalation target's appId: no secret, no
    other scope, no other grant."""
    b = _exact_keys(body, {"client_id", "grant_type", "scope"}, "the token request")
    if b["grant_type"] != "client_credentials":
        raise WriteRefusedError("body", "the token request uses client_credentials only")
    if b["scope"] != TOKEN_SCOPE:
        raise WriteRefusedError("body", f"the token scope is exactly {TOKEN_SCOPE}")
    if _maybe_guid(b["client_id"]) != client_id or b["client_id"] != str(client_id):
        raise WriteRefusedError("body", "client_id must be the escalation target's appId")


def marker_roles(body: object) -> frozenset[uuid.UUID]:
    """Enabled marker role IDs in an ``appRoles`` body (after it passed check_body)."""
    if not isinstance(body, Mapping) or not isinstance(roles := body.get("appRoles"), list):
        return frozenset()
    return frozenset(
        uuid.UUID(str(r["id"]))
        for r in roles
        if isinstance(r, Mapping) and r.get("value") == MARKER_VALUE and r.get("isEnabled") is True
    )


def check_body(form: WriteForm, body: object, m: Matched, ctx: BodyContext) -> None:
    """Raise :class:`WriteRefusedError` unless ``body`` is exactly what ``form`` allows."""
    rule = form.body
    if rule == "none":
        if body is not None:
            raise WriteRefusedError("body", f"{form.operation} has no body")
        return
    if rule == "list-keys":
        if body is not None and body != {}:
            raise WriteRefusedError("body", "listKeys has no body")
        return
    if rule == "regenerate-key":
        b = _exact_keys(body, {"keyName"}, "the regenerateKey body")
        if b["keyName"] not in ("key1", "key2"):
            raise WriteRefusedError("body", "keyName is key1 or key2")
        return
    if rule == "vault-tags":
        b = _exact_keys(body, {"tags"}, "a vault write (tags only: never properties)")
        tags = b["tags"]
        if not isinstance(tags, Mapping) or len(tags) > MAX_TAGS:
            raise WriteRefusedError("body", f"tags is a map of at most {MAX_TAGS} entries")
        for k, v in tags.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise WriteRefusedError("body", "tag names and values are strings")
            if not 1 <= len(k) <= 512 or len(v) > 256:
                raise WriteRefusedError("body", "tag name or value too long")
        return
    if rule == "add-password":
        b = _exact_keys(body, {"passwordCredential"}, "the addPassword body")
        cred = _exact_keys(
            b["passwordCredential"], {"displayName", "endDateTime"}, "passwordCredential"
        )
        name = cred["displayName"]
        if not isinstance(name, str) or not re.fullmatch(
            re.escape(CREDENTIAL_PREFIX) + r"[A-Za-z0-9-]{1,64}", name
        ):
            raise WriteRefusedError(
                "body", f"the credential's displayName starts {CREDENTIAL_PREFIX}"
            )
        end = _parse_time(cred["endDateTime"])
        if not ctx.now < end <= ctx.now + MAX_CREDENTIAL_LIFETIME:
            raise WriteRefusedError("body", "the credential must expire within 1 hour from now")
        return
    if rule == "remove-password":
        b = _exact_keys(body, {"keyId"}, "the removePassword body")
        _body_guid(b["keyId"], "keyId")
        return
    if rule == "app-roles":
        b = _exact_keys(body, {"appRoles"}, "an application write (appRoles only)")
        roles = b["appRoles"]
        if not isinstance(roles, list) or not all(isinstance(r, Mapping) for r in roles):
            raise WriteRefusedError("body", "appRoles is a list of roles")
        lab = ctx.lab.get(m.app) if m.app is not None else None
        if lab is None or lab.kind != "graph-application":
            raise WriteRefusedError("lab-check", "the application has not passed the live check")
        before = [r for r in lab.app_roles if r.get("value") != MARKER_VALUE]
        kept = [r for r in roles if r.get("value") != MARKER_VALUE]
        if sorted(map(_role_key, kept)) != sorted(map(_role_key, before)):
            raise WriteRefusedError("body", "every existing role must stay exactly as it was")
        markers = [r for r in roles if r.get("value") == MARKER_VALUE]
        if len(markers) > 1:
            raise WriteRefusedError("body", "at most one marker role")
        taken = {str(r.get("id")) for r in before}
        for r in markers:
            _check_marker(r, taken)
        return
    if rule == "assign-marker":
        b = _exact_keys(body, {"principalId", "resourceId", "appRoleId"}, "the assignment body")
        principal = _body_guid(b["principalId"], "principalId")
        resource = _body_guid(b["resourceId"], "resourceId")
        role = _body_guid(b["appRoleId"], "appRoleId")
        if resource != m.sp:
            raise WriteRefusedError("body", "resourceId must be the service principal in the path")
        if principal not in ctx.test_identities:
            raise WriteRefusedError("body", "principalId must be a test identity")
        if ctx.marker_role is None or role != ctx.marker_role:
            raise WriteRefusedError("body", "appRoleId must be the scope's marker role")
        app = ctx.sp_application.get(resource)
        lab_app = ctx.lab.get(app) if app is not None else None
        if lab_app is None or lab_app.kind != "graph-application":
            raise WriteRefusedError("lab-check", "the application has not passed the live check")
        check_defined_marker(lab_app.app_roles, role)
        return
    if rule == "add-owner":
        b = _exact_keys(body, {"@odata.id"}, "the owner reference")
        ref = b["@odata.id"]
        prefix = f"https://{GRAPH_HOST}/{GRAPH_WRITE_VERSION}/directoryObjects/"
        if not isinstance(ref, str) or not ref.startswith(prefix):
            raise WriteRefusedError("body", f"@odata.id is {prefix}<object id>")
        if _body_guid(ref[len(prefix) :], "@odata.id object") not in ctx.test_identities:
            raise WriteRefusedError("body", "the new owner must be a test identity")
        return
    raise WriteRefusedError("body", f"no body rule {rule!r}")  # pragma: no cover


# --- live lab check -------------------------------------------------------------------


def check_lab_object(
    kind: Literal["graph-application", "graph-service-principal"],
    object_id: uuid.UUID,
    display_name: str,
    observed: object,
    *,
    tenant_id: uuid.UUID,
    application: LabObject | None,
) -> LabObject:
    """Check a live GET of a Graph target, and return what the gate keeps from it.

    The object must be the one the scope names, carry both lab tags and the display
    name Terraform gave it. A service principal must belong to this tenant (not
    Microsoft's) and to its lab application, which must have passed first. This
    stops a stale scope from pointing at a recreated or foreign object.
    """
    if not isinstance(observed, Mapping):
        raise WriteRefusedError("lab-check", "the live check needs the object's JSON")
    if _maybe_guid(observed.get("id")) != object_id:
        raise WriteRefusedError("lab-check", "the object read is not the target")
    if observed.get("displayName") != display_name:
        raise WriteRefusedError("lab-check", "display name differs from the one Terraform set")
    tags = observed.get("tags")
    if not isinstance(tags, Sequence) or isinstance(tags, str) or not set(tags) >= LAB_TAGS:
        raise WriteRefusedError("lab-check", f"the object lacks the lab tags {sorted(LAB_TAGS)}")
    app_id = _maybe_guid(observed.get("appId"))
    if app_id is None or is_first_party(app_id):
        raise WriteRefusedError("lab-check", "appId is missing or Microsoft first-party")
    if kind == "graph-application":
        roles = observed.get("appRoles")
        if not isinstance(roles, list) or not all(isinstance(r, Mapping) for r in roles):
            raise WriteRefusedError("lab-check", "the application read has no appRoles list")
        return LabObject(object_id, kind, app_id, tuple(roles))
    if _maybe_guid(observed.get("appOwnerOrganizationId")) != tenant_id:
        raise WriteRefusedError("lab-check", "the service principal's app is not from this tenant")
    if application is None:
        raise WriteRefusedError("lab-check", "check the service principal's application first")
    if app_id != application.app_id:
        raise WriteRefusedError("lab-check", "the service principal is not its lab application's")
    return LabObject(object_id, kind, app_id)


def _maybe_guid(value: object) -> uuid.UUID | None:
    if isinstance(value, str) and GUID_RE.fullmatch(value):
        return uuid.UUID(value)
    return None
