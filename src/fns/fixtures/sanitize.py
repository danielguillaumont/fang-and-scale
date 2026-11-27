"""Sanitize recorded API traffic before it is written to ``fixtures/``.

Replaced with stable placeholders (same input -> same placeholder within a
fixture set, via the :class:`IdMap`):

- GUIDs (tenant, subscription, object, assignment IDs), anywhere in strings
  and mapping keys, except public well-known IDs (``wellknown.py``);
- emails / UPNs (``userN@example.invalid``) and ``*.onmicrosoft.com`` domains;
- names of *users* (``user-N``); groups, apps and resources keep their names;
- opaque non-GUID ``id`` values (Graph assignment IDs are base64 of GUIDs);
- ``$skiptoken`` values, JWT-looking strings, and secret-bearing keys.

Placeholders are *sequential*, not hashes: a hash of a real tenant ID would
let anyone confirm a guessed tenant. The mapping file (``_idmap.json``) is
gitignored and never committed. ``sanitize`` is idempotent.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Final

from fns.fixtures.wellknown import WELL_KNOWN_GUIDS
from fns.inputcap import MAX_RECORD_BYTES, read_capped

GUID_RE: Final = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
PLACEHOLDER_RE: Final = re.compile(r"^00000000-0000-4000-8000-\d{12}$")
EMAIL_RE: Final = re.compile(r"[A-Za-z0-9._%+\-#]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
DOMAIN_RE: Final = re.compile(r"\b[A-Za-z0-9\-]+\.onmicrosoft\.com\b", re.IGNORECASE)
SKIPTOKEN_RE: Final = re.compile(r"(\$?skip[Tt]oken=)[^&\s\"]+")
JWT_RE: Final = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*")
OPAQUE_RE: Final = re.compile(r"^opaque-\d+$")
SAFE_EMAIL_SUFFIX: Final = "@example.invalid"

PERSON_NAME_KEYS: Final = frozenset(
    {"displayName", "givenName", "surname", "principalDisplayName", "mailNickname"}
)
PERSON_RE: Final = re.compile(r"^user-\d+$")

REDACTED: Final = "REDACTED"
SKIPTOKEN: Final = "SKIPTOKEN"
REDACT_KEYS: Final = frozenset(
    {
        "secretText",
        "password",
        "clientSecret",
        "client_secret",
        "key",
        "customKeyIdentifier",
        "thumbprint",
        "access_token",
        "accessToken",
        "refresh_token",
        "refreshToken",
        "id_token",
    }
)


def placeholder_guid(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


class IdMap:
    """Real value -> placeholder, per category. Persist with :meth:`save`."""

    def __init__(self, data: dict[str, Any] | None = None) -> None:
        data = data or {}
        self.guids: dict[str, str] = dict(data.get("guids", {}))
        self.emails: dict[str, str] = dict(data.get("emails", {}))
        self.domains: dict[str, str] = dict(data.get("domains", {}))
        self.opaque: dict[str, str] = dict(data.get("opaque", {}))
        self.people: dict[str, str] = dict(data.get("people", {}))

    @classmethod
    def load(cls, path: Path) -> IdMap:
        if not path.is_file():
            return cls()
        return cls(json.loads(read_capped(path, MAX_RECORD_BYTES)))

    def save(self, path: Path) -> None:
        data = {
            "guids": self.guids,
            "emails": self.emails,
            "domains": self.domains,
            "opaque": self.opaque,
            "people": self.people,
            "version": 1,
        }
        path.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
        )

    def guid(self, real: str) -> str:
        key = real.lower()
        if key in WELL_KNOWN_GUIDS or PLACEHOLDER_RE.match(key):
            return key
        if key not in self.guids:
            self.guids[key] = placeholder_guid(len(self.guids) + 1)
        return self.guids[key]

    def email(self, real: str) -> str:
        if real.lower().endswith(SAFE_EMAIL_SUFFIX):
            return real
        key = real.lower()
        if key not in self.emails:
            self.emails[key] = f"user{len(self.emails) + 1}{SAFE_EMAIL_SUFFIX}"
        return self.emails[key]

    def domain(self, real: str) -> str:
        key = real.lower()
        if key not in self.domains:
            self.domains[key] = f"tenant{len(self.domains) + 1}.example.invalid"
        return self.domains[key]

    def person(self, real: str) -> str:
        """Display names of users are personal data; groups and apps keep theirs."""
        if PERSON_RE.match(real):
            return real
        if real not in self.people:
            self.people[real] = f"user-{len(self.people) + 1}"
        return self.people[real]

    def opaque_id(self, real: str) -> str:
        if OPAQUE_RE.match(real):
            return real
        if real not in self.opaque:
            self.opaque[real] = f"opaque-{len(self.opaque) + 1}"
        return self.opaque[real]


def sanitize_text(text: str, idmap: IdMap) -> str:
    text = JWT_RE.sub(REDACTED, text)
    text = SKIPTOKEN_RE.sub(lambda m: m.group(1) + SKIPTOKEN, text)
    text = EMAIL_RE.sub(lambda m: idmap.email(m.group(0)), text)
    text = DOMAIN_RE.sub(lambda m: idmap.domain(m.group(0)), text)
    return GUID_RE.sub(lambda m: idmap.guid(m.group(0)), text)


def _is_person(value: dict[str, Any]) -> bool:
    return (
        value.get("@odata.type") == "#microsoft.graph.user" or value.get("principalType") == "User"
    )


def sanitize(value: Any, idmap: IdMap, *, key: str | None = None) -> Any:
    """Return a sanitized deep copy of a JSON value."""
    if isinstance(value, dict):
        person = _is_person(value)
        out: dict[str, Any] = {}
        for k, v in value.items():
            new_key = sanitize_text(str(k), idmap)
            if person and k in PERSON_NAME_KEYS and isinstance(v, str):
                out[new_key] = idmap.person(v)
            else:
                out[new_key] = sanitize(v, idmap, key=str(k))
        return out
    if isinstance(value, list):
        return [sanitize(v, idmap, key=key) for v in value]
    if isinstance(value, str):
        if key in REDACT_KEYS:
            return REDACTED
        if key == "id" and not value.startswith("/") and not GUID_RE.fullmatch(value):
            return idmap.opaque_id(value)
        return sanitize_text(value, idmap)
    if key in REDACT_KEYS and value is not None:
        return REDACTED
    return value
