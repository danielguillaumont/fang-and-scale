"""Shared annotated types: GUIDs, ARM IDs, timezone-aware datetimes."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator, AwareDatetime, BeforeValidator, PlainSerializer, WithJsonSchema

from fns.models.armid import GUID_RE, ArmIdError, normalize_arm_id

GUID_PATTERN = GUID_RE.pattern


def _parse_guid(value: object) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    if not isinstance(value, str) or not GUID_RE.fullmatch(value):
        raise ValueError("must be a GUID like 00000000-0000-0000-0000-000000000000")
    return uuid.UUID(value)


Guid = Annotated[
    uuid.UUID,
    BeforeValidator(_parse_guid),
    PlainSerializer(str, return_type=str),
    WithJsonSchema({"type": "string", "pattern": GUID_PATTERN}),
]
"""A GUID. Accepts upper or lower case, rejects braces/URN forms; serialized lowercase."""


def _arm_id(value: object) -> str:
    try:
        return normalize_arm_id(value)
    except ArmIdError as exc:
        raise ValueError(str(exc)) from exc


ArmId = Annotated[
    str,
    BeforeValidator(_arm_id),
    WithJsonSchema({"type": "string", "pattern": "^/(subscriptions|providers)/", "minLength": 2}),
]
"""An ARM resource ID, validated and normalized to lowercase (ARM is case-insensitive)."""


def _to_utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


TzDatetime = Annotated[AwareDatetime, AfterValidator(_to_utc)]
"""A timezone-aware datetime, normalized to UTC. Naive datetimes are rejected."""


def utc_isoformat(value: datetime) -> str:
    """Canonical text form: ``YYYY-MM-DDTHH:MM:SS[.ffffff]Z``."""
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
