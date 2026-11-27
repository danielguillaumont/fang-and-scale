"""Microsoft first-party identifiers that no strike may ever touch (M4, SD2).

These are public, well-known values (the same in every tenant), not tenant data.
The write gate refuses any write whose URL or body contains one of them, and a
scope may not name one as a strike target. The suffix patterns cover the
Microsoft service application IDs that follow them (Graph, Exchange, SharePoint
and others), so an ID missing from the explicit list is still caught.
"""

from __future__ import annotations

import uuid
from typing import Final

FIRST_PARTY_APP_IDS: Final[frozenset[str]] = frozenset(
    {
        "00000003-0000-0000-c000-000000000000",  # Microsoft Graph
        "00000002-0000-0000-c000-000000000000",  # Azure AD Graph (retired)
        "00000002-0000-0ff1-ce00-000000000000",  # Office 365 Exchange Online
        "00000003-0000-0ff1-ce00-000000000000",  # Office 365 SharePoint Online
        "797f4846-ba00-4fd7-ba43-dac1f8f63013",  # Windows Azure Service Management API
        "cfa8b339-82a2-471a-a3c9-0fc0be7a4093",  # Azure Key Vault
        "e406a681-f3d4-42a8-90b6-c2b029497af1",  # Azure Storage
    }
)
FIRST_PARTY_TENANTS: Final[frozenset[str]] = frozenset(
    {
        "f8cdef31-a31e-4b4a-93e4-5f571e91255a",  # Microsoft Services (first-party apps' owner)
        "72f988bf-86f1-41af-91ab-2d7cd011db47",  # Microsoft corporate tenant
    }
)
_FIRST_PARTY_SUFFIXES: Final = ("-0000-0000-c000-000000000000", "-0000-0ff1-ce00-000000000000")


def is_first_party(value: object) -> bool:
    """True for a first-party application ID or a Microsoft tenant ID (any case)."""
    try:
        text = str(uuid.UUID(str(value)))
    except ValueError:
        return False
    return (
        text in FIRST_PARTY_APP_IDS
        or text in FIRST_PARTY_TENANTS
        or text.endswith(_FIRST_PARTY_SUFFIXES)
    )
