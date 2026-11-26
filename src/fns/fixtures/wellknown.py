"""Public, well-known Microsoft identifiers that fixtures keep verbatim.

These are the same in every tenant (built-in role definitions, first-party
app IDs, Graph app role IDs, directory role templates), so replacing them
would destroy the meaning of a fixture without hiding anything. The values
that appear in ``fixtures/lab-run-1`` were confirmed against the lab tenant on
2026-11-26 (``tests/fixtures/test_lab_fixture.py`` keeps them checked); record
any mismatch in docs/FINDINGS.md.
"""

from __future__ import annotations

from typing import Final

# Azure RBAC built-in role definitions.
OWNER: Final = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR: Final = "b24988ac-6180-42a0-ab88-20f7382dd24c"
READER: Final = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
USER_ACCESS_ADMINISTRATOR: Final = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
KEY_VAULT_SECRETS_USER: Final = "4633458b-17de-408a-b874-0445c86b69e6"
KEY_VAULT_ADMINISTRATOR: Final = "00482a5a-887f-4fb3-b363-3b7fe8e74483"
KEY_VAULT_SECRETS_OFFICER: Final = "b86a8fe4-44ce-4948-aee5-eccb2c155cd7"
STORAGE_BLOB_DATA_READER: Final = "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
STORAGE_BLOB_DATA_CONTRIBUTOR: Final = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"
STORAGE_ACCOUNT_CONTRIBUTOR: Final = "17d1049b-9a84-46fb-8f53-869881c3d3ab"
VIRTUAL_MACHINE_CONTRIBUTOR: Final = "9980e02c-c2be-4d73-94e8-173b1dc7cf3c"

# First-party applications and tenants.
MICROSOFT_GRAPH_APP_ID: Final = "00000003-0000-0000-c000-000000000000"
MICROSOFT_SERVICES_TENANT: Final = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
EVERYONE: Final = "00000000-0000-0000-0000-000000000000"

# Microsoft Graph application permissions (app role IDs).
APPLICATION_READ_ALL: Final = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"
APPLICATION_READWRITE_ALL: Final = "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9"
APPLICATION_READWRITE_OWNEDBY: Final = "18a4783c-866b-4cc7-a460-3d5e5662c884"
APPROLEASSIGNMENT_READWRITE_ALL: Final = "06b708a9-e830-4db3-a914-8e69da51d44f"
DIRECTORY_READ_ALL: Final = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
ROLEMANAGEMENT_READ_DIRECTORY: Final = "483bed4a-2ad3-4361-a73b-c83ccdbdc53c"
ROLEMANAGEMENT_READWRITE_DIRECTORY: Final = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
GROUPMEMBER_READ_ALL: Final = "98830695-27a2-44f7-8c18-0c3ebc9698f6"

# Entra built-in directory role templates.
GLOBAL_ADMINISTRATOR: Final = "62e90394-69f5-4237-9190-012177145e10"
APPLICATION_ADMINISTRATOR: Final = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
CLOUD_APPLICATION_ADMINISTRATOR: Final = "158c047a-c907-4556-b7ef-446551a6b5f7"
PRIVILEGED_ROLE_ADMINISTRATOR: Final = "e8611ab8-c189-46e8-94e1-60213ab1f814"
DIRECTORY_READERS: Final = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"

WELL_KNOWN_GUIDS: Final[frozenset[str]] = frozenset(
    v
    for k, v in dict(globals()).items()
    if k.isupper() and isinstance(v, str) and len(v) == 36 and v.count("-") == 4
)
