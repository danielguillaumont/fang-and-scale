"""Record live traffic as a sanitized fixture set (used by ``fns scout --record``)."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from fns.adapters.azure.http import ApiRequest, ApiResponse, Transport
from fns.fixtures.replay import FIXTURE_LABEL, FORMAT
from fns.fixtures.sanitize import IdMap, sanitize, sanitize_text
from fns.models.ids import utc_isoformat

IDMAP_FILE = "_idmap.json"
SCOPE_HEADER = "# Sanitized copy recorded by `fns scout --record`. Placeholder IDs only.\n"


def _strip_leading_comments(text: str) -> str:
    """Drop the live file's header comment; it describes the live file, not this copy."""
    lines = text.splitlines(keepends=True)
    while lines and lines[0].lstrip().startswith("#"):
        lines.pop(0)
    return "".join(lines)


class Recorder:
    """Wraps a transport; the caller still gets the real response."""

    def __init__(
        self,
        inner: Transport,
        out_dir: Path,
        *,
        name: str,
        tenant_id: str,
        recorded_at: datetime,
        description: str = "",
    ) -> None:
        self.inner = inner
        self.out_dir = out_dir
        self.name = name
        self.tenant_id = tenant_id
        self.recorded_at = recorded_at
        self.description = description
        self.idmap = IdMap.load(out_dir / IDMAP_FILE)
        self.exchanges: list[dict[str, Any]] = []

    def fetch(self, request: ApiRequest) -> ApiResponse:
        response = self.inner.fetch(request)
        self.exchanges.append(
            {
                "request": f"{request.method} {sanitize_text(request.url, self.idmap)}",
                "response": {
                    "status": response.status,
                    "body": sanitize(response.body, self.idmap),
                    "request_id": None,
                    "retry_after": response.retry_after,
                },
            }
        )
        return response

    def finalize(self, scope_yaml: str) -> Path:
        """Write manifest.json, exchanges.json, a sanitized scope.yaml and the idmap."""
        self.out_dir.mkdir(parents=True, exist_ok=True)

        def write(name: str, text: str) -> None:
            (self.out_dir / name).write_text(text, encoding="utf-8", newline="\n")

        manifest = {
            "format": FORMAT,
            "name": self.name,
            "label": FIXTURE_LABEL,
            "recorded_at": utc_isoformat(self.recorded_at),
            "tenant_id": sanitize_text(self.tenant_id, self.idmap),
            "description": self.description,
        }
        write("exchanges.json", json.dumps(self.exchanges, indent=2, sort_keys=True) + "\n")
        write(
            "scope.yaml",
            SCOPE_HEADER + _strip_leading_comments(sanitize_text(scope_yaml, self.idmap)),
        )
        write("manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        self.idmap.save(self.out_dir / IDMAP_FILE)
        return self.out_dir
