"""Evidence bundle: the verifier's signed verdict on one ``fns prove`` run.

Built only by ``fns.verify`` from frozen assertions, the journal and the probe
artifacts. The bundle digest excludes ``generated_at`` and ``tool_version``.
"""

from __future__ import annotations

from typing import ClassVar, Final, Literal

from pydantic import Field, NonNegativeInt, field_validator, model_validator

from fns.models.base import FnsModel
from fns.models.evidence import Finding
from fns.models.ids import TzDatetime

PREDICATE_TYPE: Final = (
    "https://github.com/danielguillaumont/fang-and-scale/blob/main/docs/predicates/prove-v1.md"
)
STATEMENT_TYPE: Final = "https://in-toto.io/Statement/v1"
DSSE_PAYLOAD_TYPE: Final = "application/vnd.in-toto+json"


class ArtifactRef(FnsModel):
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    probe_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    finding_id: str = Field(pattern=r"^[0-9a-f]{64}$")


class StrikeArtifactRef(FnsModel):
    """A strike observation the verifier read (``fns prove --after-strike``, D6)."""

    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    write_key: str = Field(min_length=1)
    finding_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    """The finding it was attached to; unset when no contract item matched."""


class BundleSummary(FnsModel):
    passed: NonNegativeInt
    critical: NonNegativeInt
    """Failed must_not_reach findings."""
    still_do_failed: NonNegativeInt
    inconclusive: NonNegativeInt
    exit_code: Literal[0, 1, 3]
    warning: str | None = None


class EvidenceBundle(FnsModel):
    __volatile__: ClassVar[frozenset[str]] = frozenset({"generated_at", "tool_version"})
    __omit_empty__: ClassVar[frozenset[str]] = frozenset({"strike_artifacts"})

    version: Literal[1]
    mode: Literal["LIVE", "FIXTURE"]
    run_id: str = Field(pattern=r"^[0-9a-f]{16,64}$")
    contract: str = Field(min_length=1)
    tenant_id: str
    assertions_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    """sha256 of ``assertions.json`` as frozen and journaled."""
    contract_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    verifier: str = Field(min_length=1)
    """Who verified: ``fns.verify`` plus the identity label it ran as."""
    generated_at: TzDatetime
    tool_version: str
    findings: tuple[Finding, ...]
    artifacts: tuple[ArtifactRef, ...] = ()
    strike_artifacts: tuple[StrikeArtifactRef, ...] = ()
    """After-harden strike observations (D6). Left out of the canonical JSON while
    empty, so every bundle made without ``--after-strike`` keeps its digest."""
    summary: BundleSummary

    @field_validator("findings")
    @classmethod
    def _sort_findings(cls, v: tuple[Finding, ...]) -> tuple[Finding, ...]:
        return tuple(sorted(v, key=lambda f: f.id))

    @field_validator("strike_artifacts")
    @classmethod
    def _sort_strikes(cls, v: tuple[StrikeArtifactRef, ...]) -> tuple[StrikeArtifactRef, ...]:
        return tuple(sorted(v, key=lambda a: (a.sha256, a.write_key, a.finding_id or "")))

    @field_validator("artifacts")
    @classmethod
    def _sort_artifacts(cls, v: tuple[ArtifactRef, ...]) -> tuple[ArtifactRef, ...]:
        return tuple(sorted(v, key=lambda a: (a.sha256, a.probe_id)))

    @model_validator(mode="after")
    def _consistent(self) -> EvidenceBundle:
        ids = {f.id for f in self.findings}
        if len(ids) != len(self.findings):
            raise ValueError("duplicate finding")
        if any(a.finding_id not in ids for a in self.artifacts):
            raise ValueError("artifact refers to an unknown finding")
        s = self.summary
        verdicts = [f.verdict for f in self.findings]
        if s.passed != verdicts.count("pass") or s.inconclusive != verdicts.count("inconclusive"):
            raise ValueError("summary does not match the findings")
        return self
