"""Fang & Scale: unit tests for breach blast radius in Microsoft Entra and Azure."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("fang-and-scale")
except PackageNotFoundError:  # pragma: no cover - only when running from a raw checkout
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
