"""secret-hunter: HTTP-only web secret/credential hunter.

Public package API.  The CLI entry point lives in :mod:`secret_hunter.cli`.
"""

from __future__ import annotations

__version__ = "1.0.0"

from .cli import main  # noqa: E402,F401

__all__ = ["main", "__version__"]
