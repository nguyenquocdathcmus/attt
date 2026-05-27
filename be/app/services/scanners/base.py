"""
Abstract scanner base class.

Every scanner plugin must implement ScannerBase.  The registry discovers
and instantiates scanners by name, so new scanners can be added without
modifying any existing code.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanConfig:
    """Common scan configuration passed to every scanner."""
    target_url: str
    timeout_seconds: int = 600
    auth: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)


@dataclass
class RawFinding:
    """Normalised finding from any scanner (before DB persistence)."""
    scanner: str          # scanner name, e.g. "zap", "nikto"
    type: str             # finding type, e.g. "xss", "sql-injection"
    severity: str         # "Critical" | "High" | "Medium" | "Low" | "Info"
    title: str
    description: str = ""
    url: str = ""
    evidence: dict = field(default_factory=dict)
    cwe: str | None = None
    owasp: str | None = None
    raw: dict = field(default_factory=dict)   # original scanner output


class ScannerBase(ABC):
    """
    Abstract base for all scanner plugins.

    Subclasses must implement:
      - name (property)
      - run(config) → list[RawFinding]
      - health_check() → bool
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique lowercase scanner identifier, e.g. 'zap', 'nikto'."""
        ...

    @abstractmethod
    def run(self, config: ScanConfig) -> list[RawFinding]:
        """
        Execute the scan and return normalised findings.

        Must be synchronous (run inside a Celery worker).
        Raises ScannerError on unrecoverable failure.
        """
        ...

    @abstractmethod
    def health_check(self) -> bool:
        """Return True if the scanner backend is reachable and ready."""
        ...

    def cancel(self) -> None:
        """Optional: cancel an in-progress scan. Default is no-op."""

    def supports_auth(self) -> bool:
        """Return True if this scanner supports authenticated scans."""
        return False


class ScannerError(Exception):
    """Raised when a scanner encounters an unrecoverable error."""
    def __init__(self, scanner: str, message: str) -> None:
        self.scanner = scanner
        super().__init__(f"[{scanner}] {message}")
