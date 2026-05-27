"""
Scanner plugin registry.

Scanners register themselves by calling register() or by being discovered
automatically if they are in the `app.services.scanners` package and export
a SCANNER_CLASS module-level attribute.

Usage:
    from app.services.scanners.registry import get_scanner, list_scanners

    scanner = get_scanner("zap")
    findings = scanner.run(config)

    # Or run multiple scanners in parallel:
    for name in list_scanners():
        scanner = get_scanner(name)
        if scanner.health_check():
            results[name] = scanner.run(config)
"""
from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import Type

from app.services.scanners.base import ScannerBase, ScannerError

logger = logging.getLogger(__name__)

_registry: dict[str, Type[ScannerBase]] = {}


# ── Registration ──────────────────────────────────────────────────────────────

def register(scanner_cls: Type[ScannerBase]) -> Type[ScannerBase]:
    """
    Register a scanner class.  Can be used as a decorator:

        @register
        class ZAPScanner(ScannerBase): ...
    """
    dummy = object.__new__(scanner_cls)
    name = scanner_cls.name.fget(dummy)   # type: ignore[attr-defined]
    if name in _registry:
        logger.debug("Scanner '%s' already registered — overwriting", name)
    _registry[name] = scanner_cls
    logger.debug("Registered scanner: %s", name)
    return scanner_cls


def auto_discover() -> None:
    """
    Scan the `app.services.scanners` package for modules that export
    a SCANNER_CLASS attribute and register them automatically.
    Called once at application startup.
    """
    import app.services.scanners as pkg
    for mod_info in pkgutil.iter_modules(pkg.__path__):
        if mod_info.name in ("base", "registry"):
            continue
        try:
            module = importlib.import_module(f"app.services.scanners.{mod_info.name}")
            cls = getattr(module, "SCANNER_CLASS", None)
            if cls is not None and issubclass(cls, ScannerBase):
                register(cls)
        except Exception as exc:
            logger.warning("Failed to auto-discover scanner %s: %s", mod_info.name, exc)


# ── Lookup ────────────────────────────────────────────────────────────────────

def get_scanner(name: str) -> ScannerBase:
    """
    Return an instantiated scanner by name.

    Raises ScannerError if the scanner is not registered.
    """
    cls = _registry.get(name)
    if cls is None:
        raise ScannerError("registry", f"Scanner '{name}' not found. Available: {list_scanners()}")
    return cls()


def list_scanners() -> list[str]:
    """Return names of all registered scanners."""
    return sorted(_registry.keys())


def run_all(config, names: list[str] | None = None):
    """
    Run multiple scanners and merge their findings.

    Args:
        config: ScanConfig shared across all scanners.
        names:  Scanner names to run (None = all registered).

    Returns:
        dict[scanner_name → list[RawFinding]]
    """
    from app.services.scanners.base import RawFinding

    targets = names or list_scanners()
    results: dict[str, list[RawFinding]] = {}

    for name in targets:
        try:
            scanner = get_scanner(name)
            if not scanner.health_check():
                logger.warning("Scanner %s health check failed — skipping", name)
                continue
            results[name] = scanner.run(config)
            logger.info("Scanner %s returned %d findings", name, len(results[name]))
        except Exception as exc:
            logger.error("Scanner %s failed: %s", name, exc)
            results[name] = []

    return results


# ── Built-in scanner adapters ─────────────────────────────────────────────────

class _ZAPScanner(ScannerBase):
    """Adapter wrapping the existing function-based zap module."""

    @property
    def name(self) -> str:
        return "zap"

    def run(self, config) -> list:
        from app.services.scanners.zap import run_full_scan
        from app.services.scanners.base import RawFinding
        raw_results = run_full_scan(
            target_url=config.target_url,
            config=config.options,
            auth_config=config.auth or None,
        )
        return [
            RawFinding(
                scanner="zap",
                type=r.get("type", "unknown"),
                severity=r.get("severity", "Info"),
                title=r.get("title", ""),
                description=r.get("description", ""),
                url=r.get("url", ""),
                evidence=r.get("evidence", {}),
                cwe=r.get("cwe"),
                owasp=r.get("owasp"),
                raw=r,
            )
            for r in (raw_results or [])
        ]

    def health_check(self) -> bool:
        try:
            import httpx
            from app.core.config import settings
            resp = httpx.get(f"{settings.zap_base_url}/JSON/core/view/version/", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def supports_auth(self) -> bool:
        return True


class _NiktoScanner(ScannerBase):
    """Adapter wrapping the existing function-based nikto module."""

    @property
    def name(self) -> str:
        return "nikto"

    def run(self, config) -> list:
        from app.services.scanners.nikto import run as nikto_run
        from app.services.scanners.base import RawFinding
        result = nikto_run(config.target_url, config=config.options)
        findings_raw = (result.get("vulnerabilities") or []) if isinstance(result, dict) else []
        return [
            RawFinding(
                scanner="nikto",
                type="nikto-finding",
                severity="Medium",
                title=v.get("msg", v.get("id", "Nikto Finding")),
                description=v.get("msg", ""),
                url=v.get("url", config.target_url),
                evidence=v,
                raw=v,
            )
            for v in findings_raw
        ]

    def health_check(self) -> bool:
        import subprocess
        try:
            result = subprocess.run(["nikto", "-Version"],
                                    capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False


# Register built-in adapters at import time
register(_ZAPScanner)
register(_NiktoScanner)
