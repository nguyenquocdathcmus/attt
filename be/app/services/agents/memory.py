"""
Agent memory store — Redis-backed, per-agent, TTL 30 days.

Namespaced by agent_id so multiple agent instances don't collide.
Values are JSON-serialized to handle any Python type.

Usage:
    from app.services.agents.memory import AgentMemory

    mem = AgentMemory(agent_id="scanner-agent-42")
    mem.store("last_target", "https://example.com")
    mem.store("findings_count", 17)

    val = mem.retrieve("last_target")   # "https://example.com"
    mem.clear()                          # wipe all keys for this agent
"""
from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

_TTL_SECONDS = 30 * 24 * 3600   # 30 days
_PREFIX = "agent:memory:"


class AgentMemory:
    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        self._ns = f"{_PREFIX}{agent_id}:"

    # ── Write ─────────────────────────────────────────────────────────────

    def store(self, key: str, value: Any, ttl: int = _TTL_SECONDS) -> None:
        """Persist *value* under *key*, resetting the TTL."""
        from app.core.cache import get_redis
        try:
            get_redis().setex(self._ns + key, ttl, json.dumps(value, default=str))
        except Exception as exc:
            logger.warning("AgentMemory.store failed agent=%s key=%s: %s", self.agent_id, key, exc)

    def store_many(self, data: dict[str, Any], ttl: int = _TTL_SECONDS) -> None:
        """Bulk store multiple key-value pairs."""
        for k, v in data.items():
            self.store(k, v, ttl)

    # ── Read ──────────────────────────────────────────────────────────────

    def retrieve(self, key: str, default: Any = None) -> Any:
        """Return the stored value, or *default* if the key has expired or doesn't exist."""
        from app.core.cache import get_redis
        try:
            raw = get_redis().get(self._ns + key)
            if raw is None:
                return default
            return json.loads(raw)
        except Exception as exc:
            logger.warning("AgentMemory.retrieve failed agent=%s key=%s: %s", self.agent_id, key, exc)
            return default

    def retrieve_many(self, keys: list[str]) -> dict[str, Any]:
        return {k: self.retrieve(k) for k in keys}

    def exists(self, key: str) -> bool:
        from app.core.cache import get_redis
        try:
            return get_redis().exists(self._ns + key) == 1
        except Exception:
            return False

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def clear(self) -> int:
        """Delete all keys for this agent. Returns number of keys deleted."""
        from app.core.cache import get_redis
        try:
            r = get_redis()
            keys = r.keys(f"{self._ns}*")
            if keys:
                return r.delete(*keys)
            return 0
        except Exception as exc:
            logger.warning("AgentMemory.clear failed agent=%s: %s", self.agent_id, exc)
            return 0

    def list_keys(self) -> list[str]:
        from app.core.cache import get_redis
        try:
            full_keys = get_redis().keys(f"{self._ns}*")
            return [k.removeprefix(self._ns) for k in full_keys]
        except Exception:
            return []

    def touch(self, key: str, ttl: int = _TTL_SECONDS) -> None:
        """Reset the TTL on an existing key without changing its value."""
        from app.core.cache import get_redis
        try:
            get_redis().expire(self._ns + key, ttl)
        except Exception:
            pass
