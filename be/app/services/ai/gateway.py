"""
LLM Gateway — single entry point for all LLM calls.

Responsibilities:
  - Provider abstraction (Ollama today, OpenAI/Anthropic tomorrow)
  - Redis response cache (keyed by hash of prompt+model+format)
  - Retry with exponential backoff
  - Configurable timeout
  - Basic telemetry logging
"""
from __future__ import annotations

import hashlib
import logging
import time
from functools import lru_cache
from typing import Literal

import httpx
import redis

from app.core.config import settings

logger = logging.getLogger(__name__)

ModelHint = Literal["default", "fast", "strong"]


class LLMGateway:
    def __init__(self) -> None:
        self._base_url = settings.ollama_base_url
        self._default_model = settings.ollama_model
        self._timeout = settings.llm_timeout
        self._max_retries = settings.llm_max_retries
        self._cache_ttl = settings.llm_cache_ttl
        self._cache_enabled = settings.llm_cache_enabled
        self._redis = redis.from_url(settings.redis_url, decode_responses=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(
        self,
        prompt: str,
        model: str | None = None,
        model_hint: ModelHint = "default",
        response_format: Literal["json", "text"] | None = None,
        use_cache: bool | None = None,   # None → respect settings.llm_cache_enabled
    ) -> str:
        """
        Generate a response from the LLM.

        Args:
            prompt: The full prompt to send.
            model: Override the model name (e.g. "llama3:8b"). None = default.
            model_hint: Logical size hint used when no explicit model given.
            response_format: "json" instructs Ollama to return valid JSON.
            use_cache: Override per-call cache behaviour.

        Returns:
            Raw text response from the model (stripped).

        Raises:
            RuntimeError: If all retries are exhausted.
        """
        resolved_model = model or self._resolve_model(model_hint)
        should_cache = use_cache if use_cache is not None else self._cache_enabled

        cache_key = self._cache_key(prompt, resolved_model, response_format)

        if should_cache:
            cached = self._redis_get(cache_key)
            if cached is not None:
                logger.debug("LLM cache hit key=%s", cache_key[:20])
                try:
                    from app.core.metrics import LLM_REQUESTS_TOTAL
                    LLM_REQUESTS_TOTAL.labels(step="unknown", outcome="cache_hit").inc()
                except Exception:
                    pass
                return cached

        result = self._call_with_retry(prompt, resolved_model, response_format)

        if should_cache and result:
            self._redis_set(cache_key, result)

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _call_with_retry(
        self,
        prompt: str,
        model: str,
        response_format: str | None,
    ) -> str:
        last_exc: Exception | None = None

        for attempt in range(1, self._max_retries + 1):
            try:
                t0 = time.monotonic()
                result = self._call_ollama(prompt, model, response_format)
                elapsed = time.monotonic() - t0
                logger.info(
                    "LLM call ok model=%s attempt=%d latency_ms=%.0f",
                    model, attempt, elapsed * 1000,
                )
                try:
                    from app.core.metrics import LLM_REQUESTS_TOTAL, LLM_LATENCY_SECONDS
                    outcome = "success" if attempt == 1 else "retry"
                    LLM_REQUESTS_TOTAL.labels(step="unknown", outcome=outcome).inc()
                    LLM_LATENCY_SECONDS.labels(model=model, step="unknown").observe(elapsed)
                except Exception:
                    pass
                return result

            except httpx.TimeoutException as exc:
                last_exc = exc
                wait = 2 ** (attempt - 1)   # 1s, 2s, 4s
                logger.warning(
                    "LLM timeout model=%s attempt=%d/%d retrying in %ds",
                    model, attempt, self._max_retries, wait,
                )
                try:
                    from app.core.metrics import LLM_REQUESTS_TOTAL
                    LLM_REQUESTS_TOTAL.labels(step="unknown", outcome="retry").inc()
                except Exception:
                    pass
                time.sleep(wait)

            except httpx.HTTPStatusError as exc:
                # 5xx → retriable; 4xx → not retriable
                if exc.response.status_code >= 500:
                    last_exc = exc
                    wait = 2 ** (attempt - 1)
                    logger.warning(
                        "LLM server error %d model=%s attempt=%d/%d retrying in %ds",
                        exc.response.status_code, model, attempt, self._max_retries, wait,
                    )
                    time.sleep(wait)
                else:
                    logger.error("LLM client error %d: %s", exc.response.status_code, exc)
                    try:
                        from app.core.metrics import LLM_REQUESTS_TOTAL
                        LLM_REQUESTS_TOTAL.labels(step="unknown", outcome="error").inc()
                    except Exception:
                        pass
                    raise

        logger.error("LLM call failed after %d retries model=%s", self._max_retries, model)
        try:
            from app.core.metrics import LLM_REQUESTS_TOTAL
            LLM_REQUESTS_TOTAL.labels(step="unknown", outcome="error").inc()
        except Exception:
            pass
        raise RuntimeError(
            f"LLM call failed after {self._max_retries} retries"
        ) from last_exc

    def _call_ollama(
        self,
        prompt: str,
        model: str,
        response_format: str | None,
    ) -> str:
        payload: dict = {
            "model": model,
            "prompt": prompt,
            "stream": False,
        }
        if response_format == "json":
            payload["format"] = "json"

        resp = httpx.post(
            f"{self._base_url}/api/generate",
            json=payload,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json().get("response", "").strip()

    def _resolve_model(self, hint: ModelHint) -> str:
        # All hints map to the same model when only Ollama is available.
        # Extend this when adding OpenAI/Anthropic providers.
        return self._default_model

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    def _cache_key(self, prompt: str, model: str, fmt: str | None) -> str:
        raw = f"{model}:{fmt}:{prompt}"
        digest = hashlib.sha256(raw.encode()).hexdigest()
        return f"llm:cache:{digest}"

    def _redis_get(self, key: str) -> str | None:
        try:
            return self._redis.get(key)
        except Exception as exc:
            logger.debug("Redis get failed: %s", exc)
            return None

    def _redis_set(self, key: str, value: str) -> None:
        try:
            self._redis.setex(key, self._cache_ttl, value)
        except Exception as exc:
            logger.debug("Redis set failed: %s", exc)


@lru_cache(maxsize=1)
def get_gateway() -> LLMGateway:
    """Return the process-wide singleton gateway instance."""
    return LLMGateway()
