import logging
import time
from typing import Any, Callable
from urllib.parse import quote, urlparse

import httpx
from zapv2 import ZAPv2

from app.core.config import settings

logger = logging.getLogger(__name__)


def _wait_for_completion(
    status_fn: Callable[[str], str],
    scan_id: str,
    timeout_seconds: int,
    poll_seconds: int,
    cancel_fn: Callable[[], bool] | None = None,
) -> None:
    start = time.time()
    while True:
        progress = int(status_fn(scan_id))
        if progress >= 100:
            return
        if time.time() - start > timeout_seconds:
            raise TimeoutError("ZAP scan timed out")
        if cancel_fn and cancel_fn():
            raise InterruptedError("Scan cancelled by user")
        time.sleep(poll_seconds)


def _run_ajax_spider(zap: ZAPv2, target_url: str, timeout_seconds: int) -> None:
    logger.info("Starting AJAX Spider on %s", target_url)
    zap.ajaxSpider.scan(target_url)
    start = time.time()
    while zap.ajaxSpider.status == "running":
        if time.time() - start > timeout_seconds:
            logger.warning("AJAX Spider timed out, stopping")
            zap.ajaxSpider.stop()
            break
        time.sleep(3)
    logger.info("AJAX Spider finished, found %s URLs", zap.ajaxSpider.number_of_results)


def _inject_jwt_header(zap: ZAPv2, auth_cfg: dict) -> None:
    """Login to target app, get JWT, inject via ZAP Replacer rule."""
    login_url = auth_cfg.get("login_url", "")
    payload = auth_cfg.get("payload", {})
    token_path = auth_cfg.get("token_path", "authentication.token")
    header_name = auth_cfg.get("header", "Authorization")
    header_prefix = auth_cfg.get("header_prefix", "Bearer")

    try:
        resp = httpx.post(login_url, json=payload, timeout=15, verify=False)
        resp.raise_for_status()
        data = resp.json()

        # Walk the token_path like "authentication.token" or just "token"
        token = data
        for key in token_path.split("."):
            token = token.get(key, {})
        token = str(token)

        zap.replacer.add_rule(
            description="JWT auth header",
            enabled="true",
            matchtype="REQ_HEADER",
            matchregex="false",
            matchstring=header_name,
            replacement=f"{header_prefix} {token}",
            initiators="",
        )
        logger.info("Injected JWT header %s", header_name)
    except Exception as exc:
        logger.warning("JWT header injection failed: %s", exc)


def _ensure_context(zap: ZAPv2, target_url: str, cfg: dict) -> tuple[str, str | None]:
    context_cfg = cfg.get("context", {}) if isinstance(cfg.get("context"), dict) else {}
    context_name = context_cfg.get("name") or f"scan-{int(time.time())}"
    context_id = zap.context.new_context(context_name)

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    includes = context_cfg.get("include") or [f"{base}.*"]
    excludes = context_cfg.get("exclude") or []

    for pattern in includes:
        zap.context.include_in_context(context_name, pattern)
    for pattern in excludes:
        zap.context.exclude_from_context(context_name, pattern)

    session_mgmt = context_cfg.get("session") or "cookie"
    if session_mgmt == "cookie":
        zap.sessionManagement.set_session_management_method(
            context_id, "cookieBasedSessionManagement", ""
        )

    auth_cfg = cfg.get("auth") if isinstance(cfg.get("auth"), dict) else None
    if not auth_cfg:
        return context_id, None

    auth_type = auth_cfg.get("type", "form")

    # JWT header auth: login externally, inject via Replacer — no ZAP user needed
    if auth_type == "jwt_header":
        _inject_jwt_header(zap, auth_cfg)
        return context_id, None

    user_id = zap.users.new_user(context_id, auth_cfg.get("user", "default"))

    if auth_type == "form":
        login_url = auth_cfg.get("login_url") or target_url
        username_field = auth_cfg.get("username_field", "username")
        password_field = auth_cfg.get("password_field", "password")
        username = auth_cfg.get("username", "")
        password = auth_cfg.get("password", "")

        login_data = f"{username_field}={quote(username)}&{password_field}={quote(password)}"
        method_params = f"loginUrl={login_url}&loginRequestData={login_data}"
        zap.authentication.set_authentication_method(
            context_id, "formBasedAuthentication", method_params
        )
        creds = f"username={quote(username)}&password={quote(password)}"
        zap.users.set_authentication_credentials(context_id, user_id, creds)
    elif auth_type == "basic":
        hostname = auth_cfg.get("hostname") or parsed.hostname or ""
        port = auth_cfg.get("port") or (parsed.port or (443 if parsed.scheme == "https" else 80))
        realm = auth_cfg.get("realm", "")

        method_params = f"hostname={hostname}&realm={realm}&port={port}"
        zap.authentication.set_authentication_method(
            context_id, "httpAuthentication", method_params
        )
        creds = f"username={quote(auth_cfg.get('username', ''))}&password={quote(auth_cfg.get('password', ''))}"
        zap.users.set_authentication_credentials(context_id, user_id, creds)

    zap.users.set_user_enabled(context_id, user_id, "true")
    zap.forcedUser.set_forced_user(context_id, user_id)
    zap.forcedUser.set_forced_user_mode_enabled("true")

    return context_id, user_id


def run(
    target_url: str,
    config: dict | None = None,
    cancel_fn: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    cfg = config or {}
    timeout_seconds = int(cfg.get("timeout_seconds", 600))
    ajax_timeout = int(cfg.get("ajax_timeout_seconds", 300))

    zap = ZAPv2(
        apikey=settings.zap_api_key or None,
        proxies={"http": settings.zap_base_url, "https": settings.zap_base_url},
    )

    if cfg.get("new_session", True):
        zap.core.new_session(f"scan-{int(time.time())}", True)

    context_id, user_id = _ensure_context(zap, target_url, cfg)

    # Traditional Spider (fast HTML crawl)
    if cfg.get("spider", True):
        logger.info("Starting Traditional Spider on %s", target_url)
        if user_id:
            spider_id = zap.spider.scan_as_user(context_id, user_id, target_url, True)
        else:
            spider_id = zap.spider.scan(target_url)
        _wait_for_completion(zap.spider.status, spider_id, timeout_seconds, 2, cancel_fn)

    # AJAX Spider — required for Angular/React SPAs like Juice Shop
    if cfg.get("ajax_spider", False):
        _run_ajax_spider(zap, target_url, ajax_timeout)

    if cfg.get("active", True):
        # Limit total scan and per-rule duration so timing-based rules (SQLi, etc.)
        # don't run indefinitely. Defaults: 5 min total, 1 min per rule.
        max_scan_mins = int(cfg.get("max_scan_duration_mins", 5))
        max_rule_mins = int(cfg.get("max_rule_duration_mins", 1))
        zap.ascan.set_option_max_scan_duration_in_mins(max_scan_mins)
        zap.ascan.set_option_max_rule_duration_in_mins(max_rule_mins)

        logger.info(
            "Starting Active Scan on %s (max %dm, %dm/rule)",
            target_url, max_scan_mins, max_rule_mins,
        )
        if user_id:
            scan_id = zap.ascan.scan_as_user(context_id, user_id, target_url)
        else:
            scan_id = zap.ascan.scan(target_url)
        try:
            _wait_for_completion(zap.ascan.status, scan_id, timeout_seconds, 5, cancel_fn)
        except InterruptedError:
            zap.ascan.stop_all_scans()
            logger.info("ZAP active scan stopped by cancel request")
            raise

    alerts = zap.core.alerts(baseurl=target_url)
    logger.info("ZAP scan complete: %d alerts", len(alerts))
    return {
        "scanner": "zap",
        "target": target_url,
        "alerts": alerts,
        "config": cfg,
    }
