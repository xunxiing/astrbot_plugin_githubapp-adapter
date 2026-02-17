from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from urllib import error, parse, request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from astrbot.api import logger
from astrbot.api.event import MessageChain
from astrbot.api.message_components import Plain
from astrbot.api.platform import (
    AstrBotMessage,
    MessageMember,
    MessageType,
    Platform,
    PlatformMetadata,
    register_platform_adapter,
)
from astrbot.core.platform.astr_message_event import MessageSesion
from astrbot.core.utils.astrbot_path import (
    get_astrbot_config_path,
    get_astrbot_plugin_data_path,
)
from astrbot.core.utils.webhook_utils import log_webhook_info

from .github_event import SUPPORTED_EVENTS, GitHubParsedEvent, parse_github_event
from .github_event_message import GitHubAppMessageEvent
from .security import (
    DeliveryDeduplicator,
    fallback_delivery_id,
    verify_github_signature,
)

PLUGIN_ROOT_DIR = "astrbot_plugin_githubapp-adopter"
ADAPTER_BUILD_MARK = "2026-02-17.2"
MENTION_PATTERN = re.compile(r"(?<![A-Za-z0-9_])@[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
SENDABLE_THREAD_TYPES = {"issue", "pr"}


@dataclass(slots=True)
class GitHubSessionRoute:
    repo: str
    thread_type: str
    thread_number: int | None
    installation_id: int | None


@dataclass(slots=True)
class InstallationTokenCacheEntry:
    token: str
    expires_at: float


class PluginConfigStore:
    def __init__(self, plugin_root_dir: str) -> None:
        config_name = f"{plugin_root_dir}_config.json"
        self._paths = self._build_candidate_paths(config_name)
        self._cached_data: dict[str, Any] = {}
        self._cached_signature: tuple[str, int, int] | None = None
        self.last_selected_path = ""
        self.last_existing_paths: list[str] = []
        self.last_error = ""
        self.last_candidate_paths: list[str] = [str(p) for p in self._paths]

    @staticmethod
    def _build_candidate_paths(config_name: str) -> list[Path]:
        roots: list[Path] = []
        roots.append(Path(get_astrbot_config_path()))

        if astrbot_root := os.environ.get("ASTRBOT_ROOT"):
            roots.append(Path(astrbot_root) / "data" / "config")

        file_path = Path(__file__).resolve()
        for ancestor in file_path.parents:
            if ancestor.name == "data":
                roots.append(ancestor / "config")
            roots.append(ancestor / "data" / "config")

        candidates = [(root / config_name).resolve(strict=False) for root in roots]
        deduped = list(dict.fromkeys(candidates))
        return deduped

    def get(self) -> dict[str, Any]:
        existing_paths = [p for p in self._paths if p.exists()]
        self.last_existing_paths = [str(p) for p in existing_paths]
        if not existing_paths:
            self.last_selected_path = ""
            self.last_error = "no_config_file_found"
            return {}
        try:
            selected = max(
                existing_paths,
                key=lambda p: p.stat().st_mtime_ns,
            )
            stat = selected.stat()
            signature = (str(selected), stat.st_mtime_ns, stat.st_size)
            self.last_selected_path = str(selected)
            self.last_error = ""
        except OSError:
            self.last_error = "stat_failed"
            return {}
        if signature == self._cached_signature:
            return self._cached_data
        try:
            with selected.open("r", encoding="utf-8-sig") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    self._cached_data = data
                    self._cached_signature = signature
                    self.last_error = ""
                    return data
        except Exception as exc:
            self.last_error = f"load_failed:{type(exc).__name__}:{exc}"
            logger.warning(f"[GitHubApp] failed to load plugin config: {exc}")
        return self._cached_data


def _ensure_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    if isinstance(value, str) and value.strip():
        return [x.strip() for x in value.split(",") if x.strip()]
    return []


def _make_message_chain_text(message_chain: MessageChain) -> str:
    parts: list[str] = []
    for component in message_chain.chain:
        if isinstance(component, Plain):
            parts.append(component.text)
        else:
            parts.append(f"[{component.type}]")
    return "".join(parts).strip()


def _normalize_pem_text(text: Any) -> str:
    if not isinstance(text, str):
        return ""
    value = text.strip()
    if not value:
        return ""
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _is_valid_pem_private_key(pem: str) -> bool:
    try:
        serialization.load_pem_private_key(
            pem.encode("utf-8"),
            password=None,
        )
        return True
    except Exception:
        return False


def _read_first_valid_private_key_text(
    paths: list[str],
) -> tuple[str, str, list[str]]:
    diagnostics: list[str] = []
    for path in paths:
        if not path:
            continue
        target_path = Path(path)
        if not target_path.is_file():
            diagnostics.append(f"missing:{target_path}")
            continue
        try:
            pem = target_path.read_text(encoding="utf-8")
            pem = _normalize_pem_text(pem)
            if pem and _is_valid_pem_private_key(pem):
                return pem, str(target_path), diagnostics
            diagnostics.append(f"invalid_pem:{target_path}")
        except Exception as exc:
            diagnostics.append(f"read_error:{target_path}:{type(exc).__name__}")
            continue
    return "", "", diagnostics


def _extract_mention_candidate_texts(event_name: str, payload: Mapping) -> list[str]:
    candidates: list[str] = []

    def append_body(node: Any) -> None:
        if not isinstance(node, Mapping):
            return
        body = node.get("body")
        if isinstance(body, str):
            text = body.strip()
            if text:
                candidates.append(text)

    append_body(payload.get("comment"))
    append_body(payload.get("review"))

    if event_name in {"issues", "issue_comment"}:
        append_body(payload.get("issue"))
    if event_name.startswith("pull_request"):
        append_body(payload.get("pull_request"))
    if event_name.startswith("discussion"):
        append_body(payload.get("discussion"))

    return candidates


def _extract_mentions_from_text(text: str) -> set[str]:
    if not isinstance(text, str) or not text:
        return set()
    return {m.group(0)[1:].lower() for m in MENTION_PATTERN.finditer(text)}


def _extract_event_mentions(event_name: str, payload: Mapping) -> set[str]:
    mentions: set[str] = set()
    for text in _extract_mention_candidate_texts(event_name, payload):
        mentions.update(_extract_mentions_from_text(text))
    return mentions


def _event_has_mention(event_name: str, payload: Mapping) -> bool:
    return bool(_extract_event_mentions(event_name, payload))


def _extract_text_after_mentions(text: str) -> str:
    if not isinstance(text, str):
        return ""
    cleaned = MENTION_PATTERN.sub(" ", text)
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
    return "\n".join(lines).strip()


def _extract_user_message_text(
    event_name: str,
    payload: Mapping,
    has_mention: bool,
) -> str:
    candidates = _extract_mention_candidate_texts(event_name, payload)
    if not candidates:
        return ""

    if has_mention:
        for text in candidates:
            if not MENTION_PATTERN.search(text):
                continue
            after_mention = _extract_text_after_mentions(text)
            if after_mention:
                return after_mention

    for text in candidates:
        value = text.strip()
        if value:
            return value
    return ""


def _replace_event_message_text(event: GitHubAppMessageEvent, text: str) -> None:
    value = (text or "").strip()
    if not value:
        return
    event.message_str = value
    event.message_obj.message_str = value
    event.message_obj.message = [Plain(text=value)]


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _parse_session_route(
    session_id: str, installation_id: int | None = None
) -> GitHubSessionRoute | None:
    if not isinstance(session_id, str):
        return None
    parts = session_id.split(":", 3)
    if len(parts) != 4:
        return None
    platform, repo, thread_type, raw_number = parts
    if platform != "github":
        return None
    if not repo:
        return None
    thread_number = int(raw_number) if raw_number.isdigit() else None
    return GitHubSessionRoute(
        repo=repo,
        thread_type=thread_type,
        thread_number=thread_number,
        installation_id=installation_id,
    )


def _get_runtime_plugin_config_snapshot() -> dict[str, Any]:
    try:
        from ..main import get_runtime_plugin_config

        config = get_runtime_plugin_config()
        if isinstance(config, dict):
            return config
    except Exception:
        pass
    return {}


def _stringify_github_error(data: Any) -> str:
    if isinstance(data, Mapping):
        message = data.get("message")
        errors = data.get("errors")
        doc_url = data.get("documentation_url")
        parts: list[str] = []
        if isinstance(message, str) and message:
            parts.append(message)
        if isinstance(errors, list) and errors:
            parts.append(f"errors={errors}")
        elif isinstance(errors, Mapping):
            parts.append(f"errors={dict(errors)}")
        if isinstance(doc_url, str) and doc_url:
            parts.append(f"doc={doc_url}")
        if parts:
            return "; ".join(parts)
    if isinstance(data, str):
        text = data.strip()
        return text[:500] if text else ""
    return ""


@register_platform_adapter(
    "github_app",
    "GitHub App Webhook 适配器（AstrBot）",
    default_config_tmpl={
        "id": "github_app",
        "type": "github_app",
        "enable": False,
        "github_app_id": "",
        "github_webhook_secret": "",
        "github_api_base_url": "https://api.github.com",
        "github_events": [],
        "wake_event_types": ["issues", "pull_request"],
        "wake_on_mentions": True,
        "mention_target_logins": [],
        "github_signature_validation": True,
        "github_delivery_cache_ttl_seconds": 900,
        "github_delivery_cache_max_entries": 10000,
        "unified_webhook_mode": True,
        "webhook_uuid": "",
    },
    adapter_display_name="GitHub 应用",
    support_streaming_message=False,
)
class GitHubAppAdapter(Platform):
    def __init__(
        self,
        platform_config: dict,
        platform_settings: dict,
        event_queue: asyncio.Queue,
    ) -> None:
        super().__init__(platform_config, event_queue)
        self.settings = platform_settings
        self._shutdown_event = asyncio.Event()

        platform_id = cast(str, platform_config.get("id", "github_app"))
        self._metadata = PlatformMetadata(
            name="github_app",
            description="GitHub App Webhook 适配器（AstrBot）",
            id=platform_id,
            support_streaming_message=False,
        )

        self._plugin_config_store = PluginConfigStore(PLUGIN_ROOT_DIR)
        self._delivery_cache = DeliveryDeduplicator()

        self.github_app_id = ""
        self.github_webhook_secret = ""
        self.github_api_base_url = "https://api.github.com"
        self.enable_signature_validation = True
        self.github_events: set[str] = set(SUPPORTED_EVENTS)
        self.wake_event_types: set[str] = set()
        self.wake_on_mentions = True
        self.mention_target_logins: set[str] = set()
        self.private_key_text = ""
        self._private_key_debug: dict[str, Any] = {}
        self._session_routes: dict[str, GitHubSessionRoute] = {}
        self._installation_token_cache: dict[int, InstallationTokenCacheEntry] = {}
        self._cached_app_slug = ""
        self._warned_no_mention_target = False
        self._http_timeout_seconds = 15

        self._refresh_runtime_config()
        logger.info(
            "[GitHubApp] adapter loaded "
            f"mark={ADAPTER_BUILD_MARK} "
            f"file={Path(__file__).resolve()}"
        )

    def meta(self) -> PlatformMetadata:
        return self._metadata

    async def send_by_session(
        self,
        session: MessageSesion,
        message_chain: MessageChain,
    ):
        text = _make_message_chain_text(message_chain)
        if text:
            success, reason = await self._send_text_to_github(
                session.session_id,
                text,
            )
            if success:
                logger.info(
                    f"[GitHubApp] posted comment to GitHub (session={session.session_id})"
                )
            else:
                logger.warning(
                    f"[GitHubApp] failed to post comment (session={session.session_id}): {reason}"
                )
        await super().send_by_session(session, message_chain)

    def run(self):
        return self._run()

    async def _run(self):
        if self.unified_webhook():
            log_webhook_info(
                self.meta().id + "(GitHub App)", self.config["webhook_uuid"]
            )
        else:
            logger.warning(
                "[GitHubApp] unified_webhook_mode is disabled or webhook_uuid missing"
            )
        await self._shutdown_event.wait()

    async def terminate(self):
        self._shutdown_event.set()

    async def webhook_callback(self, request: Any) -> Any:
        self._refresh_runtime_config()

        raw_body = cast(bytes, await request.get_data())
        event_name = str(request.headers.get("X-GitHub-Event", "")).strip().lower()
        delivery_id = str(request.headers.get("X-GitHub-Delivery", "")).strip()
        signature = request.headers.get("X-Hub-Signature-256")

        if not raw_body:
            return {"error": "empty body"}, 400
        if not event_name:
            return {"error": "missing event header"}, 400

        if self.enable_signature_validation:
            if not self.github_webhook_secret:
                return {"error": "webhook secret missing"}, 500
            if not verify_github_signature(
                self.github_webhook_secret, raw_body, signature
            ):
                return {"error": "invalid signature"}, 401

        dedup_key = (
            f"{event_name}:{delivery_id}"
            if delivery_id
            else fallback_delivery_id(event_name, raw_body)
        )
        if await self._delivery_cache.seen_before(dedup_key):
            return {"status": "duplicate_ignored"}, 200

        if event_name == "ping":
            return {"status": "pong"}, 200

        if event_name not in self.github_events:
            return {"status": "ignored", "reason": "event_not_subscribed"}, 200

        payload = await request.get_json(silent=True)
        if not isinstance(payload, dict):
            try:
                payload = json.loads(raw_body.decode("utf-8"))
            except Exception:
                return {"error": "invalid json"}, 400
        if not isinstance(payload, Mapping):
            return {"error": "invalid payload"}, 400

        parsed = parse_github_event(event_name, payload)
        if not parsed:
            return {"status": "ignored", "reason": "unsupported_event"}, 200

        self._remember_session_route(parsed)
        event = self._build_message_event(parsed, payload, delivery_id)
        mentions = _extract_event_mentions(parsed.event_name, payload)
        has_mention = bool(mentions)
        mention_targets = await self._get_effective_mention_targets()
        bot_mentioned = bool(mentions & mention_targets)
        if self.wake_on_mentions and has_mention and not mention_targets:
            if not self._warned_no_mention_target:
                logger.warning(
                    "[GitHubApp] mentions detected but no mention target is known; "
                    "set mention_target_logins or ensure app slug is readable"
                )
                self._warned_no_mention_target = True

        user_message_text = _extract_user_message_text(
            parsed.event_name,
            payload,
            has_mention,
        )
        if user_message_text:
            _replace_event_message_text(event, user_message_text)
            event.set_extra("github_user_message", user_message_text)

        wake_by_event_type = parsed.event_name in self.wake_event_types
        wake_by_mention = self.wake_on_mentions and bot_mentioned
        event.set_extra("github_contains_mention", has_mention)
        event.set_extra("github_mentions", sorted(mentions))
        event.set_extra("github_mention_targets", sorted(mention_targets))
        event.set_extra("github_bot_mentioned", bot_mentioned)
        if wake_by_event_type or wake_by_mention:
            event.is_wake = True
            event.is_at_or_wake_command = True
            event.set_extra(
                "github_wake_reason", "mention" if wake_by_mention else "event_type"
            )

        self.commit_event(event)
        return {"status": "accepted"}, 200

    def _refresh_runtime_config(self) -> None:
        file_plugin_cfg = self._plugin_config_store.get()
        runtime_plugin_cfg = _get_runtime_plugin_config_snapshot()
        plugin_cfg = dict(file_plugin_cfg)
        if runtime_plugin_cfg:
            plugin_cfg.update(runtime_plugin_cfg)

        self.github_app_id = str(self.config.get("github_app_id", "")).strip()
        self.github_webhook_secret = str(
            self.config.get("github_webhook_secret", "")
        ).strip()
        self.github_api_base_url = str(
            self.config.get("github_api_base_url", "https://api.github.com")
        ).rstrip("/")

        signature_validation = self.config.get("github_signature_validation")
        if signature_validation is None:
            signature_validation = plugin_cfg.get("enable_signature_validation", True)
        self.enable_signature_validation = bool(signature_validation)

        events = _ensure_list(self.config.get("github_events"))
        if not events:
            events = _ensure_list(plugin_cfg.get("default_github_events"))
        if events:
            self.github_events = {e for e in events if e in SUPPORTED_EVENTS}
        else:
            self.github_events = set(SUPPORTED_EVENTS)

        wake_events = _ensure_list(self.config.get("wake_event_types"))
        if not wake_events:
            wake_events = _ensure_list(plugin_cfg.get("default_wake_event_types"))
        self.wake_event_types = {e for e in wake_events if e in SUPPORTED_EVENTS}
        wake_on_mentions = self.config.get("wake_on_mentions")
        if wake_on_mentions is None:
            wake_on_mentions = plugin_cfg.get("default_wake_on_mentions", True)
        self.wake_on_mentions = bool(wake_on_mentions)
        mention_target_logins = _ensure_list(self.config.get("mention_target_logins"))
        if not mention_target_logins:
            mention_target_logins = _ensure_list(
                plugin_cfg.get("default_mention_target_logins")
            )
        self.mention_target_logins = {
            login.lower() for login in mention_target_logins if login
        }

        ttl_seconds = self.config.get(
            "github_delivery_cache_ttl_seconds",
            plugin_cfg.get("delivery_cache_ttl_seconds", 900),
        )
        max_entries = self.config.get(
            "github_delivery_cache_max_entries",
            plugin_cfg.get("delivery_cache_max_entries", 10000),
        )
        self._delivery_cache.reconfigure(
            int(ttl_seconds) if str(ttl_seconds).strip() else 900,
            int(max_entries) if str(max_entries).strip() else 10000,
        )

        file_private_key_files = _ensure_list(file_plugin_cfg.get("private_key_files"))
        runtime_private_key_files = _ensure_list(
            runtime_plugin_cfg.get("private_key_files")
        )
        configured_private_key_files = runtime_private_key_files or file_private_key_files
        platform_private_key_files = _ensure_list(self.config.get("private_key_files"))
        effective_private_key_files = (
            configured_private_key_files or platform_private_key_files
        )
        auto_discovered_private_key_paths: list[str] = []
        if not effective_private_key_files:
            auto_discovered_private_key_paths = self._auto_discover_private_key_paths()
            effective_private_key_files = auto_discovered_private_key_paths

        private_key_paths = self._resolve_private_key_paths(effective_private_key_files)
        (
            self.private_key_text,
            hit_private_key_path,
            private_key_diagnostics,
        ) = _read_first_valid_private_key_text(private_key_paths)
        existing_paths = [p for p in private_key_paths if Path(p).is_file()]
        self._private_key_debug = {
            "configured": configured_private_key_files,
            "file_config_private_key_files": file_private_key_files,
            "runtime_config_private_key_files": runtime_private_key_files,
            "platform_config_private_key_files": platform_private_key_files,
            "effective_private_key_files": effective_private_key_files,
            "auto_discovered_private_key_paths": auto_discovered_private_key_paths,
            "mention_target_logins": sorted(self.mention_target_logins),
            "cached_app_slug": self._cached_app_slug,
            "plugin_config_keys": sorted(plugin_cfg.keys()),
            "file_plugin_config_keys": sorted(file_plugin_cfg.keys()),
            "runtime_plugin_config_keys": sorted(runtime_plugin_cfg.keys()),
            "plugin_config_source": self._plugin_config_store.last_selected_path,
            "plugin_config_existing_paths": self._plugin_config_store.last_existing_paths,
            "plugin_config_candidate_paths": self._plugin_config_store.last_candidate_paths,
            "plugin_config_error": self._plugin_config_store.last_error,
            "resolved": private_key_paths,
            "existing": existing_paths,
            "hit": hit_private_key_path,
            "diagnostics": private_key_diagnostics,
        }
        if private_key_paths and not self.private_key_text:
            logger.warning(
                "[GitHubApp] private key files configured but none are valid "
                f"(searched={len(private_key_paths)}, existing={len(existing_paths)}) "
                f"configured={configured_private_key_files} "
                f"platform_cfg={platform_private_key_files} "
                f"plugin_cfg_source={self._plugin_config_store.last_selected_path} "
                f"plugin_cfg_error={self._plugin_config_store.last_error} "
                f"plugin_cfg_candidates={self._plugin_config_store.last_candidate_paths} "
                f"auto_discovered={auto_discovered_private_key_paths} "
                f"resolved={private_key_paths} "
                f"existing_paths={existing_paths} "
                f"diagnostics={private_key_diagnostics}"
            )

    def _collect_plugin_data_roots(self) -> list[Path]:
        roots: list[Path] = []
        roots.append(Path(get_astrbot_plugin_data_path()) / PLUGIN_ROOT_DIR)

        if astrbot_root := os.environ.get("ASTRBOT_ROOT"):
            roots.append(Path(astrbot_root) / "data" / "plugin_data" / PLUGIN_ROOT_DIR)
            roots.append(Path(astrbot_root) / "data" / "plugins_data" / PLUGIN_ROOT_DIR)

        file_path = Path(__file__).resolve()
        for ancestor in file_path.parents:
            if ancestor.name == "data":
                roots.append(ancestor / "plugin_data" / PLUGIN_ROOT_DIR)
                roots.append(ancestor / "plugins_data" / PLUGIN_ROOT_DIR)
            roots.append(ancestor / "data" / "plugin_data" / PLUGIN_ROOT_DIR)
            roots.append(ancestor / "data" / "plugins_data" / PLUGIN_ROOT_DIR)

        deduped = list(dict.fromkeys(p.resolve(strict=False) for p in roots))
        return deduped

    def _auto_discover_private_key_paths(self) -> list[str]:
        discovered: list[str] = []
        for root in self._collect_plugin_data_roots():
            if not root.exists() or not root.is_dir():
                continue
            for pattern in ("files/**/*.pem", "**/*.pem"):
                for pem_path in root.glob(pattern):
                    if pem_path.is_file():
                        discovered.append(str(pem_path.resolve()))
        return list(dict.fromkeys(discovered))

    def _resolve_private_key_paths(self, candidates: list[str]) -> list[str]:
        plugin_data_roots = [str(p) for p in self._collect_plugin_data_roots()]

        resolved: list[str] = []
        for candidate in candidates:
            candidate = candidate.replace("\\", "/").strip()
            if not candidate:
                continue
            if os.path.isabs(candidate):
                resolved.append(candidate)
                continue
            relative_path = candidate if candidate.startswith("files/") else f"files/{candidate}"
            for root in plugin_data_roots:
                resolved.append(str((Path(root) / relative_path).resolve()))
        return resolved

    def _remember_session_route(self, parsed: GitHubParsedEvent) -> None:
        route = _parse_session_route(parsed.session_id, parsed.installation_id)
        if not route:
            return
        existing = self._session_routes.get(parsed.session_id)
        if existing and existing.installation_id and not route.installation_id:
            route.installation_id = existing.installation_id
        self._session_routes[parsed.session_id] = route
        if len(self._session_routes) > 2000:
            self._session_routes.pop(next(iter(self._session_routes)))

    async def _get_effective_mention_targets(self) -> set[str]:
        targets = set(self.mention_target_logins)

        if self._cached_app_slug:
            targets.add(self._cached_app_slug)
            return {x.strip().lower() for x in targets if x.strip()}

        app_slug = await self._fetch_app_slug()
        if app_slug:
            self._cached_app_slug = app_slug
            targets.add(app_slug)
        return {x.strip().lower() for x in targets if x.strip()}

    async def _fetch_app_slug(self) -> str:
        app_jwt = self._build_app_jwt()
        if not app_jwt:
            return ""
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {app_jwt}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        status, data = await self._request_json(
            "GET",
            f"{self.github_api_base_url}/app",
            headers=headers,
            body=None,
        )
        if status != 200 or not isinstance(data, Mapping):
            return ""
        slug = data.get("slug")
        if isinstance(slug, str) and slug.strip():
            return slug.strip().lower()
        return ""

    async def _send_text_to_github(
        self,
        session_id: str,
        text: str,
    ) -> tuple[bool, str]:
        self._refresh_runtime_config()
        route = self._session_routes.get(session_id) or _parse_session_route(session_id)
        if not route:
            return False, "unsupported session id"
        if route.thread_type not in SENDABLE_THREAD_TYPES or route.thread_number is None:
            return False, f"thread type not sendable: {route.thread_type}"
        if not self.github_app_id:
            return False, "github_app_id is empty"
        if not self.private_key_text:
            logger.warning(f"[GitHubApp] private key debug: {self._private_key_debug}")
            return False, "private key is empty or invalid"

        installation_id = route.installation_id
        if installation_id is None:
            installation_id = await self._resolve_installation_id(route.repo)
            if installation_id is None:
                return False, "installation id not found"
            route.installation_id = installation_id
            self._session_routes[session_id] = route

        access_token = await self._get_installation_access_token(installation_id)
        if not access_token:
            return False, "failed to get installation access token"

        ok, comment_error = await self._post_issue_comment(
            route.repo,
            route.thread_number,
            access_token,
            text,
        )
        if not ok:
            return (
                False,
                f"github comment api failed: {comment_error} "
                f"(repo={route.repo}, number={route.thread_number}, installation={installation_id})",
            )
        return True, "ok"

    async def _resolve_installation_id(self, repo: str) -> int | None:
        app_jwt = self._build_app_jwt()
        if not app_jwt:
            return None
        repo_path = parse.quote(repo, safe="/")
        url = f"{self.github_api_base_url}/repos/{repo_path}/installation"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {app_jwt}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        status, data = await self._request_json("GET", url, headers=headers, body=None)
        if status != 200 or not isinstance(data, Mapping):
            detail = _stringify_github_error(data)
            logger.warning(
                f"[GitHubApp] resolve installation failed: repo={repo}, status={status}, detail={detail}"
            )
            return None
        installation_id = data.get("id")
        return int(installation_id) if isinstance(installation_id, int) else None

    async def _get_installation_access_token(self, installation_id: int) -> str:
        now = time.time()
        cached = self._installation_token_cache.get(installation_id)
        if cached and cached.expires_at - 60 > now:
            return cached.token

        app_jwt = self._build_app_jwt()
        if not app_jwt:
            return ""
        url = (
            f"{self.github_api_base_url}/app/installations/"
            f"{installation_id}/access_tokens"
        )
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {app_jwt}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        status, data = await self._request_json("POST", url, headers=headers, body={})
        if status != 201 or not isinstance(data, Mapping):
            detail = _stringify_github_error(data)
            logger.warning(
                f"[GitHubApp] get installation token failed: installation={installation_id}, status={status}, detail={detail}"
            )
            return ""

        token = data.get("token")
        if not isinstance(token, str) or not token:
            return ""
        expires_at = self._parse_github_datetime(data.get("expires_at"))
        if expires_at <= now:
            expires_at = now + 3000
        self._installation_token_cache[installation_id] = InstallationTokenCacheEntry(
            token=token,
            expires_at=expires_at,
        )
        return token

    async def _post_issue_comment(
        self,
        repo: str,
        number: int,
        access_token: str,
        body_text: str,
    ) -> tuple[bool, str]:
        repo_path = parse.quote(repo, safe="/")
        url = f"{self.github_api_base_url}/repos/{repo_path}/issues/{number}/comments"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {access_token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        status, data = await self._request_json(
            "POST",
            url,
            headers=headers,
            body={"body": body_text},
        )
        if status == 201:
            return True, "ok"
        detail = _stringify_github_error(data)
        return False, f"status={status}, detail={detail}"

    def _build_app_jwt(self) -> str:
        if not self.github_app_id or not self.private_key_text:
            return ""
        try:
            header = {"alg": "RS256", "typ": "JWT"}
            now = int(time.time())
            payload = {
                "iat": now - 60,
                "exp": now + 540,
                "iss": str(self.github_app_id),
            }
            encoded_header = _base64url(
                json.dumps(header, separators=(",", ":")).encode("utf-8")
            )
            encoded_payload = _base64url(
                json.dumps(payload, separators=(",", ":")).encode("utf-8")
            )
            signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
            private_key = serialization.load_pem_private_key(
                self.private_key_text.encode("utf-8"),
                password=None,
            )
            signature = private_key.sign(
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return f"{encoded_header}.{encoded_payload}.{_base64url(signature)}"
        except Exception as exc:
            logger.warning(f"[GitHubApp] build app jwt failed: {exc}")
            return ""

    async def _request_json(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: Mapping[str, Any] | None,
    ) -> tuple[int, Any]:
        return await asyncio.to_thread(
            self._request_json_sync,
            method,
            url,
            dict(headers),
            dict(body) if isinstance(body, Mapping) else None,
        )

    def _request_json_sync(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: dict[str, Any] | None,
    ) -> tuple[int, Any]:
        payload_bytes = (
            json.dumps(body, ensure_ascii=False).encode("utf-8")
            if body is not None
            else None
        )
        req = request.Request(
            url=url,
            data=payload_bytes,
            method=method.upper(),
            headers=headers,
        )
        if payload_bytes is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with request.urlopen(req, timeout=self._http_timeout_seconds) as resp:
                response_bytes = resp.read()
                status = int(getattr(resp, "status", 200))
        except error.HTTPError as exc:
            status = int(exc.code)
            response_bytes = exc.read()
        except Exception as exc:
            logger.warning(f"[GitHubApp] request failed: {method} {url} - {exc}")
            return -1, None

        if not response_bytes:
            return status, None
        try:
            return status, json.loads(response_bytes.decode("utf-8"))
        except Exception:
            return status, response_bytes.decode("utf-8", errors="replace")

    def _parse_github_datetime(self, value: Any) -> float:
        if not isinstance(value, str) or not value:
            return 0.0
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0

    def _build_message_event(
        self,
        parsed: GitHubParsedEvent,
        payload: Mapping,
        delivery_id: str,
    ) -> GitHubAppMessageEvent:
        abm = AstrBotMessage()
        abm.type = MessageType.GROUP_MESSAGE
        abm.self_id = self.meta().id
        abm.session_id = parsed.session_id
        abm.message_id = delivery_id or uuid.uuid4().hex
        abm.group_id = parsed.repository
        abm.sender = MessageMember(
            user_id=parsed.sender_id,
            nickname=parsed.sender_login,
        )
        abm.message = [Plain(text=parsed.summary)]
        abm.message_str = parsed.summary
        abm.raw_message = dict(payload)
        abm.timestamp = parsed.timestamp

        event = GitHubAppMessageEvent(
            message_str=abm.message_str,
            message_obj=abm,
            platform_meta=self.meta(),
            session_id=parsed.session_id,
            adapter=self,
        )
        event.set_extra("github_event", parsed.event_name)
        event.set_extra("github_action", parsed.action)
        event.set_extra("github_repository", parsed.repository)
        event.set_extra("github_session_id", parsed.session_id)
        if parsed.installation_id is not None:
            event.set_extra("github_installation_id", parsed.installation_id)
        return event
