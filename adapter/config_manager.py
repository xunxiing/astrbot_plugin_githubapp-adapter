from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from astrbot.api import logger
from astrbot.api.star import StarTools
from astrbot.core.utils.astrbot_path import (
    get_astrbot_config_path,
    get_astrbot_data_path,
)


def _ensure_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    if isinstance(value, str) and value.strip():
        return [x.strip() for x in value.split(",") if x.strip()]
    return []


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


def _get_runtime_plugin_config_snapshot() -> dict[str, Any]:
    try:
        from ..main import get_runtime_plugin_config

        config = get_runtime_plugin_config()
        if isinstance(config, dict):
            return config
    except Exception:
        pass
    return {}


@dataclass(slots=True)
class ResolvedAdapterConfig:
    github_app_id: str
    github_webhook_secret: str
    github_api_base_url: str
    enable_signature_validation: bool
    github_events: set[str]
    wake_event_types: set[str]
    wake_on_mentions: bool
    mention_target_logins: set[str]
    ignore_bot_sender_events: bool
    delivery_cache_ttl_seconds: int
    delivery_cache_max_entries: int
    private_key_text: str
    private_key_paths: list[str]
    existing_private_key_paths: list[str]
    configured_private_key_files: list[str]
    platform_private_key_files: list[str]
    auto_discovered_private_key_paths: list[str]
    private_key_debug: dict[str, Any]


class PluginConfigStore:
    def __init__(
        self,
        plugin_root_dir: str,
        legacy_root_dirs: list[str] | None = None,
    ) -> None:
        root_dirs = [plugin_root_dir]
        for legacy in legacy_root_dirs or []:
            legacy_name = str(legacy).strip()
            if legacy_name and legacy_name not in root_dirs:
                root_dirs.append(legacy_name)
        config_names = [f"{name}_config.json" for name in root_dirs]
        self._paths = self._build_candidate_paths(config_names)
        self._cached_data: dict[str, Any] = {}
        self._cached_signature: tuple[str, int, int] | None = None
        self.last_selected_path = ""
        self.last_existing_paths: list[str] = []
        self.last_error = ""
        self.last_candidate_paths: list[str] = [str(p) for p in self._paths]

    @staticmethod
    def _build_candidate_paths(config_names: list[str]) -> list[Path]:
        roots: list[Path] = []
        roots.append(Path(get_astrbot_config_path()))

        if astrbot_root := os.environ.get("ASTRBOT_ROOT"):
            roots.append(Path(astrbot_root) / "data" / "config")

        file_path = Path(__file__).resolve()
        for ancestor in file_path.parents:
            if ancestor.name == "data":
                roots.append(ancestor / "config")
            roots.append(ancestor / "data" / "config")

        candidates: list[Path] = []
        for root in roots:
            for config_name in config_names:
                candidates.append((root / config_name).resolve(strict=False))
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


class ConfigManager:
    def __init__(
        self,
        plugin_config_store: PluginConfigStore,
        plugin_root_dir: str,
        legacy_root_dirs: list[str] | None = None,
    ) -> None:
        self._plugin_config_store = plugin_config_store
        self._plugin_root_dir = str(plugin_root_dir).strip()
        self._legacy_root_dirs = [
            str(root_dir).strip()
            for root_dir in (legacy_root_dirs or [])
            if str(root_dir).strip()
        ]

    def _build_plugin_data_roots(self) -> list[Path]:
        base_dir = Path(get_astrbot_data_path()) / "plugin_data"
        root_dirs = [self._plugin_root_dir, *self._legacy_root_dirs]
        return list(
            dict.fromkeys(
                (base_dir / root_dir).resolve(strict=False)
                for root_dir in root_dirs
                if root_dir
            )
        )

    def get_plugin_data_dir(self) -> Path:
        data_dir = StarTools.get_data_dir(plugin_name=self._plugin_root_dir)
        if isinstance(data_dir, Path):
            return data_dir.resolve(strict=False)
        return Path(str(data_dir)).resolve(strict=False)

    def _collect_plugin_data_roots(self) -> list[Path]:
        current_root = self.get_plugin_data_dir()
        existing_legacy_roots = [
            root_dir
            for root_dir in self._build_plugin_data_roots()
            if root_dir != current_root and root_dir.exists() and root_dir.is_dir()
        ]
        return [current_root, *existing_legacy_roots]

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
            relative_path = (
                candidate if candidate.startswith("files/") else f"files/{candidate}"
            )
            for root in plugin_data_roots:
                resolved.append(str((Path(root) / relative_path).resolve()))
        return resolved

    def resolve(
        self,
        *,
        platform_config: Mapping[str, Any],
        cached_app_slug: str,
        supported_events: set[str],
    ) -> ResolvedAdapterConfig:
        file_plugin_cfg = self._plugin_config_store.get()
        runtime_plugin_cfg = _get_runtime_plugin_config_snapshot()
        plugin_cfg = dict(file_plugin_cfg)
        if runtime_plugin_cfg:
            plugin_cfg.update(runtime_plugin_cfg)

        github_app_id = str(platform_config.get("github_app_id", "")).strip()
        github_webhook_secret = str(
            platform_config.get("github_webhook_secret", "")
        ).strip()
        github_api_base_url = str(
            platform_config.get("github_api_base_url", "https://api.github.com")
        ).rstrip("/")

        signature_validation = platform_config.get("github_signature_validation")
        if signature_validation is None:
            signature_validation = plugin_cfg.get("enable_signature_validation", True)
        enable_signature_validation = bool(signature_validation)

        events = _ensure_list(platform_config.get("github_events"))
        if not events:
            events = _ensure_list(plugin_cfg.get("default_github_events"))
        if events:
            github_events = {e for e in events if e in supported_events}
        else:
            github_events = set(supported_events)

        wake_events = _ensure_list(platform_config.get("wake_event_types"))
        if not wake_events:
            wake_events = _ensure_list(plugin_cfg.get("default_wake_event_types"))
        wake_event_types = {e for e in wake_events if e in supported_events}

        wake_on_mentions = platform_config.get("wake_on_mentions")
        if wake_on_mentions is None:
            wake_on_mentions = plugin_cfg.get("default_wake_on_mentions", True)
        wake_on_mentions_bool = bool(wake_on_mentions)

        mention_target_logins = _ensure_list(
            platform_config.get("mention_target_logins")
        )
        if not mention_target_logins:
            mention_target_logins = _ensure_list(
                plugin_cfg.get("default_mention_target_logins")
            )
        mention_targets = {login.lower() for login in mention_target_logins if login}

        ignore_bot_sender_events = platform_config.get("ignore_bot_sender_events")
        if ignore_bot_sender_events is None:
            ignore_bot_sender_events = plugin_cfg.get(
                "default_ignore_bot_sender_events",
                True,
            )
        ignore_bot_sender_events_bool = bool(ignore_bot_sender_events)

        ttl_seconds_raw = platform_config.get(
            "github_delivery_cache_ttl_seconds",
            plugin_cfg.get("delivery_cache_ttl_seconds", 900),
        )
        max_entries_raw = platform_config.get(
            "github_delivery_cache_max_entries",
            plugin_cfg.get("delivery_cache_max_entries", 10000),
        )
        try:
            ttl_seconds = int(ttl_seconds_raw) if str(ttl_seconds_raw).strip() else 900
        except Exception:
            ttl_seconds = 900
        try:
            max_entries = (
                int(max_entries_raw) if str(max_entries_raw).strip() else 10000
            )
        except Exception:
            max_entries = 10000

        file_private_key_files = _ensure_list(file_plugin_cfg.get("private_key_files"))
        runtime_private_key_files = _ensure_list(
            runtime_plugin_cfg.get("private_key_files")
        )
        configured_private_key_files = (
            runtime_private_key_files or file_private_key_files
        )
        platform_private_key_files = _ensure_list(
            platform_config.get("private_key_files")
        )
        effective_private_key_files = (
            configured_private_key_files or platform_private_key_files
        )
        auto_discovered_private_key_paths: list[str] = []
        if not effective_private_key_files:
            auto_discovered_private_key_paths = self._auto_discover_private_key_paths()
            effective_private_key_files = auto_discovered_private_key_paths

        private_key_paths = self._resolve_private_key_paths(effective_private_key_files)
        (
            private_key_text,
            hit_private_key_path,
            private_key_diagnostics,
        ) = _read_first_valid_private_key_text(private_key_paths)
        existing_paths = [p for p in private_key_paths if Path(p).is_file()]
        private_key_debug = {
            "configured": configured_private_key_files,
            "file_config_private_key_files": file_private_key_files,
            "runtime_config_private_key_files": runtime_private_key_files,
            "platform_config_private_key_files": platform_private_key_files,
            "effective_private_key_files": effective_private_key_files,
            "auto_discovered_private_key_paths": auto_discovered_private_key_paths,
            "mention_target_logins": sorted(mention_targets),
            "ignore_bot_sender_events": ignore_bot_sender_events_bool,
            "cached_app_slug": cached_app_slug,
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

        return ResolvedAdapterConfig(
            github_app_id=github_app_id,
            github_webhook_secret=github_webhook_secret,
            github_api_base_url=github_api_base_url,
            enable_signature_validation=enable_signature_validation,
            github_events=github_events,
            wake_event_types=wake_event_types,
            wake_on_mentions=wake_on_mentions_bool,
            mention_target_logins=mention_targets,
            ignore_bot_sender_events=ignore_bot_sender_events_bool,
            delivery_cache_ttl_seconds=ttl_seconds,
            delivery_cache_max_entries=max_entries,
            private_key_text=private_key_text,
            private_key_paths=private_key_paths,
            existing_private_key_paths=existing_paths,
            configured_private_key_files=configured_private_key_files,
            platform_private_key_files=platform_private_key_files,
            auto_discovered_private_key_paths=auto_discovered_private_key_paths,
            private_key_debug=private_key_debug,
        )
