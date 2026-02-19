from __future__ import annotations

import json
import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.provider import ProviderRequest
from astrbot.api.star import Context, Star, register
from astrbot.core.config.default import CONFIG_METADATA_2, WEBHOOK_SUPPORTED_PLATFORMS
from astrbot.core.skills.skill_manager import SkillManager
from astrbot.core.utils.astrbot_path import get_astrbot_skills_path

GITHUB_ADAPTER_TYPE = "github_app"
GITHUB_SKILL_TOOL_NAME = "github_app_issue_token"
GITHUB_CREATE_LICENSE_PR_TOOL_NAME = "github_app_create_license_pr"
DEFAULT_GITHUB_SKILL_NAME = "github_app_ops"
SUPPORTED_GITHUB_EVENTS = [
    "issues",
    "issue_comment",
    "pull_request",
    "pull_request_review",
    "pull_request_review_comment",
    "push",
    "release",
    "discussion",
    "discussion_comment",
    "watch",
    "fork",
]
RUNTIME_PLUGIN_CONFIG: dict[str, Any] = {}
IMAGE_ATTACHMENT_PATH_HINT_RE = re.compile(
    r"^\[Image Attachment:\s*path\s+.+\]$",
    re.IGNORECASE,
)
SKILL_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
PERMISSION_LEVEL_RANK = {"read": 1, "write": 2}
DEFAULT_TOKEN_DEFAULT_PERMISSIONS: dict[str, str] = {
    "contents": "read",
    "pull_requests": "write",
    "issues": "write",
}
DEFAULT_TOKEN_MAX_PERMISSIONS: dict[str, str] = {
    "contents": "write",
    "pull_requests": "write",
    "issues": "write",
}
TOOL_GUARD_DEFAULT_PROTECTED_BRANCHES = ["main", "master"]
DEFAULT_PRIVILEGED_SHELL_ALLOWLIST_PATTERNS = [
    r"^\s*export\s+GH_TOKEN=.*$",
    r"^\s*unset\s+GH_TOKEN\s*$",
    r"^\s*Remove-Item\s+Env:GH_TOKEN\b.*$",
    r"^\s*curl\b[\s\S]*api\.github\.com/repos/[^/\s]+/[^/\s]+/(branches/[^/\s]+|git/refs|contents/[^\"'\s]+|pulls|issues)\b[\s\S]*$",
    r"^\s*gh\b[\s\S]*$",
    r"^\s*git\b[\s\S]*$",
]
DEFAULT_PRIVILEGED_PYTHON_ALLOWLIST_PATTERNS: list[str] = []
GITHUB_TOKEN_LITERAL_RE = re.compile(r"\bghs_[A-Za-z0-9_]{20,}\b")
TOKEN_ALIAS_PREFIX = "gha_alias_"
BRANCH_FIELD_RE = re.compile(
    r"""["\\]?branch["\\]?\s*:\s*["\\]?([A-Za-z0-9._/\-]+)["\\]?""",
    re.IGNORECASE,
)


def set_runtime_plugin_config(config: dict | None) -> None:
    global RUNTIME_PLUGIN_CONFIG
    if isinstance(config, dict):
        RUNTIME_PLUGIN_CONFIG = dict(config)
    else:
        RUNTIME_PLUGIN_CONFIG = {}


def get_runtime_plugin_config() -> dict[str, Any]:
    return dict(RUNTIME_PLUGIN_CONFIG)


def _ensure_http_url_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    urls: list[str] = []
    for item in value:
        url = str(item).strip()
        if url.startswith(("http://", "https://")):
            urls.append(url)
    return list(dict.fromkeys(urls))


def _ensure_path_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    paths: list[str] = []
    for item in value:
        path = str(item).strip()
        if path:
            paths.append(path)
    return list(dict.fromkeys(paths))


async def _register_local_image_urls(local_paths: list[str]) -> list[str]:
    image_paths: list[str] = []
    for path in local_paths:
        try:
            local_path = Path(str(path).strip()).resolve()
            if local_path.is_file():
                image_paths.append(str(local_path))
        except Exception as exc:
            logger.warning(f"[GitHubApp] failed to resolve local image path: path={path}, err={exc}")
    return list(dict.fromkeys(image_paths))


def _parse_requested_permissions(value: Any) -> dict[str, str]:
    if value is None:
        return {}

    parsed_map: Mapping[str, Any] | None = None
    if isinstance(value, Mapping):
        parsed_map = value
    else:
        raw = str(value).strip()
        if not raw:
            return {}
        if raw.startswith("{") and raw.endswith("}"):
            try:
                obj = json.loads(raw)
            except Exception:
                return {}
            if not isinstance(obj, Mapping):
                return {}
            parsed_map = obj
        else:
            parsed: dict[str, str] = {}
            for item in re.split(r"[,\s]+", raw):
                token = item.strip()
                if not token or "=" not in token:
                    continue
                key, level = token.split("=", 1)
                perm_name = key.strip()
                perm_level = level.strip().lower()
                if perm_name and perm_level in {"read", "write"}:
                    parsed[perm_name] = perm_level
            return parsed

    normalized: dict[str, str] = {}
    for key, raw_level in parsed_map.items():
        perm_name = str(key).strip()
        perm_level = str(raw_level).strip().lower()
        if perm_name and perm_level in {"read", "write"}:
            normalized[perm_name] = perm_level
    return normalized


def _normalize_repo_full_name(value: Any) -> str:
    raw = str(value or "").strip().strip("/")
    if "/" not in raw:
        return ""
    owner, repo = raw.split("/", 1)
    owner = owner.strip().lower()
    repo = repo.strip().lower()
    if not owner or not repo:
        return ""
    return f"{owner}/{repo}"


def _ensure_str_list(value: Any, fallback: list[str] | None = None) -> list[str]:
    if not isinstance(value, list):
        value = fallback or []
    items: list[str] = []
    for item in value:
        text = str(item).strip()
        if text:
            items.append(text)
    return list(dict.fromkeys(items))


def _ensure_lower_str_list(value: Any, fallback: list[str] | None = None) -> list[str]:
    if not isinstance(value, list):
        value = fallback or []
    items: list[str] = []
    for item in value:
        text = str(item).strip().lower()
        if text:
            items.append(text)
    return list(dict.fromkeys(items))


def _extract_branch_from_command_payload(command: str) -> str:
    match = BRANCH_FIELD_RE.search(command)
    if not match:
        return ""
    return str(match.group(1)).strip().lower()


def _contains_github_token_literal(text: str) -> bool:
    if not text:
        return False
    return bool(GITHUB_TOKEN_LITERAL_RE.search(text))


def _parse_expire_at_timestamp(value: Any) -> float:
    now = time.time()
    raw = str(value or "").strip()
    if not raw:
        return now + 3000
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        return now + 3000
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    ts = parsed.timestamp()
    if ts <= now:
        return now + 3000
    return ts


def _split_shell_segments(command: str) -> list[str]:
    if not command:
        return []
    segments = re.split(r"(?:&&|\|\||[;|])", command)
    return [str(seg).strip() for seg in segments if str(seg).strip()]


def _matches_any_regex(text: str, patterns: list[str]) -> bool:
    if not text:
        return False
    for pattern in patterns:
        try:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                return True
        except re.error as exc:
            logger.warning(f"[GitHubApp] invalid guard regex pattern: {pattern}, err={exc}")
    return False


def _find_shell_allowlist_violations(command: str, patterns: list[str]) -> list[str]:
    violations: list[str] = []
    for segment in _split_shell_segments(command):
        if _matches_any_regex(segment, patterns):
            continue
        preview = segment.replace("\n", " ").replace("\r", " ").strip()
        if len(preview) > 120:
            preview = f"{preview[:117]}..."
        violations.append(preview)
    return violations


def _detect_shell_guard_reasons(
    command: str,
    protected_branches: list[str],
) -> list[str]:
    if not command:
        return []
    reasons: list[str] = []
    command_text = str(command)
    command_lower = command_text.lower()

    for branch in protected_branches:
        if re.search(
            rf"\bgit\s+push\b[^\n\r;&|]*\b{re.escape(branch)}\b",
            command_text,
            re.IGNORECASE,
        ):
            reasons.append(f"git_push_protected_branch:{branch}")
        if re.search(rf"refs/heads/{re.escape(branch)}\b", command_lower):
            reasons.append(f"write_protected_ref:{branch}")

    touches_contents_api = "/contents/" in command_lower and bool(
        re.search(r"\b-x\s+(put|patch|post)\b", command_text, re.IGNORECASE)
    )
    if touches_contents_api:
        payload_branch = _extract_branch_from_command_payload(command_text)
        if not payload_branch:
            reasons.append("contents_write_without_explicit_branch")
        elif payload_branch in protected_branches:
            reasons.append(f"contents_write_protected_branch:{payload_branch}")

    return list(dict.fromkeys(reasons))


def _cap_permission_level(requested: str, max_level: str) -> str:
    requested_rank = PERMISSION_LEVEL_RANK.get(str(requested).strip().lower(), 0)
    max_rank = PERMISSION_LEVEL_RANK.get(str(max_level).strip().lower(), 0)
    if requested_rank <= 0 or max_rank <= 0:
        return ""
    return "write" if min(requested_rank, max_rank) >= 2 else "read"


def _build_effective_token_permissions(
    repo: str,
    requested: Mapping[str, str] | None,
    config: Mapping[str, Any] | None,
) -> tuple[dict[str, str], dict[str, Any]]:
    cfg = dict(config or {})
    policy_enabled = bool(cfg.get("force_token_permission_policy", True))
    privileged_write_mode = bool(cfg.get("enable_privileged_write_mode", False))

    default_permissions = _parse_requested_permissions(cfg.get("token_default_permissions"))
    if not default_permissions:
        default_permissions = dict(DEFAULT_TOKEN_DEFAULT_PERMISSIONS)

    max_permissions = _parse_requested_permissions(cfg.get("token_max_permissions"))
    if not max_permissions:
        max_permissions = dict(DEFAULT_TOKEN_MAX_PERMISSIONS)

    requested_map = (
        {str(k): str(v) for k, v in requested.items()}
        if isinstance(requested, Mapping)
        else {}
    )
    base_permissions = dict(requested_map or default_permissions)
    normalized_repo = _normalize_repo_full_name(repo)
    notes: list[str] = []

    if not policy_enabled:
        effective = dict(base_permissions or default_permissions)
        notes.append("policy_disabled")
    else:
        effective: dict[str, str] = {}
        for perm_name, req_level in base_permissions.items():
            name = str(perm_name).strip()
            if not name:
                continue
            max_level = max_permissions.get(name)
            if not max_level:
                notes.append(f"{name}:dropped_not_in_max")
                continue
            capped_level = _cap_permission_level(str(req_level), str(max_level))
            if not capped_level:
                notes.append(f"{name}:invalid_level")
                continue
            req_level_text = str(req_level).strip().lower()
            if capped_level != req_level_text:
                notes.append(f"{name}:{req_level_text}->{capped_level}")
            effective[name] = capped_level

        if not effective:
            effective = dict(default_permissions)
            notes.append("fallback_default_permissions")

    if effective.get("contents") == "write" and not privileged_write_mode:
        effective["contents"] = "read"
        notes.append("contents:write->read(privileged_write_mode_disabled)")

    if not effective:
        effective = dict(DEFAULT_TOKEN_DEFAULT_PERMISSIONS)
        notes.append("fallback_builtin_defaults")

    policy_snapshot = {
        "policy_enabled": policy_enabled,
        "privileged_write_mode_enabled": privileged_write_mode,
        "repo": normalized_repo or str(repo or "").strip(),
        "notes": notes,
    }
    return effective, policy_snapshot


def _sanitize_skill_name(raw_name: Any) -> str:
    name = str(raw_name or "").strip()
    if not name:
        return DEFAULT_GITHUB_SKILL_NAME
    if SKILL_NAME_RE.fullmatch(name):
        return name
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip(".-")
    return cleaned or DEFAULT_GITHUB_SKILL_NAME


def _extract_repo_from_github_session(session_id: str) -> str:
    if not isinstance(session_id, str):
        return ""
    parts = session_id.split(":", 3)
    if len(parts) != 4:
        return ""
    if parts[0] != "github":
        return ""
    repo = parts[1].strip()
    return repo


def _extract_issue_number_from_github_session(session_id: str) -> int:
    if not isinstance(session_id, str):
        return 0
    parts = session_id.split(":", 3)
    if len(parts) != 4:
        return 0
    if parts[0] != "github" or parts[2] != "issue":
        return 0
    raw_number = str(parts[3]).strip()
    if not raw_number.isdigit():
        return 0
    return int(raw_number)


def _build_github_skill_content(skill_name: str) -> str:
    return f"""---
description: GitHub App operations skill. Use controlled PR tool first; token tool is legacy fallback.
---

# {skill_name}

## Priority

- For branch + commit + PR tasks, call `{GITHUB_CREATE_LICENSE_PR_TOOL_NAME}` first.
- Use `{GITHUB_SKILL_TOOL_NAME}` only when explicit token workflow is required.
- Never expose token in chat/log/repo files.

## Typical flow

1. Resolve repo as `owner/repo`.
2. If task is add-license-and-open-pr, use direct controlled tool.
3. If custom operation is required, use token tool and keep token only in env var.
4. Clear token env var after task.
"""

def _ensure_github_skill(config: Mapping[str, Any] | None) -> str:
    cfg = dict(config or {})
    if not bool(cfg.get("auto_create_github_skill", True)):
        return _sanitize_skill_name(
            cfg.get("github_skill_name", DEFAULT_GITHUB_SKILL_NAME)
        )

    skill_name = _sanitize_skill_name(
        cfg.get("github_skill_name", DEFAULT_GITHUB_SKILL_NAME)
    )
    overwrite = bool(cfg.get("overwrite_github_skill", True))
    skill_content = _build_github_skill_content(skill_name)

    try:
        skill_root = Path(get_astrbot_skills_path())
        skill_dir = skill_root / skill_name
        skill_path = skill_dir / "SKILL.md"
        skill_dir.mkdir(parents=True, exist_ok=True)

        should_write = True
        if skill_path.exists() and not overwrite:
            should_write = False
        if should_write:
            if (
                not skill_path.exists()
                or skill_path.read_text(encoding="utf-8") != skill_content
            ):
                skill_path.write_text(skill_content, encoding="utf-8")

        SkillManager().set_skill_active(skill_name, True)
        logger.info(
            f"[GitHubApp] ensured skill '{skill_name}' at {skill_path} and activated it"
        )
    except Exception as exc:
        logger.warning(f"[GitHubApp] ensure skill failed ({skill_name}): {exc}")
    return skill_name


def _inject_platform_metadata() -> None:
    if GITHUB_ADAPTER_TYPE not in WEBHOOK_SUPPORTED_PLATFORMS:
        WEBHOOK_SUPPORTED_PLATFORMS.append(GITHUB_ADAPTER_TYPE)

    platform_meta = CONFIG_METADATA_2["platform_group"]["metadata"]["platform"]
    items = platform_meta["items"]

    items["github_app_id"] = {
        "description": "GitHub App ID",
        "type": "string",
        "hint": "可在 GitHub App 设置页面中找到。",
    }
    items["github_webhook_secret"] = {
        "description": "GitHub Webhook 密钥",
        "type": "string",
        "hint": "必须与 GitHub App 中配置的 Webhook Secret 完全一致。",
    }
    items["github_api_base_url"] = {
        "description": "GitHub API 基础地址",
        "type": "string",
        "hint": "默认值为 https://api.github.com。",
    }
    items["github_events"] = {
        "description": "GitHub 订阅事件",
        "type": "list",
        "hint": "留空表示订阅全部已支持事件。",
        "options": SUPPORTED_GITHUB_EVENTS,
    }
    items["wake_event_types"] = {
        "description": "唤醒事件类型",
        "type": "list",
        "hint": "仅这些事件类型会按事件触发 LLM 唤醒。",
        "options": SUPPORTED_GITHUB_EVENTS,
    }
    items["wake_on_mentions"] = {
        "description": "@提及时唤醒",
        "type": "bool",
        "hint": "当 GitHub 评论正文中提及机器人时触发唤醒。",
    }
    items["mention_target_logins"] = {
        "description": "提及目标登录名",
        "type": "list",
        "hint": "仅当 @login 命中该列表时，按提及唤醒。",
    }
    items["ignore_bot_sender_events"] = {
        "description": "忽略 Bot 发送者事件",
        "type": "bool",
        "hint": "忽略 sender 为 GitHub Bot 用户的事件。",
    }
    items["github_signature_validation"] = {
        "description": "启用签名校验",
        "type": "bool",
        "hint": "对每次 webhook 请求校验 X-Hub-Signature-256。",
    }
    items["github_delivery_cache_ttl_seconds"] = {
        "description": "Delivery 去重 TTL（秒）",
        "type": "int",
        "hint": "防重放窗口时长（秒）。",
    }
    items["github_delivery_cache_max_entries"] = {
        "description": "Delivery 去重最大条目数",
        "type": "int",
        "hint": "内存去重缓存上限。",
    }

    logger.info("[GitHubApp] platform metadata injected")


@register(
    "astrbot_plugin_githubapp-adopter",
    "OpenCode",
    "为 AstrBot 提供 GitHub App Webhook 适配与临时令牌能力。",
    "v0.2.0",
    "https://github.com/example/astrbot_plugin_githubapp-adopter",
)
class GitHubAppAdopterPlugin(Star):
    def __init__(self, context: Context, config: dict):
        super().__init__(context)
        self.config = config
        self._token_alias_store: dict[str, dict[str, Any]] = {}
        skill_name = _ensure_github_skill(self.config)
        runtime_cfg = dict(self.config)
        runtime_cfg["effective_github_skill_name"] = skill_name
        set_runtime_plugin_config(runtime_cfg)
        _inject_platform_metadata()
        from .adapter.github_app_adapter import GitHubAppAdapter  # noqa: F401

    def _cleanup_token_alias_store(self) -> None:
        now = time.time()
        stale_aliases = [
            alias
            for alias, payload in self._token_alias_store.items()
            if float(payload.get("expire_at_ts", 0.0)) <= now
            or not str(payload.get("token", ""))
        ]
        for alias in stale_aliases:
            self._token_alias_store.pop(alias, None)

    def _store_token_alias(self, token: str, expires_at: str) -> str:
        self._cleanup_token_alias_store()
        expire_at_ts = _parse_expire_at_timestamp(expires_at)
        for _ in range(6):
            alias = f"{TOKEN_ALIAS_PREFIX}{secrets.token_hex(16)}"
            if alias not in self._token_alias_store:
                self._token_alias_store[alias] = {
                    "token": token,
                    "expire_at_ts": expire_at_ts,
                }
                return alias
        alias = f"{TOKEN_ALIAS_PREFIX}{int(time.time() * 1000)}"
        self._token_alias_store[alias] = {
            "token": token,
            "expire_at_ts": expire_at_ts,
        }
        return alias

    def _replace_alias_tokens_in_text(self, text: str) -> tuple[str, int]:
        source = str(text or "")
        if not source or TOKEN_ALIAS_PREFIX not in source:
            return source, 0
        self._cleanup_token_alias_store()
        replaced_count = 0
        resolved = source
        for alias, payload in self._token_alias_store.items():
            real_token = str(payload.get("token", ""))
            if not real_token:
                continue
            if alias in resolved:
                resolved = resolved.replace(alias, real_token)
                replaced_count += 1
        return resolved, replaced_count

    def _replace_alias_tokens_in_env(
        self, env_map: Mapping[str, Any]
    ) -> tuple[dict[str, Any], int]:
        resolved_env: dict[str, Any] = {}
        replaced_count = 0
        for raw_key, raw_value in env_map.items():
            key = str(raw_key)
            if isinstance(raw_value, str):
                new_value, replaced = self._replace_alias_tokens_in_text(raw_value)
                resolved_env[key] = new_value
                replaced_count += replaced
            else:
                resolved_env[key] = raw_value
        return resolved_env, replaced_count

    def _resolve_github_adapter(
        self,
        event: AstrMessageEvent,
        platform_id: str = "",
    ) -> Any | None:
        candidate: Any | None = None
        target_platform_id = str(platform_id or "").strip()
        if target_platform_id:
            candidate = self.context.get_platform_inst(target_platform_id)
        if candidate is None and event.get_platform_name() == GITHUB_ADAPTER_TYPE:
            candidate = self.context.get_platform_inst(event.get_platform_id())
        if candidate is None:
            candidate = self.context.get_platform(GITHUB_ADAPTER_TYPE)
        if candidate is None:
            return None
        try:
            if candidate.meta().name != GITHUB_ADAPTER_TYPE:
                return None
        except Exception:
            return None
        return candidate

    @filter.on_astrbot_loaded()
    async def on_astrbot_loaded(self):
        skill_name = _ensure_github_skill(self.config)
        runtime_cfg = dict(self.config)
        runtime_cfg["effective_github_skill_name"] = skill_name
        set_runtime_plugin_config(runtime_cfg)
        _inject_platform_metadata()

    @filter.on_using_llm_tool(priority=-20000)
    async def guard_github_tool_usage(
        self,
        event: AstrMessageEvent,
        tool: Any,
        tool_args: dict | None,
    ) -> None:
        if event.get_platform_name() != GITHUB_ADAPTER_TYPE:
            return
        if not isinstance(tool_args, dict):
            return

        cfg = get_runtime_plugin_config()
        tool_name = str(getattr(tool, "name", "")).strip()
        if tool_name not in {"astrbot_execute_shell", "astrbot_execute_python"}:
            return

        enforce_guard = bool(cfg.get("enforce_tool_write_guard", True))
        privileged_write_mode = bool(cfg.get("enable_privileged_write_mode", False))
        privileged_require_whitelist = bool(
            cfg.get("privileged_mode_require_whitelist", True)
        )
        shell_allowlist_patterns = _ensure_str_list(
            cfg.get("privileged_mode_shell_allowlist_patterns"),
            DEFAULT_PRIVILEGED_SHELL_ALLOWLIST_PATTERNS,
        )
        python_allowlist_patterns = _ensure_str_list(
            cfg.get("privileged_mode_python_allowlist_patterns"),
            DEFAULT_PRIVILEGED_PYTHON_ALLOWLIST_PATTERNS,
        )
        protected_branches = _ensure_lower_str_list(
            cfg.get("guard_protected_branches"),
            TOOL_GUARD_DEFAULT_PROTECTED_BRANCHES,
        )
        if not protected_branches:
            protected_branches = list(TOOL_GUARD_DEFAULT_PROTECTED_BRANCHES)
        block_token_literal = bool(cfg.get("guard_block_token_literal", True))

        reasons: list[str] = []
        replaced_alias_count = 0
        if tool_name == "astrbot_execute_shell":
            command = str(tool_args.get("command", ""))
            if enforce_guard:
                if block_token_literal and _contains_github_token_literal(command):
                    reasons.append("token_literal_in_shell_command")
                reasons.extend(_detect_shell_guard_reasons(command, protected_branches))
                if privileged_write_mode and privileged_require_whitelist:
                    if not shell_allowlist_patterns:
                        reasons.append("privileged_mode_shell_allowlist_empty")
                    else:
                        violations = _find_shell_allowlist_violations(
                            command, shell_allowlist_patterns
                        )
                        if violations:
                            reasons.append("shell_command_not_in_allowlist")
                            reasons.append(f"shell_violation:{violations[0]}")
            if reasons:
                reason_text = ",".join(list(dict.fromkeys(reasons)))
                message = f"BLOCKED by github_app guard: {reason_text}"
                safe_message = message.replace('"', "'").replace("\n", " ")
                tool_args["command"] = f'echo "{safe_message}"'
            else:
                resolved_command, replaced = self._replace_alias_tokens_in_text(command)
                tool_args["command"] = resolved_command
                replaced_alias_count += replaced
        elif tool_name == "astrbot_execute_python":
            code = str(tool_args.get("code", ""))
            if enforce_guard:
                if block_token_literal and _contains_github_token_literal(code):
                    reasons.append("token_literal_in_python_code")
                if privileged_write_mode and privileged_require_whitelist:
                    if not python_allowlist_patterns:
                        reasons.append("privileged_mode_python_allowlist_empty")
                    elif not _matches_any_regex(code, python_allowlist_patterns):
                        reasons.append("python_code_not_in_allowlist")
            if reasons:
                reason_text = ",".join(list(dict.fromkeys(reasons)))
                message = f"BLOCKED by github_app guard: {reason_text}"
                tool_args["code"] = f"print({message!r})"
            else:
                resolved_code, replaced = self._replace_alias_tokens_in_text(code)
                tool_args["code"] = resolved_code
                replaced_alias_count += replaced

        raw_env = tool_args.get("env")
        if isinstance(raw_env, Mapping):
            resolved_env, replaced = self._replace_alias_tokens_in_env(raw_env)
            tool_args["env"] = resolved_env
            replaced_alias_count += replaced

        if replaced_alias_count:
            logger.info(
                f"[GitHubApp] replaced token alias in tool args: tool={tool_name}, count={replaced_alias_count}"
            )

        if reasons:
            logger.warning(
                f"[GitHubApp] blocked risky tool call: tool={tool_name}, reasons={reasons}"
            )

    @filter.llm_tool(name=GITHUB_CREATE_LICENSE_PR_TOOL_NAME)
    async def github_app_create_license_pr(
        self,
        event: AstrMessageEvent,
        repo: str = "",
        issue_number: int = 0,
        platform_id: str = "",
        branch_name: str = "",
        license_type: str = "MIT",
        pr_title: str = "",
        pr_body: str = "",
    ) -> str:
        """受控工具：在仓库创建 LICENSE 并发起 PR，不向模型暴露 token。"""
        runtime_cfg = get_runtime_plugin_config()
        if not bool(runtime_cfg.get("enable_direct_repo_write_tool", False)):
            return (
                "direct repo write tool is disabled. "
                "Please set enable_direct_repo_write_tool=true."
            )

        adapter = self._resolve_github_adapter(event, platform_id)
        if adapter is None:
            return "未找到可用的 github_app 平台适配器。"
        if not hasattr(adapter, "create_license_pr_for_skill"):
            return "当前 github_app 适配器不支持受控 PR 工具，请升级插件。"

        repo_value = str(repo or "").strip()
        if not repo_value:
            repo_value = str(event.get_extra("github_repository", "")).strip()
        if not repo_value:
            repo_value = _extract_repo_from_github_session(
                str(event.get_extra("github_session_id", "")).strip()
            )
        if not repo_value and event.get_platform_name() == GITHUB_ADAPTER_TYPE:
            repo_value = _extract_repo_from_github_session(event.get_session_id())
        if not repo_value:
            return "缺少 repo 参数，格式应为 owner/repo。"

        try:
            resolved_issue_number = int(issue_number or 0)
        except Exception:
            resolved_issue_number = 0
        if resolved_issue_number <= 0:
            resolved_issue_number = 0
        if resolved_issue_number <= 0:
            resolved_issue_number = _extract_issue_number_from_github_session(
                str(event.get_extra("github_session_id", "")).strip()
            )
        if resolved_issue_number <= 0 and event.get_platform_name() == GITHUB_ADAPTER_TYPE:
            resolved_issue_number = _extract_issue_number_from_github_session(
                event.get_session_id()
            )
        if resolved_issue_number <= 0:
            resolved_issue_number = None

        ok, payload = await adapter.create_license_pr_for_skill(
            repo=repo_value,
            issue_number=resolved_issue_number,
            branch_name=branch_name,
            license_type=license_type,
            pr_title=pr_title,
            pr_body=pr_body,
        )
        if not ok:
            detail = str(payload.get("error", "unknown error"))
            stage = str(payload.get("stage", "")).strip()
            if stage:
                return f"创建 LICENSE PR 失败（{stage}）：{detail}"
            return f"创建 LICENSE PR 失败：{detail}"

        pr_url = str(payload.get("pr_url", "")).strip()
        pr_number = int(payload.get("pr_number", 0) or 0)
        target_repo = str(payload.get("repo", repo_value)).strip()
        head_branch = str(payload.get("head_branch", "")).strip()
        base_branch = str(payload.get("base_branch", "")).strip()
        existing = bool(payload.get("existing_pr", False))

        lines = [
            "LICENSE PR 已创建成功。",
            f"repo: {target_repo}",
            f"base_branch: {base_branch}",
            f"head_branch: {head_branch}",
        ]
        if pr_number > 0:
            lines.append(f"pr_number: {pr_number}")
        if pr_url:
            lines.append(f"pr_url: {pr_url}")
        if existing:
            lines.append("note: 已存在同分支 PR，本次返回已有 PR。")
        return "\n".join(lines)

    @filter.llm_tool(name=GITHUB_SKILL_TOOL_NAME)
    async def github_app_issue_token(
        self,
        event: AstrMessageEvent,
        repo: str = "",
        session_id: str = "",
        platform_id: str = "",
        permissions: str = "",
    ) -> str:
        """签发短期 GitHub App Installation Token，用于仓库操作。

        Args:
            repo(string): 目标仓库，格式 owner/repo。若事件上下文可推断可不传。
            session_id(string): 可选，github 会话 ID，格式 github:owner/repo:type:number。
            platform_id(string): 可选，存在多个 github_app 平台时指定平台 ID。
            permissions(string): 可选，权限请求，支持 a=b,c=d 或 JSON（仅 read/write）。
        """
        runtime_cfg = get_runtime_plugin_config()
        if not bool(runtime_cfg.get("enable_issue_token_tool", True)):
            return (
                "github_app_issue_token is disabled by config "
                "(enable_issue_token_tool=false)."
            )

        adapter = self._resolve_github_adapter(event, platform_id)
        if adapter is None:
            return "未找到可用的 github_app 平台适配器。"
        if not hasattr(adapter, "issue_installation_token_for_skill"):
            return "当前 github_app 适配器不支持临时令牌签发，请升级插件。"

        repo_value = str(repo or "").strip()
        if not repo_value:
            repo_value = _extract_repo_from_github_session(str(session_id or "").strip())
        if not repo_value:
            repo_value = str(event.get_extra("github_repository", "")).strip()
        if not repo_value:
            repo_value = _extract_repo_from_github_session(
                str(event.get_extra("github_session_id", "")).strip()
            )
        if not repo_value and event.get_platform_name() == GITHUB_ADAPTER_TYPE:
            repo_value = _extract_repo_from_github_session(event.get_session_id())

        requested_permissions = _parse_requested_permissions(permissions)
        effective_permissions, permission_policy = _build_effective_token_permissions(
            repo_value,
            requested_permissions,
            runtime_cfg,
        )
        ok, payload = await adapter.issue_installation_token_for_skill(
            repo=repo_value,
            permissions=effective_permissions,
        )
        if not ok:
            detail = str(payload.get("error", "unknown error"))
            return f"临时安装令牌签发失败：{detail}"

        token = str(payload.get("token", ""))
        if not token:
            return "临时安装令牌签发失败：返回了空令牌。"

        expires_at = str(payload.get("expires_at", ""))
        token_alias = self._store_token_alias(token, expires_at)
        resolved_repo = str(payload.get("repo", repo_value))
        installation_id = str(payload.get("installation_id", ""))
        repository_selection = str(payload.get("repository_selection", ""))
        granted_permissions = payload.get("permissions", {})
        if not isinstance(granted_permissions, Mapping):
            granted_permissions = {}
        granted_permissions_text = json.dumps(
            dict(granted_permissions),
            ensure_ascii=False,
            sort_keys=True,
        )
        requested_permissions_text = json.dumps(
            dict(requested_permissions),
            ensure_ascii=False,
            sort_keys=True,
        )
        effective_permissions_text = json.dumps(
            dict(effective_permissions),
            ensure_ascii=False,
            sort_keys=True,
        )
        permission_policy_text = json.dumps(
            dict(permission_policy),
            ensure_ascii=False,
            sort_keys=True,
        )

        return "\n".join(
            [
                "GitHub App 临时安装令牌签发成功。",
                f"repo: {resolved_repo}",
                f"installation_id: {installation_id}",
                f"expires_at: {expires_at}",
                f"repository_selection: {repository_selection}",
                f"requested_permissions: {requested_permissions_text}",
                f"effective_permissions: {effective_permissions_text}",
                f"granted_permissions: {granted_permissions_text}",
                f"permission_policy: {permission_policy_text}",
                "token_is_alias: true",
                f"token: {token_alias}",
                "PowerShell 设置令牌：$env:GH_TOKEN='<token>'",
                "Bash 设置令牌：export GH_TOKEN='<token>'",
                "使用后请立即清理（PowerShell: Remove-Item Env:GH_TOKEN；Bash: unset GH_TOKEN）。",
            ]
        )

    @filter.on_llm_request(priority=-20000)
    async def fix_github_image_llm_request(
        self,
        event: AstrMessageEvent,
        req: ProviderRequest,
    ):
        if event.get_platform_name() != GITHUB_ADAPTER_TYPE:
            return

        local_paths = _ensure_path_list(event.get_extra("github_image_local_paths", []))
        failed_urls = _ensure_http_url_list(event.get_extra("github_image_failed_urls", []))
        origin_urls = _ensure_http_url_list(event.get_extra("github_image_urls", []))
        existing_urls = list(dict.fromkeys(str(u).strip() for u in (req.image_urls or [])))
        existing_urls = [u for u in existing_urls if u.startswith(("http://", "https://"))]

        if local_paths:
            local_image_paths = await _register_local_image_urls(local_paths)
            if local_image_paths:
                # Use local paths to avoid one-time file-token expiration warnings.
                req.image_urls = local_image_paths
            elif existing_urls:
                req.image_urls = existing_urls
            elif failed_urls:
                req.image_urls = failed_urls
            elif origin_urls:
                req.image_urls = origin_urls
        elif not existing_urls:
            if failed_urls:
                req.image_urls = failed_urls
            elif origin_urls:
                req.image_urls = origin_urls

        removed_hint_parts = 0
        kept_parts = []
        for part in req.extra_user_content_parts:
            part_type = str(getattr(part, "type", "")).lower()
            if part_type == "text":
                text = str(getattr(part, "text", "")).strip()
                if IMAGE_ATTACHMENT_PATH_HINT_RE.match(text):
                    removed_hint_parts += 1
                    continue
            kept_parts.append(part)
        if removed_hint_parts:
            req.extra_user_content_parts = kept_parts

        if not req.image_urls:
            return

        hint = (
            "图片已通过多模态输入附带。"
            "不要调用工具读取本地图片路径，请直接基于已附带图片进行分析。"
        )
        if hint not in req.system_prompt:
            req.system_prompt = f"{req.system_prompt}\n{hint}".strip()
