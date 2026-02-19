from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.message_components import Image
from astrbot.api.provider import ProviderRequest
from astrbot.api.star import Context, Star, register
from astrbot.core.config.default import CONFIG_METADATA_2, WEBHOOK_SUPPORTED_PLATFORMS
from astrbot.core.skills.skill_manager import SkillManager
from astrbot.core.utils.astrbot_path import get_astrbot_skills_path

GITHUB_ADAPTER_TYPE = "github_app"
GITHUB_SKILL_TOOL_NAME = "github_app_issue_token"
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
    image_urls: list[str] = []
    for path in local_paths:
        try:
            image_url = await Image.fromFileSystem(path).register_to_file_service()
            url = str(image_url).strip()
            if url.startswith(("http://", "https://")):
                image_urls.append(url)
        except Exception as exc:
            logger.warning(f"[GitHubApp] 注册本地图片文件服务失败: path={path}, err={exc}")
    return list(dict.fromkeys(image_urls))


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


def _build_github_skill_content(skill_name: str) -> str:
    return f"""---
description: 使用 GitHub App 临时安装令牌，安全执行 Issue/PR/工作流推进任务。
---

# {skill_name}

这个 skill 用于在 GitHub 仓库中执行工程推进任务，并使用短期令牌保证安全。

## 安全模型

- 禁止使用永久 PAT，禁止保存长期凭据。
- 必须先调用 `{GITHUB_SKILL_TOOL_NAME}` 申请 GitHub App 临时安装令牌。
- 令牌只允许放在环境变量中使用，任务完成后立即清理。

## 运行策略

- shell/git 操作优先使用沙盒环境。
- 沙盒不可用时，才回退到本地环境。

## 必须流程

1. 明确目标仓库，格式 `owner/repo`。
2. 调用 `{GITHUB_SKILL_TOOL_NAME}` 获取临时令牌。
3. 将令牌写入环境变量：
   - PowerShell: `$env:GH_TOKEN='<临时令牌>'`
   - Bash: `export GH_TOKEN='<token>'`
4. 优先使用 `gh` CLI：
   - 检查：`gh --version`
   - 验证：`gh auth status`
5. 执行任务：
   - 创建 Issue：`gh issue create --repo owner/repo --title "<标题>" --body-file <文件>`
   - 提交并创建 PR：`git checkout -b ...` -> `git push` -> `gh pr create --repo owner/repo ...`
   - 触发工作流：`gh workflow run <workflow> --repo owner/repo --ref <branch>`
6. 完成后立即清理令牌：
   - PowerShell: `Remove-Item Env:GH_TOKEN`
   - Bash: `unset GH_TOKEN`

## 令牌安全规范

- 不要把令牌输出到聊天回复、Issue 正文、PR 描述、日志或文件中。
- 不要把令牌提交进仓库。
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
        skill_name = _ensure_github_skill(self.config)
        runtime_cfg = dict(self.config)
        runtime_cfg["effective_github_skill_name"] = skill_name
        set_runtime_plugin_config(runtime_cfg)
        _inject_platform_metadata()
        from .adapter.github_app_adapter import GitHubAppAdapter  # noqa: F401

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

    @filter.llm_tool(name=GITHUB_SKILL_TOOL_NAME)
    async def github_app_issue_token(
        self,
        event: AstrMessageEvent,
        repo: str = "",
        session_id: str = "",
        platform_id: str = "",
    ) -> str:
        """签发短期 GitHub App Installation Token，用于仓库操作。

        Args:
            repo(string): 目标仓库，格式 owner/repo。若事件上下文可推断可不传。
            session_id(string): 可选，github 会话 ID，格式 github:owner/repo:type:number。
            platform_id(string): 可选，存在多个 github_app 平台时指定平台 ID。
        """
        adapter = self._resolve_github_adapter(event, platform_id)
        if adapter is None:
            return "未找到可用的 github_app 平台适配器。"
        if not hasattr(adapter, "issue_installation_token_for_skill"):
            return (
                "当前 github_app 适配器不支持临时令牌签发，请升级此插件。"
            )

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

        ok, payload = await adapter.issue_installation_token_for_skill(repo=repo_value)
        if not ok:
            detail = str(payload.get("error", "unknown error"))
            return f"临时安装令牌签发失败：{detail}"

        token = str(payload.get("token", ""))
        if not token:
            return "临时安装令牌签发失败：返回了空令牌。"

        expires_at = str(payload.get("expires_at", ""))
        resolved_repo = str(payload.get("repo", repo_value))
        installation_id = str(payload.get("installation_id", ""))

        return "\n".join(
            [
                "GitHub App 临时安装令牌签发成功。",
                f"repo: {resolved_repo}",
                f"installation_id: {installation_id}",
                f"expires_at: {expires_at}",
                f"token: {token}",
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
            refreshed_urls = await _register_local_image_urls(local_paths)
            if refreshed_urls:
                req.image_urls = refreshed_urls
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
