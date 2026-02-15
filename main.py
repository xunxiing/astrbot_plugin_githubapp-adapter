from __future__ import annotations

from astrbot.api import logger
from astrbot.api.event import filter
from astrbot.api.star import Context, Star, register
from astrbot.core.config.default import CONFIG_METADATA_2, WEBHOOK_SUPPORTED_PLATFORMS

GITHUB_ADAPTER_TYPE = "github_app"
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


def _inject_platform_metadata() -> None:
    if GITHUB_ADAPTER_TYPE not in WEBHOOK_SUPPORTED_PLATFORMS:
        WEBHOOK_SUPPORTED_PLATFORMS.append(GITHUB_ADAPTER_TYPE)

    platform_meta = CONFIG_METADATA_2["platform_group"]["metadata"]["platform"]
    items = platform_meta["items"]

    items.setdefault(
        "github_app_id",
        {
            "description": "GitHub App ID",
            "type": "string",
            "hint": "GitHub App settings page value.",
        },
    )
    items.setdefault(
        "github_webhook_secret",
        {
            "description": "GitHub Webhook Secret",
            "type": "string",
            "hint": "Must match webhook secret in GitHub App.",
        },
    )
    items.setdefault(
        "github_api_base_url",
        {
            "description": "GitHub API Base URL",
            "type": "string",
            "hint": "Default is https://api.github.com.",
        },
    )
    items.setdefault(
        "github_events",
        {
            "description": "GitHub Events",
            "type": "list",
            "hint": "Empty means all supported events.",
            "options": SUPPORTED_GITHUB_EVENTS,
        },
    )
    items.setdefault(
        "wake_event_types",
        {
            "description": "Wake Event Types",
            "type": "list",
            "hint": "Only these events trigger LLM wake.",
            "options": SUPPORTED_GITHUB_EVENTS,
        },
    )
    items.setdefault(
        "github_signature_validation",
        {
            "description": "Enable Signature Validation",
            "type": "bool",
            "hint": "Verify X-Hub-Signature-256 for each webhook request.",
        },
    )
    items.setdefault(
        "github_delivery_cache_ttl_seconds",
        {
            "description": "Delivery Dedup TTL (seconds)",
            "type": "int",
            "hint": "Replay protection window.",
        },
    )
    items.setdefault(
        "github_delivery_cache_max_entries",
        {
            "description": "Delivery Dedup Max Entries",
            "type": "int",
            "hint": "Upper bound for in-memory dedup cache size.",
        },
    )

    logger.info("[GitHubApp] platform metadata injected")


@register(
    "astrbot_plugin_githubapp-adopter",
    "OpenCode",
    "GitHub App webhook platform adapter for AstrBot",
    "v0.1.2",
    "https://github.com/example/astrbot_plugin_githubapp-adopter",
)
class GitHubAppAdopterPlugin(Star):
    def __init__(self, context: Context, config: dict):
        super().__init__(context)
        self.config = config
        _inject_platform_metadata()
        from .adapter.github_app_adapter import GitHubAppAdapter  # noqa: F401

    @filter.on_astrbot_loaded()
    async def on_astrbot_loaded(self):
        _inject_platform_metadata()
