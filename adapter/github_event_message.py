from __future__ import annotations

from astrbot.api.event import AstrMessageEvent, MessageChain


class GitHubAppMessageEvent(AstrMessageEvent):
    def __init__(
        self,
        message_str: str,
        message_obj,
        platform_meta,
        session_id: str,
        adapter,
    ) -> None:
        super().__init__(message_str, message_obj, platform_meta, session_id)
        self.adapter = adapter

    async def send(self, message: MessageChain):
        await self.adapter.send_by_session(self.session, message)
        await super().send(message)
