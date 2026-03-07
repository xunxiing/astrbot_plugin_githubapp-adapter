from __future__ import annotations

import asyncio
import base64
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib import error, parse, request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from astrbot.api import logger


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _stringify_github_error(data: Any) -> str:
    if isinstance(data, Mapping):
        message = str(data.get("message", "")).strip()
        if message:
            errors = data.get("errors")
            if isinstance(errors, list) and errors:
                parts = []
                for err in errors[:3]:
                    if isinstance(err, Mapping):
                        code = str(err.get("code", "")).strip()
                        field = str(err.get("field", "")).strip()
                        detail = str(err.get("message", "")).strip()
                        text = ":".join(x for x in [code, field, detail] if x)
                        if text:
                            parts.append(text)
                if parts:
                    return f"{message} ({'; '.join(parts)})"
            return message
    if isinstance(data, str):
        text = data.strip()
        if text:
            return text[:200]
    return ""


@dataclass(slots=True)
class InstallationTokenCacheEntry:
    token: str
    expires_at: float


class GitHubApiClient:
    def __init__(self, timeout_seconds: int = 15) -> None:
        self.github_api_base_url = "https://api.github.com"
        self.github_app_id = ""
        self.private_key_text = ""
        self._http_timeout_seconds = timeout_seconds
        self._installation_token_cache: dict[int, InstallationTokenCacheEntry] = {}

    def configure(
        self,
        *,
        github_api_base_url: str,
        github_app_id: str,
        private_key_text: str,
    ) -> None:
        self.github_api_base_url = str(github_api_base_url or "").rstrip("/")
        self.github_app_id = str(github_app_id or "").strip()
        self.private_key_text = str(private_key_text or "")

    async def fetch_app_slug(self) -> str:
        app_jwt = self.build_app_jwt()
        if not app_jwt:
            return ""
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {app_jwt}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        status, data = await self.request_json(
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

    async def resolve_installation_id(self, repo: str) -> int | None:
        app_jwt = self.build_app_jwt()
        if not app_jwt:
            return None
        repo_path = parse.quote(repo, safe="/")
        url = f"{self.github_api_base_url}/repos/{repo_path}/installation"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {app_jwt}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        status, data = await self.request_json("GET", url, headers=headers, body=None)
        if status != 200 or not isinstance(data, Mapping):
            detail = _stringify_github_error(data)
            logger.warning(
                f"[GitHubApp] resolve installation failed: repo={repo}, status={status}, detail={detail}"
            )
            return None
        installation_id = data.get("id")
        return int(installation_id) if isinstance(installation_id, int) else None

    async def get_installation_access_token(self, installation_id: int) -> str:
        token_data = await self.create_installation_access_token(
            installation_id,
            permissions=None,
            repositories=None,
            use_cache=True,
        )
        token = token_data.get("token")
        if isinstance(token, str):
            return token
        return ""

    async def create_installation_access_token(
        self,
        installation_id: int,
        *,
        permissions: Mapping[str, str] | None = None,
        repositories: list[str] | None = None,
        use_cache: bool = True,
    ) -> dict[str, Any]:
        now = time.time()
        permission_map = (
            {str(k): str(v) for k, v in permissions.items()}
            if isinstance(permissions, Mapping)
            else {}
        )
        scoped_repositories = list(
            dict.fromkeys(
                str(name).strip()
                for name in (repositories or [])
                if isinstance(name, str) and str(name).strip()
            )
        )
        use_default_scope = not permission_map and not scoped_repositories
        if use_cache and use_default_scope:
            cached = self._installation_token_cache.get(installation_id)
            if cached and cached.expires_at - 60 > now:
                return {
                    "token": cached.token,
                    "expires_at": "",
                    "expires_at_epoch": cached.expires_at,
                    "repository_selection": "all",
                    "permissions": {},
                }

        app_jwt = self.build_app_jwt()
        if not app_jwt:
            return {"error": "app jwt build failed"}
        url = (
            f"{self.github_api_base_url}/app/installations/"
            f"{installation_id}/access_tokens"
        )
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {app_jwt}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        body: dict[str, Any] = {}
        if permission_map:
            body["permissions"] = permission_map
        if scoped_repositories:
            body["repositories"] = scoped_repositories
        status, data = await self.request_json("POST", url, headers=headers, body=body)
        if status != 201 or not isinstance(data, Mapping):
            detail = _stringify_github_error(data)
            logger.warning(
                "[GitHubApp] get installation token failed: "
                f"installation={installation_id}, status={status}, detail={detail}"
            )
            return {"error": f"status={status}, detail={detail}"}

        token = data.get("token")
        if not isinstance(token, str) or not token:
            return {"error": "token missing"}
        expires_at_text = data.get("expires_at")
        expires_at_epoch = self.parse_github_datetime(expires_at_text)
        if expires_at_epoch <= now:
            expires_at_epoch = now + 3000
        if use_cache and use_default_scope:
            self._installation_token_cache[installation_id] = InstallationTokenCacheEntry(
                token=token,
                expires_at=expires_at_epoch,
            )
        return {
            "token": token,
            "expires_at": str(expires_at_text or ""),
            "expires_at_epoch": expires_at_epoch,
            "repository_selection": data.get("repository_selection"),
            "permissions": dict(data.get("permissions", {}))
            if isinstance(data.get("permissions"), Mapping)
            else {},
        }

    async def post_issue_comment(
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
        status, data = await self.request_json(
            "POST",
            url,
            headers=headers,
            body={"body": body_text},
        )
        if status == 201:
            return True, "ok"
        detail = _stringify_github_error(data)
        return False, f"status={status}, detail={detail}"

    def build_app_jwt(self) -> str:
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

    async def request_json(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: Mapping[str, Any] | None,
    ) -> tuple[int, Any]:
        return await asyncio.to_thread(
            self.request_json_sync,
            method,
            url,
            dict(headers),
            dict(body) if isinstance(body, Mapping) else None,
        )

    def request_json_sync(
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

    @staticmethod
    def parse_github_datetime(value: Any) -> float:
        if not isinstance(value, str) or not value:
            return 0.0
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0
