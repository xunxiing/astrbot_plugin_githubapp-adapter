from __future__ import annotations

from collections.abc import Mapping

THREAD_ISSUE_EVENTS = {"issues", "issue_comment"}
THREAD_PR_EVENTS = {
    "pull_request",
    "pull_request_review",
    "pull_request_review_comment",
}
THREAD_DISCUSSION_EVENTS = {"discussion", "discussion_comment"}


def _safe_repo_name(repo_name: str | None) -> str:
    if isinstance(repo_name, str) and repo_name.strip():
        return repo_name.strip()
    return "unknown/unknown"


def extract_repo_full_name(payload: Mapping) -> str:
    repository = payload.get("repository", {})
    if not isinstance(repository, Mapping):
        return "unknown/unknown"
    return _safe_repo_name(repository.get("full_name"))


def build_dynamic_session_id(event_name: str, payload: Mapping) -> str:
    repo_name = extract_repo_full_name(payload)

    if event_name in THREAD_ISSUE_EVENTS:
        issue = payload.get("issue", {})
        if isinstance(issue, Mapping):
            number = issue.get("number")
            if isinstance(number, int):
                return f"github:{repo_name}:issue:{number}"

    if event_name in THREAD_PR_EVENTS:
        pr = payload.get("pull_request", {})
        number = None
        if isinstance(pr, Mapping):
            number = pr.get("number")
        if not isinstance(number, int):
            payload_number = payload.get("number")
            if isinstance(payload_number, int):
                number = payload_number
        if isinstance(number, int):
            return f"github:{repo_name}:pr:{number}"

    if event_name in THREAD_DISCUSSION_EVENTS:
        discussion = payload.get("discussion", {})
        if isinstance(discussion, Mapping):
            number = discussion.get("number")
            if isinstance(number, int):
                return f"github:{repo_name}:discussion:{number}"

    return f"github:{repo_name}:global"
