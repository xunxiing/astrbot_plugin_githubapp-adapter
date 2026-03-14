from __future__ import annotations

import sys

from . import config_manager as _config_manager
from . import github_api_client as _github_api_client
from . import github_app_adapter as _github_app_adapter
from . import github_event as _github_event
from . import github_event_message as _github_event_message
from . import security as _security
from . import session_routing as _session_routing
from .github_app_adapter import GitHubAppAdapter

_ALIAS_PACKAGE_NAMES = (
    "data.plugins.astrbot_plugin_githubapp_adapter",
    "data.plugins.astrbot_plugin_githubapp-adapter",
    "data.plugins.astrbot_plugin_githubapp_adopter",
    "data.plugins.astrbot_plugin_githubapp-adopter",
)

for _alias in _ALIAS_PACKAGE_NAMES:
    sys.modules.setdefault(f"{_alias}.adapter", sys.modules[__name__])
    sys.modules.setdefault(f"{_alias}.adapter.config_manager", _config_manager)
    sys.modules.setdefault(f"{_alias}.adapter.github_api_client", _github_api_client)
    sys.modules.setdefault(f"{_alias}.adapter.github_app_adapter", _github_app_adapter)
    sys.modules.setdefault(f"{_alias}.adapter.github_event", _github_event)
    sys.modules.setdefault(
        f"{_alias}.adapter.github_event_message",
        _github_event_message,
    )
    sys.modules.setdefault(f"{_alias}.adapter.security", _security)
    sys.modules.setdefault(f"{_alias}.adapter.session_routing", _session_routing)

__all__ = ["GitHubAppAdapter"]
