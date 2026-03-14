from __future__ import annotations

import sys

from astrbot.core.star.star import star_map

from . import adapter as _adapter_pkg
from . import main as _main_mod
from .main import GitHubAppAdapterPlugin, GitHubAppAdopterPlugin

_ALIAS_PACKAGE_NAMES = (
    "data.plugins.astrbot_plugin_githubapp_adapter",
    "data.plugins.astrbot_plugin_githubapp-adapter",
    "data.plugins.astrbot_plugin_githubapp_adopter",
    "data.plugins.astrbot_plugin_githubapp-adopter",
)

for _alias in _ALIAS_PACKAGE_NAMES:
    sys.modules.setdefault(_alias, sys.modules[__name__])
    sys.modules.setdefault(f"{_alias}.main", _main_mod)
    sys.modules.setdefault(f"{_alias}.adapter", _adapter_pkg)

if _metadata := star_map.get(_main_mod.__name__):
    for _alias in _ALIAS_PACKAGE_NAMES:
        star_map.setdefault(_alias, _metadata)
        star_map.setdefault(f"{_alias}.main", _metadata)

__all__ = ["GitHubAppAdapterPlugin", "GitHubAppAdopterPlugin"]
