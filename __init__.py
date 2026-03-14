from __future__ import annotations

import sys

from . import adapter as _adapter_pkg
from . import main as _main_mod
from .main import GitHubAppAdapterPlugin, GitHubAppAdopterPlugin

_ALIAS_PACKAGE_NAMES = (
    "data.plugins.astrbot_plugin_githubapp_adapter",
    "data.plugins.astrbot_plugin_githubapp-adapter",
)

for _alias in _ALIAS_PACKAGE_NAMES:
    sys.modules.setdefault(_alias, sys.modules[__name__])
    sys.modules.setdefault(f"{_alias}.main", _main_mod)
    sys.modules.setdefault(f"{_alias}.adapter", _adapter_pkg)

__all__ = ["GitHubAppAdapterPlugin", "GitHubAppAdopterPlugin"]
