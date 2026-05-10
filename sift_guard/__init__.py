"""sift-guard — turnkey forensic-analysis appliance over the MCP server.

Public surface:

  - ``Config`` — parsed sift-guard.yaml
  - ``load_config`` — load + validate config from a path or
    auto-discover ``./sift-guard.yaml`` / ``~/.config/sift-guard.yaml``
  - ``preflight_check_image`` — Volatility OS detection probe used by
    the CLI before dispatching analysts
  - ``main`` — the ``sift-guard`` CLI entry point
"""

from sift_guard.config import (
    AnalysisConfig,
    Config,
    DiskToolsConfig,
    OutputConfig,
    VolatilityConfig,
    load_config,
)
from sift_guard.preflight import OsDetectionResult, preflight_check_image


__all__ = [
    "AnalysisConfig",
    "Config",
    "DiskToolsConfig",
    "OsDetectionResult",
    "OutputConfig",
    "VolatilityConfig",
    "load_config",
    "preflight_check_image",
]
