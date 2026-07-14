"""Configuration loader for ``sift-guard.yaml``.

Layout::

    volatility:
      path: /usr/bin/vol            # or omit for auto-detect
      symbols_dir: /opt/volatility3/symbols/
      python: /opt/volatility3/bin/python3   # optional override

    disk_tools:
      log2timeline: /usr/bin/log2timeline.py
      psort: /usr/bin/psort.py
      evtx_dump: /usr/bin/evtx_dump.py
      regripper: /usr/bin/rip.pl
      ewfmount: /usr/bin/ewfmount
      guestmount: /usr/bin/guestmount
      mount: /usr/bin/mount

    analysis:
      max_iterations: 6
      token_budget: 2000000
      model: claude-sonnet-5

    output:
      dir: ./results
      generate_report: true

Every field is optional; missing values fall back to the runtime
defaults baked into the orchestrator and the local runner. The
config takes effect by:

  - exporting environment variables that the runner / disk_mount
    modules already consult (``SIFT_VOL_PATH``, ``SIFT_VOL_PYTHON``,
    ``SIFT_DISK_LOG2TIMELINE_BIN``, etc.)
  - shaping the ``analyze`` subcommand's defaults for
    ``--max-iterations`` / ``--token-budget`` / ``--output-dir``
    when those flags are not passed explicitly.

CLI flags always win over config values, which always win over
environment defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml


@dataclass
class VolatilityConfig:
    path: str | None = None
    python: str | None = None
    symbols_dir: str | None = None


@dataclass
class DiskToolsConfig:
    log2timeline: str | None = None
    psort: str | None = None
    evtx_dump: str | None = None
    regripper: str | None = None
    ewfmount: str | None = None
    guestmount: str | None = None
    mount: str | None = None
    prefetch_cmd: str | None = None
    premounted_path: str | None = None


@dataclass
class AnalysisConfig:
    max_iterations: int | None = None
    token_budget: int | None = None
    model: str | None = None


@dataclass
class OutputConfig:
    dir: str | None = None
    generate_report: bool = True


@dataclass
class Config:
    volatility: VolatilityConfig = field(default_factory=VolatilityConfig)
    disk_tools: DiskToolsConfig = field(default_factory=DiskToolsConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    source_path: Path | None = None


# Standard discovery order, first match wins. Computed at call time
# (not import time) so cwd/HOME changes after import — the CLI chdirs
# into case directories — still resolve correctly.
def _default_discovery_paths() -> tuple[Path, ...]:
    return (
        Path.cwd() / "sift-guard.yaml",
        Path.cwd() / "sift-guard.yml",
        Path.home() / ".config" / "sift-guard.yaml",
        Path("/etc/sift-guard.yaml"),
    )


def _coerce_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _config_from_doc(doc: dict[str, Any], source_path: Path | None) -> Config:
    """Translate a parsed YAML document into a `Config`.

    Unknown keys are ignored — forward-compat with future fields a
    later version of sift-guard might add. Callers that want strict
    validation can add it on top of this function.
    """
    vol_doc = doc.get("volatility") or {}
    disk_doc = doc.get("disk_tools") or {}
    ana_doc = doc.get("analysis") or {}
    out_doc = doc.get("output") or {}

    return Config(
        volatility=VolatilityConfig(
            path=_coerce_str(vol_doc.get("path")),
            python=_coerce_str(vol_doc.get("python")),
            symbols_dir=_coerce_str(vol_doc.get("symbols_dir")),
        ),
        disk_tools=DiskToolsConfig(
            log2timeline=_coerce_str(disk_doc.get("log2timeline")),
            psort=_coerce_str(disk_doc.get("psort")),
            evtx_dump=_coerce_str(disk_doc.get("evtx_dump")),
            regripper=_coerce_str(disk_doc.get("regripper")),
            ewfmount=_coerce_str(disk_doc.get("ewfmount")),
            guestmount=_coerce_str(disk_doc.get("guestmount")),
            mount=_coerce_str(disk_doc.get("mount")),
            prefetch_cmd=_coerce_str(disk_doc.get("prefetch_cmd")),
            premounted_path=_coerce_str(disk_doc.get("premounted_path")),
        ),
        analysis=AnalysisConfig(
            max_iterations=_coerce_int(ana_doc.get("max_iterations")),
            token_budget=_coerce_int(ana_doc.get("token_budget")),
            model=_coerce_str(ana_doc.get("model")),
        ),
        output=OutputConfig(
            dir=_coerce_str(out_doc.get("dir")),
            generate_report=_coerce_bool(out_doc.get("generate_report"), True),
        ),
        source_path=source_path,
    )


def discover_config(extra_candidates: Iterable[Path] = ()) -> Path | None:
    for candidate in tuple(extra_candidates) + _default_discovery_paths():
        if candidate.is_file():
            return candidate
    return None


def load_config(config_path: Path | str | None = None) -> Config:
    """Load `Config` from `config_path` or auto-discover.

    Returns an empty `Config` (every field None / default) when no
    file is found — callers can still apply CLI flags on top.
    """
    if config_path is not None:
        path = Path(config_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"config file not found: {path}")
    else:
        path = discover_config()
        if path is None:
            return Config()

    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict):
        raise ValueError(f"config file is not a YAML mapping: {path}")
    return _config_from_doc(raw, source_path=path.resolve())


def apply_to_environment(config: Config) -> dict[str, str]:
    """Project the config onto the env vars consulted by the
    runtime modules.

    Returns a dict of env vars that were set so the CLI can echo
    them back to the operator. Idempotent — re-running with the
    same config produces the same env state.
    """
    env_changes: dict[str, str] = {}

    def _set(name: str, value: str | None) -> None:
        if value:
            os.environ[name] = value
            env_changes[name] = value

    _set("SIFT_VOL_PATH", config.volatility.path)
    _set("SIFT_VOL_PYTHON", config.volatility.python)
    _set("VOLATILITY3_SYMBOL_DIRS", config.volatility.symbols_dir)
    _set("SIFT_DISK_LOG2TIMELINE_BIN", config.disk_tools.log2timeline)
    _set("SIFT_DISK_PSORT_BIN", config.disk_tools.psort)
    _set("SIFT_DISK_EVTX_DUMP_CMD", config.disk_tools.evtx_dump)
    _set("SIFT_DISK_REGRIPPER_BIN", config.disk_tools.regripper)
    _set("SIFT_DISK_EWFMOUNT_BIN", config.disk_tools.ewfmount)
    _set("SIFT_DISK_GUESTMOUNT_BIN", config.disk_tools.guestmount)
    _set("SIFT_DISK_MOUNT_BIN", config.disk_tools.mount)
    _set("SIFT_DISK_PREFETCH_CMD", config.disk_tools.prefetch_cmd)
    _set("SIFT_DISK_PREMOUNTED_PATH", config.disk_tools.premounted_path)
    if config.analysis.model:
        env_changes["ANTHROPIC_MODEL"] = config.analysis.model
        os.environ["ANTHROPIC_MODEL"] = config.analysis.model
    return env_changes


__all__ = [
    "AnalysisConfig",
    "Config",
    "DiskToolsConfig",
    "OutputConfig",
    "VolatilityConfig",
    "apply_to_environment",
    "discover_config",
    "load_config",
]
