"""Smoke tests for `sift_guard.config`."""

from __future__ import annotations

from pathlib import Path

import pytest

from sift_guard.config import (
    Config,
    apply_to_environment,
    discover_config,
    load_config,
)


def test_load_config_returns_empty_when_no_file_found(monkeypatch: pytest.MonkeyPatch):
    # Walk the discovery list with a tmp HOME / cwd so nothing
    # resolves; load_config should hand back an empty Config.
    monkeypatch.chdir(Path("/"))
    monkeypatch.setenv("HOME", "/nonexistent-home-for-test")
    cfg = load_config()
    assert isinstance(cfg, Config)
    assert cfg.volatility.path is None
    assert cfg.disk_tools.log2timeline is None
    assert cfg.analysis.max_iterations is None
    assert cfg.report_formats() == ["markdown", "json"]


def test_load_config_parses_full_document(tmp_path: Path):
    cfg_path = tmp_path / "sift-guard.yaml"
    cfg_path.write_text(
        """
volatility:
  path: /opt/vol3/bin/vol
  python: /opt/vol3/bin/python3
  symbols_dir: /opt/vol3/symbols/

disk_tools:
  log2timeline: /usr/bin/log2timeline.py
  evtx_dump: /usr/bin/evtx_dump.py
  premounted_path: /mnt/sift_disk

analysis:
  max_iterations: 10
  token_budget: 1234567
  model: claude-sonnet-4-20250514

output:
  dir: ./out
  generate_report: false
  report_format: markdown
""",
        encoding="utf-8",
    )
    cfg = load_config(cfg_path)
    assert cfg.volatility.path == "/opt/vol3/bin/vol"
    assert cfg.volatility.python == "/opt/vol3/bin/python3"
    assert cfg.volatility.symbols_dir == "/opt/vol3/symbols/"
    assert cfg.disk_tools.log2timeline == "/usr/bin/log2timeline.py"
    assert cfg.disk_tools.evtx_dump == "/usr/bin/evtx_dump.py"
    assert cfg.disk_tools.premounted_path == "/mnt/sift_disk"
    assert cfg.analysis.max_iterations == 10
    assert cfg.analysis.token_budget == 1_234_567
    assert cfg.analysis.model == "claude-sonnet-4-20250514"
    assert cfg.output.dir == "./out"
    assert cfg.output.generate_report is False
    assert cfg.report_formats() == ["markdown"]


def test_load_config_missing_file_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "does-not-exist.yaml")


def test_load_config_non_mapping_raises(tmp_path: Path):
    cfg_path = tmp_path / "bad.yaml"
    cfg_path.write_text("- a list, not a mapping\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(cfg_path)


def test_apply_to_environment_sets_expected_vars(monkeypatch: pytest.MonkeyPatch):
    cfg = Config()
    cfg.volatility.path = "/opt/vol3/bin/vol"
    cfg.disk_tools.log2timeline = "/usr/bin/log2timeline.py"
    cfg.analysis.model = "claude-sonnet-4-20250514"
    monkeypatch.delenv("SIFT_VOL_PATH", raising=False)
    monkeypatch.delenv("SIFT_DISK_LOG2TIMELINE_BIN", raising=False)
    monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
    changed = apply_to_environment(cfg)
    assert changed["SIFT_VOL_PATH"] == "/opt/vol3/bin/vol"
    assert changed["SIFT_DISK_LOG2TIMELINE_BIN"] == "/usr/bin/log2timeline.py"
    assert changed["ANTHROPIC_MODEL"] == "claude-sonnet-4-20250514"
    # Empty fields do not pollute the environment.
    assert "SIFT_DISK_REGRIPPER_BIN" not in changed


def test_discover_config_extra_candidate_wins(tmp_path: Path):
    extra = tmp_path / "preferred.yaml"
    extra.write_text("volatility: {}\n", encoding="utf-8")
    found = discover_config(extra_candidates=[extra])
    assert found == extra
