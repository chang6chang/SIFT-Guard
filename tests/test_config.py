"""sift_guard.config — YAML config loader (ported from the enterprise
branch). CLI flags > config file > built-in defaults."""

from __future__ import annotations

import pytest

from sift_guard.config import (
    Config,
    apply_to_environment,
    discover_config,
    load_config,
)


def _write(tmp_path, text):
    p = tmp_path / "sift-guard.yaml"
    p.write_text(text)
    return p


class TestLoad:
    def test_missing_explicit_path_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nope.yaml")

    def test_no_file_anywhere_returns_empty_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("HOME", str(tmp_path))
        cfg = load_config(None)
        assert cfg.analysis.max_iterations is None
        assert cfg.output.generate_report is True

    def test_full_document_round_trips(self, tmp_path):
        p = _write(
            tmp_path,
            """
volatility:
  path: /usr/bin/vol
  symbols_dir: /opt/volatility3/symbols
disk_tools:
  ewfmount: /usr/local/bin/ewfmount
  mount: /usr/bin/mount
analysis:
  max_iterations: 3
  token_budget: 750000
  model: claude-sonnet-5
output:
  dir: /cases/out
  generate_report: false
""",
        )
        cfg = load_config(p)
        assert cfg.volatility.path == "/usr/bin/vol"
        assert cfg.disk_tools.mount == "/usr/bin/mount"
        assert cfg.analysis.max_iterations == 3
        assert cfg.analysis.token_budget == 750000
        assert cfg.output.dir == "/cases/out"
        assert cfg.output.generate_report is False
        assert cfg.source_path == p.resolve()

    def test_non_mapping_document_raises(self, tmp_path):
        p = _write(tmp_path, "- just\n- a list\n")
        with pytest.raises(ValueError):
            load_config(p)

    def test_unknown_keys_ignored(self, tmp_path):
        p = _write(tmp_path, "future_section:\n  x: 1\nanalysis:\n  max_iterations: 2\n")
        assert load_config(p).analysis.max_iterations == 2

    def test_garbage_int_coerces_to_none(self, tmp_path):
        p = _write(tmp_path, "analysis:\n  max_iterations: lots\n")
        assert load_config(p).analysis.max_iterations is None


class TestDiscovery:
    def test_cwd_file_discovered(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        p = _write(tmp_path, "analysis: {}\n")
        assert discover_config() == p

    def test_explicit_candidates_win(self, tmp_path):
        extra = tmp_path / "custom.yaml"
        extra.write_text("analysis: {}\n")
        assert discover_config(extra_candidates=[extra]) == extra


class TestApplyToEnvironment:
    def test_sets_only_configured_vars(self, tmp_path, monkeypatch):
        for var in ("SIFT_VOL_PATH", "SIFT_DISK_MOUNT_BIN", "ANTHROPIC_MODEL"):
            monkeypatch.delenv(var, raising=False)
        p = _write(tmp_path, "volatility:\n  path: /usr/bin/vol\n")
        changes = apply_to_environment(load_config(p))
        assert changes == {"SIFT_VOL_PATH": "/usr/bin/vol"}
        import os

        assert os.environ["SIFT_VOL_PATH"] == "/usr/bin/vol"
        assert "SIFT_DISK_MOUNT_BIN" not in os.environ

    def test_model_maps_to_anthropic_model(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
        p = _write(tmp_path, "analysis:\n  model: claude-sonnet-5\n")
        changes = apply_to_environment(load_config(p))
        assert changes["ANTHROPIC_MODEL"] == "claude-sonnet-5"


class TestCliPrecedence:
    def test_flag_beats_config_beats_default(self, tmp_path, monkeypatch):
        from sift_guard.cli import _parser

        _write(tmp_path, "analysis:\n  max_iterations: 3\n")
        monkeypatch.chdir(tmp_path)

        args = _parser().parse_args(["analyze", str(tmp_path), "--max-iterations", "9"])
        assert args.max_iterations == 9

        args = _parser().parse_args(["analyze", str(tmp_path)])
        assert args.max_iterations is None  # resolved later from config
