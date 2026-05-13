"""Tests for ``orchestrator.dispatch`` — MCP-attach plumbing.

The 2026-05-12 SRL-2015 incident: subagents launched without the
sift-guard MCP server attached, the agent frontmatter's
``tools: mcp__sift-guard__*`` allow-list silently failed open, and
the analyst burned 50-130K tokens improvising with Bash + Write
instead of calling ``record_finding``. Zero findings, zero audit
entries past ``register_evidence``.

These tests pin the architectural guardrail introduced in response:

  - ``resolve_mcp_config_path``: env > repo > install location.
  - ``dispatch_subagent`` adds ``--mcp-config`` to the claude argv.
  - The stream-json ``system`` init event is parsed for
    ``mcp_servers``; a missing ``sift-guard: connected`` entry
    flips ``DispatchResult.succeeded`` to False (fail-closed).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from orchestrator import dispatch as dispatch_mod
from orchestrator.dispatch import (
    DispatchResult,
    _extract_mcp_server_status,
    dispatch_subagent,
    resolve_mcp_config_path,
)


class TestResolveMcpConfigPath:
    def test_env_var_wins(self, tmp_path: Path, monkeypatch):
        custom = tmp_path / "custom.mcp.json"
        custom.write_text("{}")
        monkeypatch.setenv("SIFT_GUARD_MCP_CONFIG", str(custom))
        assert resolve_mcp_config_path() == custom

    def test_env_var_missing_file_falls_through(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("SIFT_GUARD_MCP_CONFIG", str(tmp_path / "does-not-exist.json"))
        # If the repo root .mcp.json exists (it does in CI), we get it.
        # The test only asserts we DON'T blow up and DON'T return the
        # non-existent env path.
        resolved = resolve_mcp_config_path()
        assert resolved != tmp_path / "does-not-exist.json"

    def test_returns_none_when_no_candidate_exists(
        self, tmp_path: Path, monkeypatch
    ):
        monkeypatch.delenv("SIFT_GUARD_MCP_CONFIG", raising=False)
        monkeypatch.setattr(
            dispatch_mod, "_REPO_ROOT_MCP_CONFIG", tmp_path / "nope.json"
        )
        monkeypatch.setattr(
            dispatch_mod,
            "_DEFAULT_INSTALL_MCP_CONFIG",
            tmp_path / "also-nope.json",
        )
        assert resolve_mcp_config_path() is None


class TestExtractMcpServerStatus:
    def test_parses_list_shape(self):
        events = [
            {
                "type": "system",
                "mcp_servers": [
                    {"name": "sift-guard", "status": "connected"},
                    {"name": "other", "status": "failed"},
                ],
            }
        ]
        assert _extract_mcp_server_status(events) == {
            "sift-guard": "connected",
            "other": "failed",
        }

    def test_parses_camelcase_key(self):
        events = [
            {
                "type": "init",
                "mcpServers": [{"name": "sift-guard", "status": "connected"}],
            }
        ]
        assert _extract_mcp_server_status(events) == {"sift-guard": "connected"}

    def test_parses_dict_shape(self):
        events = [
            {
                "type": "system",
                "mcp_servers": {"sift-guard": {"status": "connected"}},
            }
        ]
        assert _extract_mcp_server_status(events) == {"sift-guard": "connected"}

    def test_returns_empty_when_no_init_event(self):
        # Only assistant/user events; no system/init at all.
        events = [{"type": "assistant", "message": {"content": []}}]
        assert _extract_mcp_server_status(events) == {}


class TestDispatchSubagentMcpConfigArg:
    """The ``claude -p`` argv must include ``--mcp-config <path>`` when
    a config is resolvable, and the dispatch must mark itself failed
    when the subagent's init event doesn't list sift-guard as
    connected."""

    def _fake_proc(self, stdout: str):
        """Build a fake subprocess.CompletedProcess-like with stdout."""

        class _R:
            returncode = 0

            def __init__(self, out):
                self.stdout = out
                self.stderr = ""

        return _R(stdout)

    def _stream(self, mcp_attached: bool) -> str:
        """A minimal stream-json transcript: system init + result."""
        init = {
            "type": "system",
            "mcp_servers": [
                {
                    "name": "sift-guard",
                    "status": "connected" if mcp_attached else "failed",
                }
            ],
        }
        result = {
            "type": "result",
            "session_id": "sid",
            "stop_reason": "end_turn",
            "num_turns": 1,
            "duration_ms": 100,
            "duration_api_ms": 50,
            "total_cost_usd": 0.0,
            "usage": {
                "input_tokens": 10,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
                "output_tokens": 5,
            },
        }
        return json.dumps(init) + "\n" + json.dumps(result) + "\n"

    def test_argv_includes_mcp_config(self, tmp_path: Path, monkeypatch):
        # Real .mcp.json so the resolver picks it up.
        cfg = tmp_path / ".mcp.json"
        cfg.write_text('{"mcpServers": {}}')
        monkeypatch.setenv("SIFT_GUARD_MCP_CONFIG", str(cfg))

        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return self._fake_proc(self._stream(mcp_attached=True))

        with patch.object(dispatch_mod.subprocess, "run", side_effect=fake_run):
            result = dispatch_subagent(
                "process_analyst",
                prompt="evidence_id: foo",
                cwd=tmp_path,
            )

        assert "--mcp-config" in captured["cmd"]
        idx = captured["cmd"].index("--mcp-config")
        assert captured["cmd"][idx + 1] == str(cfg)
        assert result.succeeded
        assert result.sift_guard_mcp_attached

    def test_dispatch_fails_when_sift_guard_mcp_not_attached(
        self, tmp_path: Path, monkeypatch
    ):
        cfg = tmp_path / ".mcp.json"
        cfg.write_text('{"mcpServers": {}}')
        monkeypatch.setenv("SIFT_GUARD_MCP_CONFIG", str(cfg))

        def fake_run(cmd, **kwargs):
            return self._fake_proc(self._stream(mcp_attached=False))

        with patch.object(dispatch_mod.subprocess, "run", side_effect=fake_run):
            result = dispatch_subagent(
                "process_analyst",
                prompt="evidence_id: foo",
                cwd=tmp_path,
            )

        # stop_reason was end_turn — normally that'd be "succeeded".
        # The MCP-attach guard flips it to False so the orchestrator
        # sees the failure mode immediately.
        assert result.stop_reason == "end_turn"
        assert result.sift_guard_mcp_attached is False
        assert result.succeeded is False
        assert result.mcp_server_status.get("sift-guard") == "failed"

    def test_dispatch_fails_when_no_init_event(self, tmp_path: Path, monkeypatch):
        cfg = tmp_path / ".mcp.json"
        cfg.write_text('{"mcpServers": {}}')
        monkeypatch.setenv("SIFT_GUARD_MCP_CONFIG", str(cfg))

        result_only = (
            json.dumps(
                {
                    "type": "result",
                    "session_id": "sid",
                    "stop_reason": "end_turn",
                    "num_turns": 1,
                    "duration_ms": 100,
                    "duration_api_ms": 50,
                    "total_cost_usd": 0.0,
                    "usage": {
                        "input_tokens": 0,
                        "cache_creation_input_tokens": 0,
                        "cache_read_input_tokens": 0,
                        "output_tokens": 0,
                    },
                }
            )
            + "\n"
        )

        def fake_run(cmd, **kwargs):
            return self._fake_proc(result_only)

        with patch.object(dispatch_mod.subprocess, "run", side_effect=fake_run):
            result = dispatch_subagent(
                "process_analyst",
                prompt="evidence_id: foo",
                cwd=tmp_path,
            )

        assert result.mcp_server_status == {}
        assert result.succeeded is False

    def _stream_with_status(self, sift_status: str) -> str:
        """Like ``_stream`` but with an explicit sift-guard status string,
        for covering Claude Code's mid-handshake (``pending``) and
        explicit-failure (``needs-auth``, ``error``) shapes."""
        init = {
            "type": "system",
            "mcp_servers": [{"name": "sift-guard", "status": sift_status}],
        }
        result = {
            "type": "result",
            "session_id": "sid",
            "stop_reason": "end_turn",
            "num_turns": 1,
            "duration_ms": 100,
            "duration_api_ms": 50,
            "total_cost_usd": 0.0,
            "usage": {
                "input_tokens": 10,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
                "output_tokens": 5,
            },
        }
        return json.dumps(init) + "\n" + json.dumps(result) + "\n"

    @pytest.mark.parametrize(
        "sift_status",
        ["connected", "pending", "attached", "ready", "ok"],
    )
    def test_dispatch_succeeds_when_sift_guard_in_mid_handshake_or_attached(
        self, tmp_path: Path, monkeypatch, sift_status: str
    ):
        # Claude Code emits the system/init event before MCP servers
        # finish their handshake. For locally-spawned stdio servers
        # the typical status at init is ``pending``; tool calls
        # succeed once the handshake completes. The 2026-05-12
        # SRL-2015 v4 incident proved this: every subagent's init
        # event showed ``{'sift-guard': 'pending'}``, the guard
        # treated it as failure, and 12 dispatches bailed in <20s
        # each, producing zero findings. The guard must accept any
        # non-failure state.
        cfg = tmp_path / ".mcp.json"
        cfg.write_text('{"mcpServers": {}}')
        monkeypatch.setenv("SIFT_GUARD_MCP_CONFIG", str(cfg))

        def fake_run(cmd, **kwargs):
            return self._fake_proc(self._stream_with_status(sift_status))

        with patch.object(dispatch_mod.subprocess, "run", side_effect=fake_run):
            result = dispatch_subagent(
                "process_analyst",
                prompt="evidence_id: foo",
                cwd=tmp_path,
            )

        assert result.sift_guard_mcp_attached, (
            f"status={sift_status!r} should be accepted as attached"
        )
        assert result.succeeded

    @pytest.mark.parametrize(
        "sift_status", ["failed", "needs-auth", "error", "disconnected"]
    )
    def test_dispatch_fails_on_explicit_failure_states(
        self, tmp_path: Path, monkeypatch, sift_status: str
    ):
        cfg = tmp_path / ".mcp.json"
        cfg.write_text('{"mcpServers": {}}')
        monkeypatch.setenv("SIFT_GUARD_MCP_CONFIG", str(cfg))

        def fake_run(cmd, **kwargs):
            return self._fake_proc(self._stream_with_status(sift_status))

        with patch.object(dispatch_mod.subprocess, "run", side_effect=fake_run):
            result = dispatch_subagent(
                "process_analyst",
                prompt="evidence_id: foo",
                cwd=tmp_path,
            )

        assert result.sift_guard_mcp_attached is False, (
            f"status={sift_status!r} must be rejected"
        )
        assert result.succeeded is False
        assert result.mcp_server_status.get("sift-guard") == sift_status

    def test_argv_omits_flag_when_no_config_resolvable(
        self, tmp_path: Path, monkeypatch
    ):
        monkeypatch.delenv("SIFT_GUARD_MCP_CONFIG", raising=False)
        monkeypatch.setattr(
            dispatch_mod, "_REPO_ROOT_MCP_CONFIG", tmp_path / "absent-repo.json"
        )
        monkeypatch.setattr(
            dispatch_mod,
            "_DEFAULT_INSTALL_MCP_CONFIG",
            tmp_path / "absent-install.json",
        )
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return self._fake_proc(self._stream(mcp_attached=False))

        with patch.object(dispatch_mod.subprocess, "run", side_effect=fake_run):
            dispatch_subagent(
                "process_analyst",
                prompt="evidence_id: foo",
                cwd=tmp_path,
            )

        assert "--mcp-config" not in captured["cmd"], (
            "no config resolved → the flag must be omitted, not passed with empty arg"
        )


class TestDispatchSubagentHostScoping:
    """When ``host_id`` is supplied, ``dispatch_subagent`` synthesizes
    a per-dispatch .mcp.json that adds ``SIFT_GUARD_HOST_ID`` to the
    sift-guard env block, and passes THAT file via ``--mcp-config``.
    The MCP server child reads the env block when it starts and the
    server-side ``record_finding`` override binds every recorded
    finding to the dispatched host. Per CLAUDE.md Hard Rule #2."""

    def _fake_proc(self):
        class _R:
            returncode = 0

            def __init__(self):
                self.stdout = (
                    json.dumps(
                        {
                            "type": "system",
                            "mcp_servers": [
                                {"name": "sift-guard", "status": "connected"}
                            ],
                        }
                    )
                    + "\n"
                    + json.dumps(
                        {
                            "type": "result",
                            "session_id": "sid",
                            "stop_reason": "end_turn",
                            "num_turns": 1,
                            "duration_ms": 100,
                            "duration_api_ms": 50,
                            "total_cost_usd": 0.0,
                            "usage": {
                                "input_tokens": 10,
                                "cache_creation_input_tokens": 0,
                                "cache_read_input_tokens": 0,
                                "output_tokens": 5,
                            },
                        }
                    )
                    + "\n"
                )
                self.stderr = ""

        return _R()

    def _seed_base_config(self, tmp_path: Path, monkeypatch) -> Path:
        cfg = tmp_path / ".mcp.json"
        cfg.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "sift-guard": {
                            "command": "/opt/sift-guard/.venv/bin/python",
                            "args": ["-m", "server.main"],
                            "cwd": "/opt/sift-guard",
                            "env": {
                                "SIFT_GUARD_CASE_DIR": "/case",
                            },
                        }
                    }
                }
            )
        )
        monkeypatch.setenv("SIFT_GUARD_MCP_CONFIG", str(cfg))
        return cfg

    def test_argv_points_at_synthesized_config_when_host_id_set(
        self, tmp_path: Path, monkeypatch
    ):
        base_cfg = self._seed_base_config(tmp_path, monkeypatch)
        captured: dict[str, list[str]] = {}

        # Snapshot the synthesized config's bytes BEFORE the dispatch
        # `finally` deletes it.
        synthesized_payload: dict[str, dict] = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            idx = cmd.index("--mcp-config")
            cfg_path = Path(cmd[idx + 1])
            synthesized_payload["content"] = json.loads(
                cfg_path.read_text(encoding="utf-8")
            )
            synthesized_payload["path"] = str(cfg_path)
            return self._fake_proc()

        with patch.object(dispatch_mod.subprocess, "run", side_effect=fake_run):
            result = dispatch_subagent(
                "process_analyst",
                prompt="evidence_id: foo",
                cwd=tmp_path,
                host_id="nfury",
            )

        # 1. The argv pointed at a path under .mcp-dispatch/, not at
        #    the base config — concurrent workers would otherwise
        #    clobber each other's host scoping.
        assert synthesized_payload["path"] != str(base_cfg)
        assert ".mcp-dispatch" in synthesized_payload["path"]
        # 2. The synthesized config has SIFT_GUARD_HOST_ID in the env
        #    block — that's the only channel that reaches the MCP
        #    server child (Claude Code does not forward the parent's
        #    process env to stdio MCP servers).
        env = synthesized_payload["content"]["mcpServers"]["sift-guard"]["env"]
        assert env["SIFT_GUARD_HOST_ID"] == "nfury"
        # 3. Pre-existing env keys (SIFT_GUARD_CASE_DIR) survive.
        assert env["SIFT_GUARD_CASE_DIR"] == "/case"
        # 4. After dispatch completes, the synthesized file is cleaned
        #    up so the case_dir doesn't accumulate stale per-dispatch
        #    configs across a long run.
        assert not Path(synthesized_payload["path"]).exists()
        assert result.succeeded

    def test_argv_uses_base_config_when_host_id_omitted(
        self, tmp_path: Path, monkeypatch
    ):
        base_cfg = self._seed_base_config(tmp_path, monkeypatch)
        captured: dict[str, list[str]] = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return self._fake_proc()

        with patch.object(dispatch_mod.subprocess, "run", side_effect=fake_run):
            dispatch_subagent(
                "process_analyst",
                prompt="evidence_id: foo",
                cwd=tmp_path,
            )

        idx = captured["cmd"].index("--mcp-config")
        # Single-evidence path: base config is passed unchanged.
        assert captured["cmd"][idx + 1] == str(base_cfg)
