"""Unit tests for `server.runners.sift_vm`.

Real SSH calls are out of scope here — those are integration tests
against a live SIFT VM, marked ``@pytest.mark.integration`` and skipped
by default per pyproject.toml's pytest config. These unit tests mock
``subprocess.run`` and exercise:

  - the ``plugin_name`` regex (positive + negative cases)
  - the ``image_path_in_vm`` prefix check
  - the ``parse_pslist_json`` PascalCase → snake_case mapping, including
    forward-compat behavior on unknown fields a future Volatility
    release might add.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Pin SIFT_VM_HOST before importing the module so module-load-time
# detection is bypassed. Without this, the import would shell out to
# `ip route show` on the test runner — fine on WSL2, not portable.
os.environ.setdefault("SIFT_VM_HOST", "test.invalid")

from server.runners.sift_vm import (  # noqa: E402  (intentional post-env import)
    SIFT_VM_EVIDENCE_PREFIX,
    parse_pslist_json,
    run_vol_plugin,
)


PSLIST_FIXTURE = Path(__file__).parent / "fixtures" / "vol_pslist_sample.json"
VALID_IMAGE_PATH = f"{SIFT_VM_EVIDENCE_PREFIX}/Rocba-Memory.raw"


# ---------------------------------------------------------------------------
# plugin_name regex
# ---------------------------------------------------------------------------


class TestPluginNameRegex:
    """The regex shape is ``lower.lower.PascalCase``. It is the
    defense-in-depth check on top of the architectural boundary
    (the MCP tool wrapper exposes only typed, plugin-specific
    functions; the agent never names a plugin via free-form input).
    Even so, the regex must reject every shape that could embed shell
    metacharacters."""

    @pytest.mark.parametrize(
        "name",
        [
            "windows.pslist.PsList",
            "windows.netscan.NetScan",
            "windows.malfind.Malfind",
        ],
    )
    def test_accepts_valid_plugin_names(self, name: str):
        # Mock subprocess.run so no real SSH happens; we only want to
        # confirm the regex let the call through to subprocess.
        with patch("server.runners.sift_vm.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="[]", returncode=0)
            stdout, command_string, runtime_seconds = run_vol_plugin(
                name, VALID_IMAGE_PATH
            )
        assert stdout == "[]"
        assert name in command_string
        assert runtime_seconds >= 0
        assert mock_run.call_count == 1
        argv = mock_run.call_args.args[0]
        # The plugin name must appear as the LAST argv element — no
        # shell, no string interpolation, just argv.
        assert argv[-1] == name

    @pytest.mark.parametrize(
        "name",
        [
            "windows.pslist.PsList; rm -rf /",
            "../../../etc/passwd",
            "windows.pslist.PsList && evil",
            "",
            "no_dots",
        ],
    )
    def test_rejects_malformed_plugin_names(self, name: str):
        # subprocess must NOT be called for any rejected input.
        with patch("server.runners.sift_vm.subprocess.run") as mock_run:
            with pytest.raises(ValueError):
                run_vol_plugin(name, VALID_IMAGE_PATH)
            assert mock_run.call_count == 0


# ---------------------------------------------------------------------------
# image_path_in_vm prefix check
# ---------------------------------------------------------------------------


class TestImagePathPrefix:
    def test_path_outside_prefix_rejected(self):
        # `/etc/passwd` is the canonical out-of-bounds probe — outside
        # SIFT_VM_EVIDENCE_PREFIX, so the runner must refuse to even
        # construct the SSH command.
        with patch("server.runners.sift_vm.subprocess.run") as mock_run:
            with pytest.raises(ValueError):
                run_vol_plugin("windows.pslist.PsList", "/etc/passwd")
            assert mock_run.call_count == 0


# ---------------------------------------------------------------------------
# parse_pslist_json
# ---------------------------------------------------------------------------


class TestParsePslistJson:
    def test_maps_three_record_fixture_to_snake_case(self):
        # Fixture: System (PID 4), Registry (PID 100), smss.exe (PID 440)
        # — replace tests/fixtures/vol_pslist_sample.json with the real
        # first 3 records of /tmp/pslist.json from the SIFT VM and these
        # assertions still hold.
        stdout = PSLIST_FIXTURE.read_text(encoding="utf-8")
        rows = parse_pslist_json(stdout)

        assert len(rows) == 3
        assert rows[0]["pid"] == 4
        assert rows[0]["ppid"] == 0
        assert rows[0]["image_file_name"] == "System"
        assert rows[1]["pid"] == 100
        assert rows[1]["image_file_name"] == "Registry"
        assert rows[2]["pid"] == 440
        assert rows[2]["image_file_name"] == "smss.exe"

        # Volatility's PascalCase / parens / spaces are gone.
        for row in rows:
            assert "PID" not in row
            assert "ImageFileName" not in row
            assert "Offset(V)" not in row
            assert "File output" not in row
            assert "__children" not in row

        # Every expected snake_case key is present in row 0 (System).
        expected_keys = {
            "pid", "ppid", "image_file_name", "offset_v", "threads",
            "handles", "session_id", "wow64", "create_time", "exit_time",
        }
        assert set(rows[0].keys()) == expected_keys

    def test_empty_list_returns_empty(self):
        # Pathological dump: zero processes. The parser must not crash —
        # downstream PslistResult tolerates an empty list (see
        # tests/test_schemas.py::TestPslistResult).
        assert parse_pslist_json("[]") == []

    def test_unknown_extra_fields_ignored(self):
        # Forward-compat: a future Volatility release may add fields
        # like ``ImageBase``, ``AuditFlags``, or ``TokenPrivileges``.
        # The parser must drop unknown keys silently rather than poison
        # the dict ``ProcessRecord(**d)`` will consume.
        future_output = json.dumps(
            [
                {
                    "PID": 4,
                    "PPID": 0,
                    "ImageFileName": "System",
                    "Offset(V)": 0,
                    "Threads": 1,
                    "Handles": None,
                    "SessionId": None,
                    "Wow64": False,
                    "CreateTime": "2024-01-01T00:00:00+00:00",
                    "ExitTime": None,
                    "File output": "Disabled",
                    "__children": [],
                    # Hypothetical future fields:
                    "AuditFlags": 0,
                    "ImageBase": 12345,
                    "TokenPrivileges": ["SeDebugPrivilege"],
                }
            ]
        )
        rows = parse_pslist_json(future_output)
        assert len(rows) == 1
        for unknown in ("AuditFlags", "ImageBase", "TokenPrivileges"):
            assert unknown not in rows[0]
        # And the known fields still made it through.
        assert rows[0]["pid"] == 4
        assert rows[0]["image_file_name"] == "System"
