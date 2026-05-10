"""sift-guard — turnkey forensic-analysis CLI on top of Claude Code.

The MCP server (`server.main`) exposes typed forensic tools; the
analyst / validator subagents in ``.claude/agents/`` consume those
tools via the Claude Code CLI; the orchestrator loop dispatches
those subagents and tracks findings + correlations across
iterations. ``sift-guard analyze <evidence-dir>`` is the
operator-facing wrapper that scans, registers, preflights, and
drives the multi-host loop with real-time progress on stdout.

Authentication is handled by Claude Code (`claude login`) — no
ANTHROPIC_API_KEY needed when running with a Max subscription.
"""

from sift_guard.preflight import OsDetectionResult, preflight_check_image


__all__ = ["OsDetectionResult", "preflight_check_image"]
