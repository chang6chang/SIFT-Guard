"""Subagent dispatch wrapper for the orchestrator loop.

Spawns `claude -p --agent <name>` as a subprocess and parses the
stream-json output to capture session id, token usage, duration,
stop reason. The CLI's frontmatter-restricted tool surface is what
enforces analyst/validator architectural boundaries — the wrapper
simply hands the agent a structured user prompt and waits for the
final result event.

# Focus-context delivery

The Claude Code CLI does not expose a parameter for arbitrary
subagent context. The fallback per the substrate prompt is a
structured user message:

  evidence_id={uuid}
  case_id={case-string}
  iteration_number={int}
  focus_context={"pids": [7900], "image_names": ["svchost.exe"]}

This is what the orchestrator passes via the prompt positional
argument. The analyst subagent's prompt has a `# Focus context
(optional)` section explaining the V5c-1 semantics: focus biases
attention but does not constrain scope.

# Parallel dispatch (fcntl-protected chain writers)

The five hash-chained writers (audit, findings, correlations,
extractions, iterations) all serialize their read-modify-write
phase via ``server._chain_lock.chain_write_lock``, an
``fcntl.flock``-backed sidecar mutex. This lets the orchestrator's
ANALYZE step submit every analyst job to a ``ThreadPoolExecutor``;
each thread spawns its own ``claude -p --agent <name>`` subprocess
with its own MCP-server child, and those concurrent MCP servers
contend for the chain locks rather than corrupting the chain.

Expected ANALYZE wall-clock for the SRL-2015 4-host case
(12 jobs at ~5-15 min each):

  - Sequential:        12 jobs × ~10 min = ~120 min
  - Parallel (this):   max single-job wall-clock ≈ 15-20 min

CORRELATE / PROMOTE / PLAN / WRITE stay sequential — the validator
needs the full DRAFT set before correlating, promotion is a single
DAG pass, and the iteration record is one entry per loop turn.

# Token accounting

The "result" stream-json event includes a usage block with
input_tokens, cache_creation_input_tokens, cache_read_input_tokens,
output_tokens. We define `tokens_uncached` as input + cache_creation
+ output — everything that wasn't served from cache. The orchestrator
sums these across iterations and triggers R_c termination if the
sum exceeds `TOKEN_BUDGET_UNCACHED`.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# Per-dispatch synthesized MCP configs land here so concurrent
# workers don't clobber one another's host scoping. Cleaned up in
# the dispatch ``finally`` once ``claude -p`` has exited.
_DISPATCH_MCP_SUBDIR = ".mcp-dispatch"


# MCP-config path resolution. Claude Code subagents discover MCP
# servers from ``.mcp.json`` in the launch cwd. The orchestrator's
# default cwd is ``case_dir.parent`` (e.g. ``~/results/``), which
# never contains the SIFT-Guard config — so without an explicit
# ``--mcp-config`` flag the subagent has no MCP tools and silently
# falls back to the default Bash/Read/Write surface, improvising
# instead of calling ``record_finding``. We resolve the config
# location explicitly:
#
#   1. ``SIFT_GUARD_MCP_CONFIG`` env var (operator override).
#   2. ``$REPO_ROOT/.mcp.json`` (works when running from a checkout).
#   3. ``/opt/sift-guard/.mcp.json`` (the installed location written
#      by setup-sift-guard.sh).
#
# ``resolve_mcp_config_path`` returns the first hit or None;
# ``dispatch_subagent`` includes the flag iff a path is found.
_DEFAULT_INSTALL_MCP_CONFIG = Path("/opt/sift-guard/.mcp.json")
_REPO_ROOT_MCP_CONFIG = Path(__file__).resolve().parent.parent / ".mcp.json"


def resolve_mcp_config_path() -> Path | None:
    """Return the path to the MCP-server config, or None when no
    candidate exists. See module-level comment for resolution order."""
    env = os.environ.get("SIFT_GUARD_MCP_CONFIG")
    if env:
        candidate = Path(env)
        if candidate.exists():
            return candidate
        logger.warning(
            "SIFT_GUARD_MCP_CONFIG=%s does not exist; falling through to defaults",
            env,
        )
    if _REPO_ROOT_MCP_CONFIG.exists():
        return _REPO_ROOT_MCP_CONFIG
    if _DEFAULT_INSTALL_MCP_CONFIG.exists():
        return _DEFAULT_INSTALL_MCP_CONFIG
    return None


def _synthesize_host_scoped_mcp_config(
    base_config_path: Path,
    cwd: Path,
    host_id: str | None,
    *,
    allowed_evidence_ids: list[str] | None = None,
    role: str | None = None,
) -> Path | None:
    """Write a per-dispatch .mcp.json that adds ``SIFT_GUARD_HOST_ID``
    and (optionally) ``SIFT_GUARD_ALLOWED_EVIDENCE_IDS`` to the
    sift-guard server's ``env`` block, and return the new path.

    Claude Code does NOT forward the parent process's environment to a
    stdio-launched MCP server child — the child's env is sourced from
    the .mcp.json ``env`` block (which is also why ``SIFT_GUARD_CASE_DIR``
    lives there, see ``cli.py``'s per-case config synthesis). So
    per-dispatch host scoping has to land in a per-dispatch config file
    rather than being passed through ``subprocess.run``'s env=.

    ``allowed_evidence_ids`` is the per-dispatch evidence-id allow-list
    enforced by every tier-1 and tier-2 tool's resolver. The 2026-05-19
    multi-host run logged 11 ``*:rejected_wrong_artifact_class`` events
    where the analyst called a tier-1 tool with an evidence_id from a
    *sibling* host's findings (carried across via ``findings_by_host``).
    The allow-list short-circuits those before the (slower) CASE.yaml
    resolution and emits a distinct ``:rejected_evidence_id_out_of_scope``
    audit suffix so operators can grep cross-host id leakage
    independently of artifact-class mismatches. ``None`` leaves the
    allow-list unset (single-evidence runs and the validator dispatch,
    which legitimately needs every host's evidence_ids visible).

    The synthesized file lives under ``cwd / .mcp-dispatch /`` with a
    UUID suffix so concurrent workers can't collide. Cleanup is the
    caller's responsibility (``dispatch_subagent`` deletes it in
    ``finally`` once the subagent exits).

    Returns None on any failure (malformed base config, missing
    sift-guard entry, write error). The caller falls back to the base
    config in that case — host attribution degrades but the dispatch
    still proceeds.
    """
    try:
        content = json.loads(base_config_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning(
            "could not read base mcp config %s for host scoping: %s",
            base_config_path,
            exc,
        )
        return None
    servers = content.get("mcpServers")
    if not isinstance(servers, dict):
        return None
    sift_guard = servers.get("sift-guard")
    if not isinstance(sift_guard, dict):
        return None
    env_block = dict(sift_guard.get("env") or {})
    if host_id:
        env_block["SIFT_GUARD_HOST_ID"] = host_id
    if allowed_evidence_ids:
        env_block["SIFT_GUARD_ALLOWED_EVIDENCE_IDS"] = ",".join(allowed_evidence_ids)
    # ``role`` is the dispatched agent's name; the server's write/RAG
    # tools enforce role separation against it (SIFT_GUARD_ROLE gate
    # in server.tools.findings / correlations / rag).
    if role:
        env_block["SIFT_GUARD_ROLE"] = role
    sift_guard["env"] = env_block

    dispatch_dir = cwd / _DISPATCH_MCP_SUBDIR
    try:
        dispatch_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.warning("could not create %s for host scoping: %s", dispatch_dir, exc)
        return None
    out_path = dispatch_dir / f"{host_id or role or 'dispatch'}-{uuid.uuid4().hex[:8]}.json"
    try:
        out_path.write_text(json.dumps(content, indent=2), encoding="utf-8")
    except OSError as exc:
        logger.warning("could not write host-scoped mcp config %s: %s", out_path, exc)
        return None
    return out_path


class MCPServerNotAttachedError(RuntimeError):
    """Raised when a subagent's stream-json shows the sift-guard MCP
    server did NOT attach. The agent would still run — with the
    default Bash/Read/Write surface — but it would never see
    ``record_finding`` / ``vol_pslist`` / etc. Failing the dispatch
    is the architectural guardrail (failure-closed, per CLAUDE.md
    "Architectural guardrails > prompt guardrails")."""


def _extract_mcp_server_status(events: list[dict[str, Any]]) -> dict[str, str]:
    """Walk the stream-json events and return ``{server_name: status}``.

    Claude Code emits a ``system`` / ``init`` event near the top of
    every session with an ``mcp_servers`` field listing each
    configured server's connection status. We tolerate a few
    historical shapes (``mcpServers`` camelCase, top-level
    ``servers`` list with ``{name, status}`` dicts) so a Claude
    Code version bump doesn't silently break the check.
    """
    for event in events:
        if event.get("type") not in ("system", "init", "system_init"):
            continue
        # Shape 1: {"type": "system", "mcp_servers": [{"name": "...", "status": "connected"}]}
        for key in ("mcp_servers", "mcpServers"):
            servers = event.get(key)
            if isinstance(servers, list):
                return {
                    s["name"]: s.get("status", "unknown")
                    for s in servers
                    if isinstance(s, dict) and "name" in s
                }
            if isinstance(servers, dict):
                return {
                    name: (info.get("status", "unknown") if isinstance(info, dict) else "unknown")
                    for name, info in servers.items()
                }
        # Shape 2: nested under "subtype" payload (rarer).
        nested = event.get("subtype")
        if isinstance(nested, dict):
            for key in ("mcp_servers", "mcpServers"):
                servers = nested.get(key)
                if isinstance(servers, list):
                    return {
                        s["name"]: s.get("status", "unknown")
                        for s in servers
                        if isinstance(s, dict) and "name" in s
                    }
    return {}


@dataclass
class DispatchResult:
    agent: str
    session_id: str | None
    stop_reason: str | None
    num_turns: int
    duration_ms: int
    duration_api_ms: int
    total_cost_usd: float
    input_tokens: int
    cache_creation_input_tokens: int
    cache_read_input_tokens: int
    output_tokens: int
    tokens_uncached: int
    final_text: str
    # MCP-server attach status as reported by the subagent's
    # stream-json ``system`` init event. Empty dict means the event
    # was missing or unparseable (treated as not-attached).
    mcp_server_status: dict[str, str] = field(default_factory=dict)
    raw_events: list[dict[str, Any]] = field(default_factory=list)

    # States Claude Code emits in the system/init event that mean
    # "the .mcp.json was loaded and the server is at worst still
    # finishing its handshake." `pending` is the common case for
    # locally-spawned stdio servers because Claude Code emits init
    # before every MCP server has finished attaching; tool calls
    # later in the stream still succeed once the handshake lands.
    # The 2026-05-12 SRL-2015 v4 incident burned a whole rate-limit
    # window because the guard treated `pending` as failure and
    # bailed every subagent in <20s.
    _MCP_ATTACHED_STATES = frozenset(
        {"connected", "pending", "attached", "ready", "ok"}
    )

    @property
    def sift_guard_mcp_attached(self) -> bool:
        """True iff the subagent's init event listed sift-guard in a
        non-failed state. Missing-from-dict is treated as
        not-attached (catches the original ``--mcp-config not
        passed`` bug); explicit ``failed`` / ``needs-auth`` /
        ``error`` states are also treated as not-attached. Mid-
        handshake states (``pending``, ``connected``, ``attached``,
        ``ready``, ``ok``) all count as attached for guard
        purposes."""
        status = self.mcp_server_status.get("sift-guard")
        if status is None:
            return False
        return status in self._MCP_ATTACHED_STATES

    @property
    def sift_guard_tool_calls(self) -> int:
        """How many ``mcp__sift-guard__*`` tool calls the subagent
        actually issued in its stream. Zero means the subagent
        produced its answer WITHOUT touching the evidence — the
        confabulation failure mode.

        The 2026-07-15 Rocba incident: with the sift-guard tools
        surfaced as *deferred* and ``ToolSearch`` missing from the
        agent frontmatter allow-lists, no subagent could load its
        own tools. Rather than erroring, every analyst fabricated a
        plausible finding set in a single turn (different invented
        PIDs each run) and the orchestrator accepted the empty
        chain as a clean ``0 findings`` result — a compromised host
        reported as clean. The attach check above did not catch it:
        the server *was* attached; it was simply never called."""
        count = 0
        for event in self.raw_events:
            if event.get("type") != "assistant":
                continue
            content = event.get("message", {}).get("content", [])
            if not isinstance(content, list):
                continue
            for block in content:
                if (
                    isinstance(block, dict)
                    and block.get("type") == "tool_use"
                    and str(block.get("name", "")).startswith("mcp__sift-guard__")
                ):
                    count += 1
        return count

    @property
    def succeeded(self) -> bool:
        # Fail-closed on MCP-attach: a run with no sift-guard MCP is
        # not a successful analyst dispatch even when stop_reason
        # says end_turn. The 2026-05-12 SRL-2015 incident burned a
        # full multi-hour run on eight subagents whose MCP attach
        # was missing; surfacing the failure here is the architectural
        # guardrail that prevents a repeat.
        if not self.sift_guard_mcp_attached:
            return False
        # Fail-closed on zero tool calls: a subagent that attached the
        # server but never called a single sift-guard tool did not
        # analyze the evidence — it confabulated. Treating that as a
        # successful "0 findings" is the dangerous silent failure the
        # 2026-07-15 Rocba incident exposed. An analysis that legitimately
        # finds nothing still calls tools to reach that conclusion, so a
        # true-zero-tool-call run is always a failure.
        if self.sift_guard_tool_calls == 0:
            return False
        return self.stop_reason in ("end_turn", "tool_use", "stop_sequence")


# Per-agent mcp__sift-guard__* tool list, mirroring each agent's
# frontmatter ``tools:`` block. Used to construct the
# schema-preload preamble at the top of every dispatched prompt:
# Claude Code surfaces MCP tools as *deferred* (the schema is not
# preloaded; agents must call ``ToolSearch`` first), and analyst
# system prompts on their own do not know this protocol. Without
# the preamble, subagents skip the MCP layer entirely and fall
# through to the default Bash surface — the 2026-05-12 SRL v6
# incident (12 dispatches × ~600s each, 0 MCP tool calls, 0
# findings).
_AGENT_MCP_TOOLS: dict[str, tuple[str, ...]] = {
    "process_analyst": (
        "register_evidence",
        "vol_pslist",
        "vol_psscan",
        "vol_pstree",
        "vol_cmdline",
        "vol_malfind",
        "query_records",
        "group_by",
        "set_difference",
        "subtree",
        "record_finding",
    ),
    "network_analyst": (
        "register_evidence",
        "vol_netscan",
        "query_records",
        "group_by",
        "record_finding",
    ),
    "disk_analyst": (
        "register_evidence",
        "disk_mft_timeline",
        "disk_prefetch",
        "disk_evtx",
        "disk_registry",
        "query_records",
        "group_by",
        "set_difference",
        "subtree",
        "record_finding",
    ),
    "validator": (
        "register_evidence",
        "vol_pslist",
        "vol_psscan",
        "vol_pstree",
        "vol_netscan",
        "query_records",
        "group_by",
        "set_difference",
        "subtree",
        "record_correlation",
        "rag_query",
    ),
}


def _schema_preload_preamble(agent: str) -> str:
    """Build the leading instruction that tells the model to batch-load
    every mcp__sift-guard__* tool's JSON schema via ToolSearch
    before doing anything else. Returns '' for unknown agents."""
    tools = _AGENT_MCP_TOOLS.get(agent)
    if not tools:
        return ""
    select_arg = ",".join(f"mcp__sift-guard__{t}" for t in tools)
    return (
        "**TOOL SCHEMA PRELOAD — RUN BEFORE ANYTHING ELSE.**\n\n"
        "Your `mcp__sift-guard__*` tools are surfaced as *deferred* "
        "tools by Claude Code: each appears in your tool list but "
        "its JSON schema is not preloaded, so calling one directly "
        "fails with `InputValidationError: schema not loaded`. "
        "Your very first action MUST be a single `ToolSearch` call "
        "that selects every mcp__sift-guard__* tool you may need.\n\n"
        f"Call exactly this once:\n\n"
        f"    ToolSearch(query=\"select:{select_arg}\", "
        f"max_results={len(tools)})\n\n"
        "After it returns, every listed tool becomes callable "
        "directly. Do NOT skip this step. Do NOT fall back to Bash "
        "or any other shell-based parser when an MCP tool exists "
        "for the task — Bash invocations do not enter the audit "
        "chain, do not produce evidence_refs the validator can "
        "cite, and findings recorded from Bash output cannot pass "
        "schema validation. Every tool-derived observation in this "
        "session MUST come from an mcp__sift-guard__* call.\n"
    )


def _build_prompt(
    *,
    agent: str,
    evidence_id: str,
    case_id: str,
    iteration_number: int,
    focus_context: dict[str, Any] | None = None,
    findings_summary: list[dict[str, Any]] | None = None,
    host_id: str | None = None,
    host_label: str | None = None,
    host_grouped_findings: list[dict[str, Any]] | None = None,
) -> str:
    """Construct the structured user message for the subagent.

    The shape varies by agent role:
      - process_analyst / network_analyst / disk_analyst: evidence_id
        (+ optional focus_context, + optional host context). They
        discover findings independently.
      - validator: evidence_id, case_id, iteration_number,
        findings_summary OR host_grouped_findings. The findings input
        is the list of DRAFT findings to correlate (filtered to
        exclude CONFIRMED). When `host_grouped_findings` is provided
        (run-case mode), the prompt presents one ``=== Findings from
        host: ===`` block per host so the validator can read shared
        indicators across hosts at a glance.

    `host_id` / `host_label` are populated by the multi-evidence
    orchestrator and produce a "You are analyzing evidence from
    host: <label> (<id>)" line at the top of the analyst prompt.
    Single-evidence runs leave them None and emit no host line.
    """
    lines = [
        f"evidence_id: {evidence_id}",
        f"case_id: {case_id}",
        f"iteration_number: {iteration_number}",
    ]
    if host_id is not None:
        lines.append(f"host_id: {host_id}")
    if host_label is not None and host_label != host_id:
        lines.append(f"host_label: {host_label}")
    if focus_context is not None:
        lines.append(f"focus_context: {json.dumps(focus_context)}")
    if host_grouped_findings is not None:
        # Host-grouped block. Each entry is
        # {host_id, host_label, findings: [...]} — formatted for
        # readability rather than re-JSON'd, so the validator's
        # in-prompt scan sees host blocks the way the user spec'd.
        lines.append("findings_by_host:")
        for block in host_grouped_findings:
            host_text = (
                f"  === Findings from host: "
                f"{block.get('host_label', block['host_id'])} "
                f"({block['host_id']}) ==="
            )
            lines.append(host_text)
            lines.append(json.dumps(block.get("findings", []), indent=2))
    elif findings_summary is not None:
        lines.append("findings_summary:")
        lines.append(json.dumps(findings_summary, indent=2))

    role_intros = {
        "process_analyst": ("Analyze the registered Windows memory image for process anomalies."),
        "network_analyst": ("Analyze the registered Windows memory image for network anomalies."),
        "disk_analyst": (
            "Analyze the registered Windows disk image for filesystem, "
            "execution, event-log, and registry anomalies."
        ),
        "validator": (
            "Validate the DRAFT findings below by emitting correlations. "
            "You see only DRAFT-state findings; CONFIRMED findings are out "
            "of scope for this iteration.\n"
            "Before emitting a corroborates or contradicts correlation for "
            "any finding, call rag_query to check for matching ATT&CK "
            "techniques or Sigma detection rules. Cite the audit_line from "
            "the rag_query result in your correlation."
        ),
    }
    intro = role_intros.get(agent, f"Run as {agent}.")
    if host_id is not None and agent != "validator":
        # Multi-evidence (run-case) analyst dispatch surfaces the host
        # context at the top of the prompt — separate from the
        # structured key/value lines the agent parses for tool calls.
        host_text = host_label or host_id
        intro = f"You are analyzing evidence from host: {host_text} ({host_id}).\n" + intro
    if agent == "validator" and host_grouped_findings is not None:
        # The cross-host extension is communicated to the validator
        # at run-time (in-prompt) rather than pinned in
        # validator.md, so the same agent file works for both
        # single-evidence and run-case modes.
        intro = (
            intro + "\n\n"
            "Multi-host case: findings span multiple hosts (see "
            "`findings_by_host` below). When you see two findings "
            "on different hosts that share a load-bearing indicator "
            "(an IP address, a binary hash, a synchronized timestamp, "
            "a named MITRE ATT&CK technique), emit a correlation with "
            '`correlation_type="cross_host"`, list every involved '
            "host_id in `host_ids`, and capture the shared indicator "
            "in `shared_indicator` (e.g. "
            '`{"type": "ip", "value": "10.3.58.42"}`). '
            "Cross-host correlations are independent-source corroborations "
            "and feed the same R3 strong-corroboration promotion path."
        )
    preamble = _schema_preload_preamble(agent)
    body = intro + "\n" + "\n".join(lines)
    return preamble + "\n" + body if preamble else body


def _parse_stream_json(stdout: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse the subprocess stdout into (events, final_result).

    final_result is the {"type":"result"} event; if absent, returns
    an empty dict and the caller treats the dispatch as failed.
    """
    events: list[dict[str, Any]] = []
    final: dict[str, Any] = {}
    for raw in stdout.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
        except (ValueError, TypeError):
            logger.debug("non-JSON line in stream-json: %r", stripped[:200])
            continue
        events.append(event)
        if isinstance(event, dict) and event.get("type") == "result":
            final = event
    return events, final


def _extract_final_text(events: list[dict[str, Any]]) -> str:
    """The last assistant message's text content, if any. Best-effort
    — the audit chain + findings.jsonl are the authoritative outputs.
    """
    for event in reversed(events):
        if event.get("type") == "assistant":
            msg = event.get("message", {})
            content = msg.get("content", [])
            if isinstance(content, list):
                texts = [
                    block.get("text", "")
                    for block in content
                    if isinstance(block, dict) and block.get("type") == "text"
                ]
                if texts:
                    return "\n".join(texts).strip()
    return ""


def dispatch_subagent(
    agent: str,
    prompt: str,
    *,
    cwd: Path,
    max_budget_usd: float = 5.0,
    timeout_seconds: int = 1800,
    host_id: str | None = None,
    allowed_evidence_ids: list[str] | None = None,
) -> DispatchResult:
    """Spawn `claude -p --agent <name>` and capture the run.

    The subagent's frontmatter restricts its tool surface; the parent
    process role here is purely transport — start it, wait for the
    result event, return token + timing metadata.

    When ``host_id`` is set, a per-dispatch .mcp.json is synthesized
    that adds ``SIFT_GUARD_HOST_ID=<host_id>`` to the sift-guard
    server's ``env`` block, so every ``record_finding`` call from this
    dispatch is server-side attributed to the dispatched host
    regardless of what the analyst supplies. Architectural guardrail
    per CLAUDE.md Hard Rule #2: host attribution must not depend on
    the analyst remembering to pass ``host_id``. ``None`` preserves
    the single-evidence path (no host scoping).

    Failure modes:
      - Subprocess timeout → DispatchResult with stop_reason="timeout"
        and partial token usage / events reconstructed from the
        captured stdout up to the kill. Findings already in
        findings.jsonl are picked up by the loop's
        ``_count_draft_finding_ids_for`` delta; this dispatch is
        marked unsucceeded so the orchestrator can warn.
      - Non-zero exit → DispatchResult with stop_reason=None.
      - Missing result event (truncated stream) → same.

    All three propagate as DispatchResult.succeeded == False; the
    caller decides how to react.
    """
    # ``--mcp-config`` is variadic (``<configs...>`` per claude --help)
    # so it greedily consumes subsequent argv elements as additional
    # config paths until it sees a recognized flag. Place it at the
    # start (immediately after ``claude -p``) so the following
    # ``--agent`` token terminates the variadic capture cleanly.
    # The prompt MUST be the final positional and must be preceded
    # by a fixed-arity flag (``--max-budget-usd <amount>``) — never
    # adjacent to ``--mcp-config``. See 2026-05-12 SRL re-run logs
    # where the wrong argv order caused every dispatch to fail with
    # ``MCP config file not found: /home/sansforensics/evidence_id:…``
    # (the prompt itself was being interpreted as a config path).
    cmd: list[str] = ["claude", "-p"]
    base_mcp_config = resolve_mcp_config_path()
    mcp_config = base_mcp_config
    synthesized_mcp_config: Path | None = None
    if base_mcp_config is not None:
        synthesized_mcp_config = _synthesize_host_scoped_mcp_config(
            base_mcp_config,
            cwd,
            host_id,
            allowed_evidence_ids=allowed_evidence_ids,
            role=agent,
        )
        if synthesized_mcp_config is not None:
            mcp_config = synthesized_mcp_config
    if mcp_config is not None:
        cmd.extend(["--mcp-config", str(mcp_config)])
    else:
        logger.warning(
            "no .mcp.json located; subagent %s will start without sift-guard MCP "
            "tools and will be flagged as not-attached after dispatch",
            agent,
        )
    cmd.extend(
        [
            "--agent",
            agent,
            "--output-format",
            "stream-json",
            "--verbose",
            "--permission-mode",
            "bypassPermissions",
            "--max-budget-usd",
            str(max_budget_usd),
            prompt,
        ]
    )
    logger.info(
        "dispatching subagent %s (cwd=%s, mcp_config=%s)",
        agent,
        cwd,
        mcp_config,
    )

    # Bump claude's per-server MCP connection timeout. The default
    # is 30000ms; the sift-guard MCP server cold-start on the SIFT
    # 2026.1 image measures ~7s for a single instance and climbs to
    # 20-30s under the parallel-analyst case (3-12 stdio MCP servers
    # importing the schema graph + pydantic + the Volatility 3 typing
    # stubs simultaneously, all racing for CPU). The 2026-05-14
    # SRL-test-xp run hit this: every analyst's MCP connection timed
    # out at exactly 30000ms, the analyst saw "no MCP tools attached"
    # and returned 0 findings without touching evidence. 120s is safe
    # headroom on a cold parallel start; operators can override by
    # exporting MCP_TIMEOUT before invoking sift-guard.
    subprocess_env = dict(os.environ)
    subprocess_env.setdefault("MCP_TIMEOUT", "120000")

    try:
        try:
            proc = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                env=subprocess_env,
            )
        except subprocess.TimeoutExpired as exc:
            # Best-effort partial-result reconstruction. The 2026-05-19
            # multi-host run logged two ``subagent disk_analyst timed
            # out after 3600s`` events for nfury and nromanoff in
            # iteration 1, and both were attributed ``0 new findings``
            # — yet ``subprocess.TimeoutExpired`` carries the captured
            # stdout/stderr up to the kill in ``exc.output``. Findings
            # the subagent already committed are in findings.jsonl
            # already; what we lose by treating the timeout as
            # all-zero is the streaming event log (tool-call usage,
            # session id, partial token usage). Parse what we have and
            # populate the DispatchResult so the iteration summary
            # reflects whatever work actually happened.
            partial_stdout = exc.output or ""
            partial_events, _ = _parse_stream_json(partial_stdout)
            # Sum input/output/cache tokens across all assistant turns
            # in the partial stream. The schema is the same as the
            # final-result aggregate, just split across N message
            # events; ``_parse_stream_json`` already kept every line.
            partial_input_tok = 0
            partial_cc_tok = 0
            partial_cr_tok = 0
            partial_out_tok = 0
            session_id: str | None = None
            num_turns = 0
            for event in partial_events:
                if not isinstance(event, dict):
                    continue
                if session_id is None and isinstance(event.get("session_id"), str):
                    session_id = event["session_id"]
                if event.get("type") == "assistant":
                    num_turns += 1
                    usage = event.get("message", {}).get("usage", {}) or {}
                    partial_input_tok += int(usage.get("input_tokens", 0) or 0)
                    partial_cc_tok += int(usage.get("cache_creation_input_tokens", 0) or 0)
                    partial_cr_tok += int(usage.get("cache_read_input_tokens", 0) or 0)
                    partial_out_tok += int(usage.get("output_tokens", 0) or 0)
            partial_uncached = partial_input_tok + partial_cc_tok + partial_out_tok
            logger.error(
                "subagent %s timed out after %ds — reconstructed "
                "%d event(s), %d assistant turn(s), %d uncached "
                "token(s) from partial stdout; any findings already "
                "committed to findings.jsonl are picked up by the "
                "post-dispatch finding-count delta in the loop",
                agent,
                timeout_seconds,
                len(partial_events),
                num_turns,
                partial_uncached,
            )
            return DispatchResult(
                agent=agent,
                session_id=session_id,
                # Sentinel stop_reason so the orchestrator and the
                # CLI display can distinguish "timed out with no
                # final-result event" from "completed cleanly with
                # stop_reason=end_turn".
                stop_reason="timeout",
                num_turns=num_turns,
                duration_ms=timeout_seconds * 1000,
                duration_api_ms=0,
                total_cost_usd=0.0,
                input_tokens=partial_input_tok,
                cache_creation_input_tokens=partial_cc_tok,
                cache_read_input_tokens=partial_cr_tok,
                output_tokens=partial_out_tok,
                tokens_uncached=partial_uncached,
                final_text="",
                raw_events=partial_events,
            )
    finally:
        if synthesized_mcp_config is not None:
            try:
                synthesized_mcp_config.unlink()
            except OSError:
                pass

    events, final = _parse_stream_json(proc.stdout)
    if not final:
        logger.error(
            "subagent %s emitted no result event (returncode=%s)",
            agent,
            proc.returncode,
        )

    # Architectural guardrail: confirm the sift-guard MCP server
    # actually attached. Without it the subagent has no
    # `record_finding`/`vol_*`/`disk_*` tools and the run silently
    # produces zero findings (the 2026-05-12 SRL-2015 incident).
    # We fail-closed: the dispatch is marked unsucceeded so the
    # orchestrator can warn and stop rather than burn tokens on
    # eight subagents that won't write anything.
    server_status = _extract_mcp_server_status(events)
    sift_status = server_status.get("sift-guard")
    if sift_status not in DispatchResult._MCP_ATTACHED_STATES:
        logger.error(
            "subagent %s started without sift-guard MCP attached "
            "(sift_guard_status=%r, mcp_servers=%s); marking "
            "dispatch unsucceeded so findings-less runs surface "
            "immediately",
            agent,
            sift_status,
            server_status or "<no init event>",
        )

    usage = final.get("usage", {}) if final else {}
    input_tok = int(usage.get("input_tokens", 0))
    cc_tok = int(usage.get("cache_creation_input_tokens", 0))
    cr_tok = int(usage.get("cache_read_input_tokens", 0))
    out_tok = int(usage.get("output_tokens", 0))

    return DispatchResult(
        agent=agent,
        session_id=final.get("session_id"),
        stop_reason=final.get("stop_reason"),
        num_turns=int(final.get("num_turns", 0)),
        duration_ms=int(final.get("duration_ms", 0)),
        duration_api_ms=int(final.get("duration_api_ms", 0)),
        total_cost_usd=float(final.get("total_cost_usd", 0.0)),
        input_tokens=input_tok,
        cache_creation_input_tokens=cc_tok,
        cache_read_input_tokens=cr_tok,
        output_tokens=out_tok,
        tokens_uncached=input_tok + cc_tok + out_tok,
        final_text=_extract_final_text(events),
        mcp_server_status=server_status,
        raw_events=events,
    )


# Per-analyst dispatch timeout defaults. The uniform 1800s ceiling
# was too tight for `disk_analyst`: log2timeline / plaso on a 13 GB
# E01 commonly takes 30-60 minutes for a single pass, and the
# 2026-05-13 SRL-v2 run had three disk dispatches hit the 1800s wall
# with plaso still mid-MFT. Memory-side analysts have no equivalent
# long-running tool — vol_* plugins finish in seconds to a couple
# minutes — so we keep their ceiling at 30 minutes. The validator
# can also run long under heavy correlation work; same default as
# the memory analysts.
#
# This is a stopgap. The architecturally cleaner fix is to
# pre-extract tier-1 disk outputs at preflight time so the analyst
# dispatch only does fast tier-2 queries against cached extractions.
# Tracking that as a follow-up.
_DEFAULT_TIMEOUT_BY_ANALYST: dict[str, int] = {
    "process_analyst": 1800,
    "network_analyst": 1800,
    "disk_analyst": 3600,
    "validator": 1800,
}
_DEFAULT_TIMEOUT_FALLBACK = 1800


def _default_timeout_for(agent: str) -> int:
    return _DEFAULT_TIMEOUT_BY_ANALYST.get(agent, _DEFAULT_TIMEOUT_FALLBACK)


def dispatch_analyst(
    agent: str,
    *,
    evidence_id: str,
    case_id: str,
    iteration_number: int,
    cwd: Path,
    focus_context: dict[str, Any] | None = None,
    host_id: str | None = None,
    host_label: str | None = None,
    max_budget_usd: float = 5.0,
    timeout_seconds: int | None = None,
) -> DispatchResult:
    """High-level dispatch for an analyst subagent.

    ``timeout_seconds=None`` (the default) picks a per-agent value
    from ``_DEFAULT_TIMEOUT_BY_ANALYST`` — disk_analyst gets a longer
    rope because plaso on a real disk image is slow. Pass an explicit
    integer to override per-call (e.g. for the CLI ``--analyst-timeout``
    flag if/when one is added).

    `host_id` / `host_label` populated by run-case orchestration —
    surface as a "You are analyzing evidence from host:" line at the
    top of the analyst's prompt. Single-evidence runs leave them
    None and the prompt is unchanged.

    The per-dispatch evidence-id allow-list is set to
    ``[evidence_id]`` — each analyst sees only the evidence it was
    dispatched against. Tier-1 and tier-2 tool calls with any other
    evidence_id short-circuit at the server with a distinct
    ``:rejected_evidence_id_out_of_scope`` audit suffix. The 2026-05-19
    multi-host run logged 11 ``*:rejected_wrong_artifact_class``
    events where the analyst carried an evidence_id across from a
    sibling host's findings; the allow-list eliminates that class
    of drift by construction.
    """
    if timeout_seconds is None:
        timeout_seconds = _default_timeout_for(agent)
    prompt = _build_prompt(
        agent=agent,
        evidence_id=evidence_id,
        case_id=case_id,
        iteration_number=iteration_number,
        focus_context=focus_context,
        host_id=host_id,
        host_label=host_label,
    )
    return dispatch_subagent(
        agent,
        prompt,
        cwd=cwd,
        max_budget_usd=max_budget_usd,
        timeout_seconds=timeout_seconds,
        host_id=host_id,
        allowed_evidence_ids=[evidence_id],
    )


def dispatch_validator(
    *,
    evidence_id: str,
    case_id: str,
    iteration_number: int,
    findings_summary: list[dict[str, Any]] | None = None,
    host_grouped_findings: list[dict[str, Any]] | None = None,
    cwd: Path,
    max_budget_usd: float = 5.0,
    timeout_seconds: int = 1800,
) -> DispatchResult:
    """High-level dispatch for the validator subagent.

    Either `findings_summary` (single-evidence) OR
    `host_grouped_findings` (run-case) must be set. When the
    host-grouped form is provided, the validator's prompt frames the
    findings as per-host blocks and gains the cross-host correlation
    instructions inline.
    """
    prompt = _build_prompt(
        agent="validator",
        evidence_id=evidence_id,
        case_id=case_id,
        iteration_number=iteration_number,
        findings_summary=findings_summary,
        host_grouped_findings=host_grouped_findings,
    )
    return dispatch_subagent(
        "validator",
        prompt,
        cwd=cwd,
        max_budget_usd=max_budget_usd,
        timeout_seconds=timeout_seconds,
    )


__all__ = [
    "DispatchResult",
    "dispatch_analyst",
    "dispatch_subagent",
    "dispatch_validator",
]
