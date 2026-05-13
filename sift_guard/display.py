"""Real-time progress display for the orchestrator loop.

Two input streams feed the same formatted stdout:

  1. **Coarse loop events** — the orchestrator's `on_progress`
     callback fires synchronously between dispatches:
     iteration_start, analyze_start/done, correlate_start/done,
     promote, plan, terminate. The CLI binds these directly.

  2. **Fine-grained MCP tool calls** — a daemon thread tails
     ``<case_dir>/audit/sift-guard-mcp.jsonl`` and renders one line
     per significant tool call (vol_*, query_records, rag_query,
     record_finding, record_correlation, update_finding). Per-row
     validation warnings are suppressed to keep output legible.

This is the entire user-facing surface during a 30-60 minute run.
The two streams are merged into a single FIFO renderer that holds
a `threading.Lock` while writing — interleaved lines stay
well-formed even under concurrent emit pressure.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO


_TICK_SECONDS = 0.4
_BAR = "═" * 60


def _hms() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _truncate(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    return s[: n - 1] + "…"


class ProgressDisplay:
    """Synchronous, thread-safe formatter for the loop's two
    progress streams.

    Usage::

        display = ProgressDisplay(case_dir, stream=sys.stdout)
        display.start_audit_tail()
        try:
            run_loop_multi_host(..., on_progress=display.on_event)
        finally:
            display.stop_audit_tail()

    Methods are safe to call from any thread; the inner write lock
    serializes line production.
    """

    def __init__(
        self,
        case_dir: Path,
        *,
        stream: TextIO | None = None,
        verbose: bool = False,
    ):
        self._case_dir = Path(case_dir)
        self._stream = stream or sys.stdout
        self._verbose = verbose
        self._write_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._tail_thread: threading.Thread | None = None
        self._iteration_label_for_audit = "—"
        # Counters used by terminate-time summary.
        self._counters = {
            "vol_calls": 0,
            "vol_cached": 0,
            "tier2_calls": 0,
            "rag_queries": 0,
            "findings": 0,
            "correlations": 0,
            "promotions": 0,
        }
        self._known_attack_techniques: set[str] = set()

    # ------------------------------------------------------------------
    # Output primitive
    # ------------------------------------------------------------------

    def _print(self, msg: str) -> None:
        with self._write_lock:
            self._stream.write(msg + "\n")
            self._stream.flush()

    # ------------------------------------------------------------------
    # Loop callback (synchronous, fires from the loop's main thread)
    # ------------------------------------------------------------------

    def on_event(self, event: str, payload: dict[str, Any]) -> None:
        handler = getattr(self, f"_evt_{event}", None)
        if handler is None:
            if self._verbose:
                self._print(f"[{_hms()}] EVENT  {event}  {json.dumps(payload, default=str)}")
            return
        try:
            handler(payload)
        except Exception as exc:  # noqa: BLE001 — observer must not crash loop
            self._print(f"[{_hms()}] WARN   display handler {event} crashed: {exc}")

    def _evt_iteration_start(self, payload: dict[str, Any]) -> None:
        n = payload.get("iteration", "?")
        cap = payload.get("max_iterations")
        cap_str = f"/{cap}" if cap else ""
        self._iteration_label_for_audit = f"iter {n}"
        self._print("")
        self._print(f"{_BAR}")
        self._print(f"  Iteration {n}{cap_str}")
        focus = payload.get("pending_host_ids")
        if focus:
            self._print(f"  Focused dispatch on hosts: {', '.join(focus)}")
        self._print(f"{_BAR}")

    def _evt_analyze_start(self, payload: dict[str, Any]) -> None:
        host = payload.get("host_label") or payload.get("host_id") or "?"
        analyst = payload.get("analyst", "analyst")
        focused = " (focused)" if payload.get("focused") else ""
        self._print(
            f"[{_hms()}] ANALYZE   │ {host:<14} │ {analyst:<17} → dispatching{focused}…"
        )

    def _evt_analyze_done(self, payload: dict[str, Any]) -> None:
        host = payload.get("host_label") or payload.get("host_id") or "?"
        analyst = payload.get("analyst", "analyst")
        added = int(payload.get("findings_added", 0))
        tokens = int(payload.get("tokens_uncached", 0))
        ms = int(payload.get("duration_ms", 0))
        ok = bool(payload.get("succeeded", True))
        mark = "✓" if ok else "✗"
        suffix = "" if ok else f"  stop_reason={payload.get('stop_reason')}"
        self._print(
            f"[{_hms()}] ANALYZE   │ {host:<14} │ {analyst:<17} → "
            f"{added} new finding(s), {tokens:,} tokens uncached, "
            f"{ms / 1000:.0f}s {mark}{suffix}"
        )

    def _evt_host_skip(self, payload: dict[str, Any]) -> None:
        host = payload.get("host_label") or payload.get("host_id") or "?"
        self._print(
            f"[{_hms()}] SKIP      │ {host:<14} │ unknown evidence_type "
            f"{payload.get('evidence_type')!r}"
        )

    def _evt_correlate_start(self, payload: dict[str, Any]) -> None:
        n = payload.get("draft_findings", 0)
        h = payload.get("host_count", 0)
        self._print(
            f"[{_hms()}] CORRELATE │ validator       → "
            f"dispatching with {n} DRAFT finding(s) across {h} host(s)…"
        )

    def _evt_correlate_skip(self, payload: dict[str, Any]) -> None:
        reason = payload.get("reason", "unknown")
        self._print(f"[{_hms()}] CORRELATE │ validator       → skipped ({reason})")

    def _evt_correlate_done(self, payload: dict[str, Any]) -> None:
        added = int(payload.get("correlations_added", 0))
        cross = int(payload.get("cross_host", 0))
        tokens = int(payload.get("tokens_uncached", 0))
        ms = int(payload.get("duration_ms", 0))
        ok = bool(payload.get("succeeded", True))
        mark = "✓" if ok else "✗"
        cross_str = f", {cross} cross-host" if cross else ""
        self._print(
            f"[{_hms()}] CORRELATE │ validator       → "
            f"{added} correlation(s){cross_str}, {tokens:,} tokens, "
            f"{ms / 1000:.0f}s {mark}"
        )

    def _evt_promote(self, payload: dict[str, Any]) -> None:
        rule_counts = payload.get("rule_counts") or {}
        if not rule_counts:
            self._print(f"[{_hms()}] PROMOTE   │ (no promotions this iteration)")
            return
        rendered = ", ".join(
            f"{rule} × {n}" for rule, n in sorted(rule_counts.items()) if n
        )
        applied = int(payload.get("applied", 0))
        total = int(payload.get("total", 0))
        self._print(
            f"[{_hms()}] PROMOTE   │ {rendered}   ({applied}/{total} applied)"
        )

    def _evt_plan(self, payload: dict[str, Any]) -> None:
        decision = payload.get("decision", "")
        next_hosts = payload.get("next_host_ids") or []
        followups = int(payload.get("followups_consumed", 0))
        if decision == "terminate":
            return  # iteration_done + terminate carry the message
        if next_hosts:
            self._print(
                f"[{_hms()}] PLAN      │ request_followup → "
                f"{', '.join(next_hosts)}  ({followups} followup(s))"
            )
        else:
            self._print(
                f"[{_hms()}] PLAN      │ continue (no host-scoped followups)"
            )

    def _evt_iteration_done(self, payload: dict[str, Any]) -> None:
        # Subtle one-line iteration footer. The next iteration's
        # banner is the visual separator.
        if self._verbose:
            cum = int(payload.get("cumulative_tokens_uncached", 0))
            self._print(
                f"[{_hms()}] iter {payload.get('iteration')} done  "
                f"(cumulative {cum:,} uncached tokens)"
            )

    def _evt_terminate(self, payload: dict[str, Any]) -> None:
        reason = payload.get("reason", "unknown")
        self._print("")
        self._print(f"[{_hms()}] TERMINATE │ {reason}")

    # ------------------------------------------------------------------
    # Audit-tail thread — fires for fine-grained MCP tool calls
    # ------------------------------------------------------------------

    def start_audit_tail(self) -> None:
        if self._tail_thread is not None:
            return
        self._stop_event.clear()
        self._tail_thread = threading.Thread(
            target=self._audit_tail_loop,
            name="sift-guard-audit-tail",
            daemon=True,
        )
        self._tail_thread.start()

    def stop_audit_tail(self) -> None:
        self._stop_event.set()
        if self._tail_thread is not None:
            # Best-effort join; the polling loop wakes once per
            # _TICK_SECONDS so this returns within ~half a second.
            self._tail_thread.join(timeout=2.0)
            self._tail_thread = None

    def _audit_tail_loop(self) -> None:
        audit_path = self._case_dir / "audit" / "sift-guard-mcp.jsonl"
        offset = 0
        # If the file already exists when we start, skip everything
        # already written so we only render NEW activity. The
        # registration-time lines were already produced
        # synchronously by the CLI's own register_evidence calls.
        if audit_path.exists():
            try:
                offset = audit_path.stat().st_size
            except OSError:
                offset = 0
        while not self._stop_event.is_set():
            try:
                if not audit_path.exists():
                    self._stop_event.wait(_TICK_SECONDS)
                    continue
                size = audit_path.stat().st_size
                if size <= offset:
                    self._stop_event.wait(_TICK_SECONDS)
                    continue
                with audit_path.open("rb") as f:
                    f.seek(offset)
                    chunk = f.read(size - offset)
                    offset = size
                # Hand the new bytes off to the renderer. The
                # remainder (a trailing partial line) is unlikely
                # in the project's atomic-append writer, but we
                # defensively requeue any incomplete tail.
                text = chunk.decode("utf-8", errors="replace")
                lines = text.splitlines(keepends=False)
                if text and not text.endswith("\n"):
                    # Last line is incomplete — back off offset to
                    # re-read it next tick.
                    offset -= len(lines[-1].encode("utf-8"))
                    lines = lines[:-1]
                for raw in lines:
                    self._render_audit_line(raw)
            except Exception as exc:  # noqa: BLE001
                self._print(f"[{_hms()}] WARN   audit tail: {exc}")
                self._stop_event.wait(_TICK_SECONDS)

    def _render_audit_line(self, raw: str) -> None:
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            return
        tool = str(entry.get("tool_name") or "")
        if not tool:
            return
        if tool.endswith(":record_validation_warning"):
            # Per-row validator warnings are noisy during cold
            # extractions; suppress them in the live display. They
            # remain in the audit chain.
            return

        # Bookkeeping for the post-run summary line.
        if tool.startswith("vol_") and ":" not in tool:
            self._counters["vol_calls"] += 1
        elif tool.endswith(":cached") and tool.startswith("vol_"):
            self._counters["vol_cached"] += 1
        elif tool in {"query_records", "group_by", "set_difference", "subtree"}:
            self._counters["tier2_calls"] += 1
        elif tool.startswith("rag_query"):
            self._counters["rag_queries"] += 1
        elif tool == "record_finding":
            self._counters["findings"] += 1
        elif tool == "record_correlation":
            self._counters["correlations"] += 1
        elif tool == "update_finding":
            self._counters["promotions"] += 1

        line = self._format_audit_line(tool, entry)
        if line is not None:
            self._print(line)

    def _format_audit_line(self, tool: str, entry: dict[str, Any]) -> str | None:
        ts = _hms()
        evidence_id = str(entry.get("evidence_id") or "")
        short_eid = evidence_id[:8] if evidence_id else "—"

        if tool == "register_evidence":
            return None  # registration is already echoed by the CLI

        if tool.startswith("vol_") and ":" not in tool:
            return f"[{ts}]  · MCP   │ {tool:<14} on evidence {short_eid}"
        if tool.endswith(":cached") and tool.startswith("vol_"):
            base = tool.split(":", 1)[0]
            return f"[{ts}]  · MCP   │ {base:<14} (cached) on {short_eid}"
        if tool.endswith(":hash_mismatch"):
            base = tool.split(":", 1)[0]
            return f"[{ts}]  ! MCP   │ {base} hash_mismatch on {short_eid}"
        if ":rejected_" in tool:
            # The hash-chained audit log stores only `input_hash`, not
            # the offending payload — so `entry.get('input_args')` is
            # always None for rejection lines. The side-channel debug
            # log `audit/rejections.jsonl` carries a sanitized copy
            # keyed by audit-chain line_number. Look up the matching
            # record and render a compact preview of the offending
            # input; fall back to the old behavior if the side-channel
            # is missing (older runs, or rejections written by tools
            # that don't route through it).
            line_no = entry.get("line_number")
            redacted = self._lookup_redacted_input(line_no) if line_no else None
            if redacted:
                return (
                    f"[{ts}]  ! MCP   │ {tool} "
                    f"input={_truncate(self._compact_rejected_input(redacted), 80)}"
                )
            return f"[{ts}]  ! MCP   │ {tool} (input=unavailable)"

        if tool in {"query_records", "group_by", "set_difference", "subtree"}:
            args = entry.get("input_args") or {}
            args_str = self._compact_args(args)
            return f"[{ts}]  · MCP   │ {tool:<14} {args_str}"

        if tool.startswith("rag_query"):
            args = entry.get("input_args") or {}
            output = entry.get("output") or {}
            tids = self._extract_attack_ids(args, output)
            if tids:
                self._known_attack_techniques.update(tids)
                return f"[{ts}]  · MCP   │ rag_query     {','.join(sorted(tids))}"
            qv = args.get("technique_id") or args.get("semantic_query") or ""
            return f"[{ts}]  · MCP   │ rag_query     {_truncate(str(qv), 60)}"

        if tool == "record_finding":
            # `AuditLogEntry` carries only `output_hash`; the
            # operator-facing fields (title, confidence, host_id) live
            # in the findings chain under `finding`. Join the two by
            # matching the audit entry's `output_hash` to the finding
            # entry's `this_finding_hash` (set by the writer in
            # `record_finding`). Fall back to placeholders if the
            # findings chain isn't readable.
            output_hash = entry.get("output_hash")
            finding = (
                self._lookup_finding_by_hash(output_hash) if output_hash else None
            )
            title = str((finding or {}).get("title") or "")
            conf = (finding or {}).get("confidence") or "?"
            host = (finding or {}).get("host_id") or "—"
            return (
                f"[{ts}]  + FIND  │ {conf:<8} host={host:<12} "
                f"{_truncate(title, 70)}"
            )

        if tool == "record_correlation":
            output = entry.get("output") or {}
            ctype = output.get("correlation_type") or "?"
            strength = output.get("strength") or output.get("severity") or ""
            return f"[{ts}]  + CORR  │ {ctype:<16} {strength}"

        if tool == "update_finding":
            output = entry.get("output") or {}
            rule = output.get("promotion_rule") or "?"
            new_state = output.get("new_state") or ""
            new_conf = output.get("new_confidence") or ""
            return f"[{ts}]  ↑ PROMO │ {rule:<3} → {new_state}/{new_conf}"

        if self._verbose:
            return f"[{ts}]  · MCP   │ {tool}"
        return None

    @staticmethod
    def _compact_args(args: dict[str, Any]) -> str:
        # Render at most three tier-2 arg fields the operator cares
        # about (plugin, key, axis, projection-len). Avoid dumping
        # raw JSON for every line.
        bits: list[str] = []
        for k in ("plugin", "plugin_a", "plugin_b", "key", "axis", "direction"):
            if k in args:
                bits.append(f"{k}={args[k]}")
        if "projection" in args and args["projection"]:
            bits.append(f"projection={len(args['projection'])}f")
        return " ".join(bits) if bits else ""

    @staticmethod
    def _compact_rejected_input(redacted: dict[str, Any]) -> str:
        # Highlight the fields an operator scanning a rejection most
        # often needs: the tool's main targets and any unknown_field
        # offenders. Falls back to a JSON-ish summary for everything
        # else.
        bits: list[str] = []
        for k in (
            "plugin",
            "plugin_a",
            "plugin_b",
            "key",
            "axis",
            "category",
            "severity",
            "confidence",
            "analyst",
        ):
            v = redacted.get(k)
            if isinstance(v, (str, int, float, bool)):
                bits.append(f"{k}={v}")
        filt = redacted.get("filter")
        if isinstance(filt, dict) and "field" in filt:
            bits.append(f"filter.field={filt.get('field')}")
        proj = redacted.get("projection")
        if isinstance(proj, list) and proj:
            preview = ",".join(str(p) for p in proj[:3])
            suffix = "…" if len(proj) > 3 else ""
            bits.append(f"projection=[{preview}{suffix}]")
        refs = redacted.get("evidence_refs")
        if isinstance(refs, list) and refs:
            bits.append(f"refs={len(refs)}")
        if bits:
            return " ".join(bits)
        # Final fallback: short JSON snapshot. Keeps the line
        # informative even for tools we haven't tuned a compact
        # rendering for.
        try:
            return json.dumps(redacted, default=str, sort_keys=True)[:100]
        except (TypeError, ValueError):
            return repr(redacted)[:100]

    def _lookup_redacted_input(self, line_number: int) -> dict[str, Any] | None:
        """Find the side-channel rejection record matching an audit
        line. Linear scan from the bottom of the file — the rejections
        we want are almost always the last few entries (we're
        rendering live). Returns None on any IO error so the formatter
        falls back to ``input=unavailable`` rather than crashing.

        The audit chain entry is written before the side-channel
        record (the audit chain is the authoritative log; the
        side-channel is debug). When the audit tail thread polls
        immediately after a rejection, it can read the audit line
        before ``rejections.jsonl`` has been flushed — particularly
        on the *first* rejection of a run, when the file may not yet
        exist. One short retry covers that window without bloating
        rendering latency for the common case.
        """
        for attempt in range(2):
            hit = self._read_rejection_record(line_number)
            if hit is not None:
                return hit
            if attempt == 0:
                time.sleep(0.1)
        return None

    def _read_rejection_record(
        self, line_number: int
    ) -> dict[str, Any] | None:
        path = self._case_dir / "audit" / "rejections.jsonl"
        if not path.exists():
            return None
        try:
            with path.open("r", encoding="utf-8") as f:
                tail: list[str] = f.readlines()[-200:]
        except OSError:
            return None
        for raw in reversed(tail):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                rec = json.loads(stripped)
            except ValueError:
                continue
            if rec.get("line_number") == line_number:
                ri = rec.get("redacted_input")
                if isinstance(ri, dict):
                    return ri
                return None
        return None

    def _lookup_finding_by_hash(
        self, output_hash: str
    ) -> dict[str, Any] | None:
        """Find the finding-chain entry that hashes to the audit
        entry's ``output_hash``.

        Join: ``server.audit.append_audit_entry`` writes
        ``output_hash = sha256(output.model_dump_json().encode())``
        where ``output`` is the ``FindingChainEntry``. The findings
        log writes the same bytes
        (``entry.model_dump_json() + "\\n"``) per line. So the
        matching findings.jsonl line is the one whose stripped text,
        when SHA-256'd, equals the audit entry's ``output_hash``.

        We can't join on ``this_finding_hash``: that's hashed over
        the finding's payload *excluding* ``this_finding_hash``
        itself (chain semantics), so it doesn't equal the
        whole-entry digest the audit chain stores.

        Linear scan over recent lines — the matching finding was
        almost certainly written in the last few hundred
        milliseconds, so the answer is at the tail. Returns the
        ``finding`` payload (a DraftFinding dict) directly so the
        caller can pull ``host_id`` / ``title`` / ``confidence``
        without further unwrapping.
        """
        import hashlib

        path = self._case_dir / "findings.jsonl"
        if not path.exists():
            return None
        try:
            with path.open("r", encoding="utf-8") as f:
                tail = f.readlines()[-200:]
        except OSError:
            return None
        for raw in reversed(tail):
            stripped = raw.strip()
            if not stripped:
                continue
            digest = hashlib.sha256(stripped.encode("utf-8")).hexdigest()
            if digest != output_hash:
                continue
            try:
                rec = json.loads(stripped)
            except ValueError:
                return None
            finding = rec.get("finding")
            if isinstance(finding, dict):
                return finding
            return None
        return None

    @staticmethod
    def _extract_attack_ids(args: dict[str, Any], output: dict[str, Any]) -> set[str]:
        import re

        out: set[str] = set()
        attack_re = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
        for v in (
            args.get("technique_id"),
            args.get("semantic_query"),
            output.get("query_value"),
        ):
            if isinstance(v, str):
                out.update(attack_re.findall(v))
        for hit in (output.get("hits") or []):
            if isinstance(hit, dict):
                tid = hit.get("technique_id")
                if isinstance(tid, str):
                    out.add(tid)
        return out

    # ------------------------------------------------------------------
    # Final summary
    # ------------------------------------------------------------------

    def render_summary(
        self,
        *,
        host_count: int,
        confidence_counts: dict[str, int],
        cross_host_count: int,
        iteration_count: int,
        termination_reason: str | None,
        runtime_seconds: float,
        report_paths: list[Path],
    ) -> None:
        self._print("")
        self._print(f"{_BAR}")
        self._print("  Results")
        self._print(f"{_BAR}")
        total = sum(confidence_counts.values())
        high = confidence_counts.get("HIGH", 0)
        med = confidence_counts.get("MEDIUM", 0)
        low = confidence_counts.get("LOW", 0)
        disp = confidence_counts.get("DISPUTED", 0)
        self._print(f"  Hosts analyzed:     {host_count}")
        self._print(
            f"  Total findings:     {total} "
            f"({high} HIGH, {med} MEDIUM, {low} LOW, {disp} DISPUTED)"
        )
        self._print(f"  Cross-host:         {cross_host_count} correlation(s)")
        self._print(f"  Iterations:         {iteration_count}")
        if termination_reason:
            self._print(f"  Termination:        {termination_reason}")
        mins = int(runtime_seconds // 60)
        secs = int(runtime_seconds - mins * 60)
        self._print(f"  Runtime:            {mins}m {secs}s")
        if self._known_attack_techniques:
            tids = ", ".join(sorted(self._known_attack_techniques))
            self._print(f"  ATT&CK seen:        {tids}")
        for path in report_paths:
            self._print(f"  Report:             {path}")
        self._print(f"{_BAR}")


# ---------------------------------------------------------------------------
# Replay helper — used by the verbose mock-run subcommand to render a
# pre-recorded event sequence to stdout. Useful for showing operators
# what a live run looks like without burning tokens.
# ---------------------------------------------------------------------------


def replay_events(
    events: list[tuple[str, dict[str, Any]]],
    *,
    case_dir: Path | None = None,
    stream: TextIO | None = None,
    delay_seconds: float = 0.0,
) -> None:
    """Drive a `ProgressDisplay` synchronously over a list of events.

    Skips the audit tail thread (the events list is the only input).
    Used by ``sift-guard mock-run`` to show what real-time output
    looks like.
    """
    display = ProgressDisplay(case_dir or Path.cwd(), stream=stream)
    for event, payload in events:
        display.on_event(event, payload)
        if delay_seconds:
            time.sleep(delay_seconds)


__all__ = ["ProgressDisplay", "replay_events"]
