"""File-lock-based critical section for the hash-chained writers.

Every chain writer (audit, findings, correlations, extractions,
iterations) follows the same shape: read the last line of the chain
to recover ``prev_line_hash`` and ``next_line_number``, compute the
new ``this_line_hash``, then append. Two writers racing on those
three operations would each see the same ``prev_line_hash``, compute
the same ``next_line_number``, and produce two divergent lines —
breaking the chain's tamper-evident contract.

In the single-process server design this never mattered: Python's
GIL serializes the operations and ``open(..., "a")`` writes one
record at a time. But the orchestrator's parallel subagent dispatch
spawns a separate MCP-server child per analyst session, so each
chain writer now serves multiple PROCESSES concurrently. We
serialize them with ``fcntl.flock`` on a sidecar lock file —
exclusive, blocking, ~5 ms per acquisition under contention.

The lock target is a sidecar (``<chain>.lock``) rather than the
chain file itself because the writers open the chain file in
distinct modes — ``"r"`` for read_chain_state, ``"a"`` for the
append — and ``fcntl.flock`` only serializes file descriptors
that share an OS-level inode handle. A separate single-purpose lock
file gives every writer one consistent fd to lock.

The lock is held just across read + write. Subagent subprocess
calls (which can take minutes) sit OUTSIDE the lock; only the
millisecond-scale chain-update phase is serialized.
"""

from __future__ import annotations

import fcntl
import threading
from contextlib import contextmanager
from pathlib import Path

# Per-thread re-entrancy ledger: {resolved lock path: hold depth}.
# ``fcntl.flock`` locks belong to the open file description, so a
# thread that already holds the exclusive lock and opens the sidecar
# a second time would block against itself. The ledger lets the same
# thread nest ``chain_write_lock`` on the same chain (e.g.
# ``reserve_audit_line`` wrapping an ``append_audit_entry``) while
# distinct threads and processes still serialize through flock —
# the ledger is thread-local, so a sibling thread's entry is
# invisible here and it takes the flock path as before.
_local = threading.local()


@contextmanager
def chain_write_lock(chain_path: Path):
    """Exclusive blocking lock around a chain writer's read-modify-write.

    ``chain_path`` is the actual chain file path (e.g.
    ``case-data/audit/sift-guard-mcp.jsonl``). The lock target is a
    sidecar named ``<chain_path>.lock`` next to the chain. The
    sidecar is opened in append mode so creation is concurrent-safe
    (open + create races resolve cleanly without an explicit
    ``O_EXCL``-style guard).

    Re-entrant within a thread: nested acquisition of the same chain
    by the same thread yields immediately and releases only when the
    outermost holder exits.

    Releases the lock on ``finally``, including on exception. The
    OS releases the lock when the file descriptor is closed too, so
    even a hard-killed worker won't leak the lock past process
    exit.

    Use::

        with chain_write_lock(audit_path):
            line_number, prev = _read_chain_state(audit_path)
            ...
            with audit_path.open("a") as f:
                f.write(serialized + "\n")
    """
    chain_path = Path(chain_path)
    chain_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = chain_path.with_suffix(chain_path.suffix + ".lock")

    held: dict[str, int] = getattr(_local, "held", None) or {}
    _local.held = held
    key = str(lock_path.resolve())

    if held.get(key, 0) > 0:
        held[key] += 1
        try:
            yield
        finally:
            held[key] -= 1
        return

    with lock_path.open("a") as lockf:
        fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
        held[key] = 1
        try:
            yield
        finally:
            del held[key]
            fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)


__all__ = ["chain_write_lock"]
