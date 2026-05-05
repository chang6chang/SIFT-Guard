"""Mount validation per CLAUDE.md "Architectural enforcement of evidence integrity"."""

from __future__ import annotations

from pathlib import Path


def verify_mount_readonly(path: Path) -> None:
    raise NotImplementedError(
        "Mount validation lands when the first disk-image tool is "
        "implemented (Week 3-4)"
    )


__all__ = ["verify_mount_readonly"]
