"""Pytest collection-time setup.

Pin SIFT_VM_HOST before any test module imports server.runners.sift_vm,
which would otherwise shell out to `ip route show` at module-load time
to detect the WSL2 default gateway. On WSL2 the detection works but is
non-portable; on CI without a default route it would fail. The runner
is mocked in unit tests, so the pinned value never reaches the wire.
"""

from __future__ import annotations

import os

os.environ.setdefault("SIFT_VM_HOST", "test.invalid")
