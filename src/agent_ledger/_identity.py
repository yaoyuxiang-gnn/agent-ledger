"""Identity constants, in their own module so submodules can import them.

This exists because of a circular import that is easy to walk into: if the
constant lived in ``agent_ledger/__init__.py``, then any submodule doing
``from . import USER_AGENT`` would re-enter the package initialiser while it was
still executing — and the failure reads as "cannot import name X from a partially
initialized module", which points at the importer rather than at the cycle.

Keeping it here means the dependency direction is one-way: every module may
import this, and it imports nothing.
"""

from __future__ import annotations

__all__ = ["REPO_URL", "USER_AGENT", "VERSION"]

VERSION = "0.2.0"

#: Where the project lives. Named in the ``User-Agent`` and in every generated
#: document, so a remote operator who sees unexpected traffic can find out what
#: sent it.
REPO_URL = "https://github.com/yaoyuxiang-gnn/agent-ledger"

#: The ``User-Agent`` every outbound request carries. Defined once because it had
#: been copy-pasted into five modules with the version hard-coded, which meant a
#: release bump would have left most of them advertising the old one.
USER_AGENT = f"agent-ledger/{VERSION} (+{REPO_URL})"
