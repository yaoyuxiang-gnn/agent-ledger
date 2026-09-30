"""Allow ``python -m agent_ledger`` as an alternative to the ``al`` script.

Useful when the console script is not on ``PATH`` — inside a ``pipx run``, a
container, or a virtualenv nobody activated.
"""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
