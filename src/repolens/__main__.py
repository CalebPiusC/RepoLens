"""Allow ``python -m repolens`` to behave exactly like the ``repolens`` executable."""

from __future__ import annotations

import sys

from repolens.cli import main

if __name__ == "__main__":
    sys.exit(main())
