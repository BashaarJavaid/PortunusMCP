"""Compatibility wrapper for ``portunusmcp keys generate``."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from services.cli import main  # noqa: E402

mode = "signed" if "--signed" in sys.argv[1:] else "bearer"
arguments = ["keys", "generate", mode]
if "--totp" in sys.argv[1:]:
    arguments.append("--totp")
raise SystemExit(main(arguments))
