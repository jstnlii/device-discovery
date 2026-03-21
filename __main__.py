"""Allow running the CLI via `python -m device_discover`."""
import sys
from pathlib import Path

# Add repo root to path (for running via -m from parent directory)
_root = Path(__file__).resolve().parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from cli import main

if __name__ == "__main__":
    main()
