"""Allow running the CLI via `python -m device_discover`."""
import sys
from pathlib import Path

# Ensure parent of device_discover is on path (for running from any cwd)
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from device_discover.cli import main

if __name__ == "__main__":
    main()
