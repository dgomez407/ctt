"""Run repository cleanup from a source checkout."""

import sys
from importlib import import_module
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))
main = import_module("controlled_text_transfer.cleanup").main

if __name__ == "__main__":
    raise SystemExit(main())
