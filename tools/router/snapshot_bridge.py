#!/usr/bin/env python3
"""Installed path shim; safety bridge is not a public mutation CLI."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kdn.engine import snapshot_bridge


if __name__ == '__main__':
    raise SystemExit(snapshot_bridge.run(sys.argv[1:]))
