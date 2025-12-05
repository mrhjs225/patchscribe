"""
Ensure the repository root is importable during pytest runs.

The Codex CLI launches pytest without automatically prepending the repo root
to sys.path, so we do it manually here.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
