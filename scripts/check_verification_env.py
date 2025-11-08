#!/usr/bin/env python3
"""
Environment checker for PatchScribe verification backends.

Usage:
    python scripts/check_verification_env.py
    python scripts/check_verification_env.py --json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from patchscribe.verification import Verifier  # noqa: E402


def format_status(stage: str, info: dict) -> str:
    icon = "✅" if info.get("available") else "⚠️"
    reason = info.get("reason", "")
    tools = ", ".join(info.get("tools") or []) or "N/A"
    if info.get("available"):
        reason_text = "ready"
    else:
        reason_text = reason or "unknown issue"
    return f"{icon} {stage:12s} :: tools=[{tools}] :: {reason_text}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Check availability of symbolic/model/fuzzing backends.")
    parser.add_argument("--json", action="store_true", help="Print raw JSON instead of human-readable output.")
    args = parser.parse_args()

    status = Verifier.check_environment()

    if args.json:
        print(json.dumps(status, indent=2))
        return

    print("PatchScribe verification environment status\n")
    for stage in ("symbolic", "model_check", "fuzzing"):
        info = status.get(stage, {})
        print(format_status(stage, info))
    print("\nRun this script after installing angr/CBMC/clang to confirm availability.")


if __name__ == "__main__":
    main()
