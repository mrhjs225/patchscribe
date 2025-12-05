"""
Embedded data artifacts used by PatchScribe.

Currently exposes the SCM template catalog referenced in the paper. The JSON
file is loaded via importlib.resources so the tests and tooling can access it
without relying on relative filesystem paths.
"""
from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Union

PACKAGE_NAME = __name__
SCM_TEMPLATE_FILENAME = "scm_templates.json"


def data_path(name: str) -> Path:
    """Return the absolute path to a packaged data file."""
    return Path(resources.files(PACKAGE_NAME) / name)


def read_text(name: str) -> str:
    """Return the textual contents of a packaged data file."""
    with resources.as_file(resources.files(PACKAGE_NAME) / name) as path:
        return path.read_text(encoding="utf-8")


__all__ = ["PACKAGE_NAME", "SCM_TEMPLATE_FILENAME", "data_path", "read_text"]
