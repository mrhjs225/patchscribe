"""angr-based symbolic execution adapter.

This component is optional; it attempts to symbolically execute the given C
program (via compiled binary) and collect path predicates relevant to a target
line. Because compiling and exploring binaries can be expensive, the adapter is
lightweight and defensive. If angr is missing or compilation fails, the caller
receives ``None`` and can fall back to heuristic symbolic analysis.
"""
from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

try:  # pragma: no cover - optional dependency
    import angr
    import claripy
except Exception:  # pragma: no cover
    angr = None
    claripy = None


@dataclass
class AngrPath:
    predicates: List[str]
    addresses: List[int]


@dataclass
class AngrResult:
    paths: List[AngrPath]


class AngrExplorer:
    def __init__(self, source: str) -> None:
        self.source = source

    @property
    def available(self) -> bool:
        return angr is not None

    def run(self, target_function: str | None = None, timeout: int = 10) -> AngrResult | None:
        if not self.available:
            return None
        with tempfile.TemporaryDirectory() as tmpdir:
            src_path = Path(tmpdir) / "program.c"
            bin_path = Path(tmpdir) / "program"
            src_path.write_text(self.source)
            compile_cmd = ["gcc", "-g", str(src_path), "-o", str(bin_path)]
            try:
                subprocess.run(compile_cmd, check=True, capture_output=True, text=True)
            except Exception:
                return None
            project = angr.Project(str(bin_path), auto_load_libs=False)
            entry_state = project.factory.entry_state()
            simgr = project.factory.simulation_manager(entry_state)
            paths: List[AngrPath] = []
            try:
                simgr.explore(find=lambda s: True, num_find=3, timeout=timeout)
            except Exception:
                pass
            for found in simgr.found or []:
                predicates = [str(c) for c in found.history.descriptions]
                addresses = [addr for addr in found.history.bbl_addrs]
                paths.append(AngrPath(predicates=predicates, addresses=addresses))
            if not paths:
                return None
            return AngrResult(paths=paths)
