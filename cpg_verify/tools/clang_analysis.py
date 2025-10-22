"""Clang-based static analysis helpers.

This module attempts to use libclang (via clang.cindex) to compute backward
slices and dependency relationships. If libclang is unavailable, the helper
reports that it is disabled so the pipeline can fall back to heuristic
analysis.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

try:  # pragma: no cover - optional dependency
    from clang import cindex
except Exception:  # pragma: no cover - optional dependency missing
    cindex = None


@dataclass
class ClangNode:
    usr: str
    kind: str
    spelling: str
    location: Optional[int]


@dataclass
class ClangAnalysisResult:
    nodes: List[ClangNode]
    edges: List[Dict[str, str]]


class ClangStaticAnalyzer:
    def __init__(self, source: str, filename: str = "translation_unit.c") -> None:
        self.source = source
        self.filename = filename

    @property
    def available(self) -> bool:
        return cindex is not None

    def run(self, vuln_line: int) -> ClangAnalysisResult | None:
        if not self.available:
            return None
        index = cindex.Index.create()
        unsaved = [(self.filename, self.source)]
        try:
            translation_unit = index.parse(self.filename, args=["-std=c11"], unsaved_files=unsaved)
        except Exception:
            return None
        nodes: List[ClangNode] = []
        edges: List[Dict[str, str]] = []
        target_tokens = self._tokens_at_line(translation_unit, vuln_line)
        for token in target_tokens:
            decl = token.get_cursor()
            if not decl or not decl.spelling:
                continue
            node_usr = decl.get_usr() or decl.spelling
            node_line = decl.location.line if decl.location.file else None
            nodes.append(ClangNode(node_usr, str(decl.kind).split(".")[-1], decl.spelling, node_line))
            for ref in decl.get_referenced().get_children() if decl.get_referenced() else []:
                parent_line = ref.location.line if ref.location.file else None
                edges.append(
                    {
                        "source": node_usr,
                        "target": ref.get_usr() or ref.spelling,
                        "kind": "clang",
                        "line": parent_line,
                    }
                )
        return ClangAnalysisResult(nodes=nodes, edges=edges)

    def _tokens_at_line(self, tu, line: int):  # pragma: no cover - libclang
        for token in tu.get_tokens(location=tu.get_location(self.filename, (line, 1))):
            yield token
