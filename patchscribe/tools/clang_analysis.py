"""Clang-based static analysis helpers.

This module attempts to use libclang (via clang.cindex) to compute backward
slices and dependency relationships. If libclang is unavailable, the helper
reports that it is disabled so the pipeline can fall back to heuristic
analysis.

Updated to use LLVM-based backward slicing for improved PDG analysis.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

try:  # pragma: no cover - optional dependency
    from clang import cindex
except Exception:  # pragma: no cover - optional dependency missing
    cindex = None

try:
    from .llvm_slicer import create_backward_slicer, BackwardSliceResult
    LLVM_SLICER_AVAILABLE = True
except ImportError:
    LLVM_SLICER_AVAILABLE = False
    BackwardSliceResult = None


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
        # Try LLVM-based backward slicing first (more accurate)
        if LLVM_SLICER_AVAILABLE:
            llvm_result = self._run_llvm_slicer(vuln_line)
            if llvm_result:
                return llvm_result

        # Fallback to libclang token-based analysis
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

    def _run_llvm_slicer(self, vuln_line: int) -> ClangAnalysisResult | None:
        """
        Use LLVM-based backward slicing for more accurate PDG analysis.

        This implements the paper's approach:
        "Backward slicing via Clang/LLVM 14.0 to identify data and control dependencies"
        """
        try:
            slicer = create_backward_slicer(self.source, self.filename)
            slice_result = slicer.slice(vuln_line)

            if not slice_result:
                return None

            # Convert slice result to ClangAnalysisResult format
            nodes: List[ClangNode] = []
            edges: List[Dict[str, str]] = []

            # Create nodes from slice statements
            for stmt in slice_result.statements:
                node_id = f"stmt_{stmt.line_number}"
                nodes.append(
                    ClangNode(
                        usr=node_id,
                        kind=stmt.statement_type,
                        spelling=stmt.statement,
                        location=stmt.line_number,
                    )
                )

            # Create edges from data dependencies
            for from_line, to_line in slice_result.data_dependencies:
                edges.append(
                    {
                        "source": f"stmt_{from_line}",
                        "target": f"stmt_{to_line}",
                        "kind": "data_dependency",
                        "line": from_line,
                    }
                )

            # Create edges from control dependencies
            for from_line, to_line in slice_result.control_dependencies:
                edges.append(
                    {
                        "source": f"stmt_{from_line}",
                        "target": f"stmt_{to_line}",
                        "kind": "control_dependency",
                        "line": from_line,
                    }
                )

            return ClangAnalysisResult(nodes=nodes, edges=edges)

        except Exception:
            return None

    def _tokens_at_line(self, tu, line: int):  # pragma: no cover - libclang
        for token in tu.get_tokens(location=tu.get_location(self.filename, (line, 1))):
            yield token
