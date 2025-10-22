"""
Simplified static analysis pipeline approximating backward slicing and dependency extraction.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

from ..pcg import PCGEdge, PCGNode, ProgramCausalGraph, next_node_id

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_CONTROL_KEYWORDS = ("if", "while", "for", "switch")


@dataclass
class StaticAnalysisResult:
    graph: ProgramCausalGraph
    trace: List[str]


class StaticAnalyzer:
    def __init__(self, source: str, vuln_line: int) -> None:
        self.source = source
        self.lines = source.splitlines()
        self.vuln_line = vuln_line
        self.seq: Dict[str, int] = {}
        self.graph = ProgramCausalGraph()
        self.trace: List[str] = []

    def run(self) -> StaticAnalysisResult:
        vuln_tokens = self._tokens_for_line(self.vuln_line)
        vuln_node = self._register_node(
            node_type="vulnerability",
            description=self.lines[self.vuln_line - 1].strip(),
            line=self.vuln_line,
        )
        worklist = list(sorted(vuln_tokens))
        visited: set[Tuple[int, str]] = set()
        while worklist:
            token = worklist.pop()
            match = self._find_def_use(token)
            if not match:
                continue
            line_no, kind = match
            if (line_no, token) in visited:
                continue
            visited.add((line_no, token))
            predicate = self._make_node_for_line(line_no, token, kind)
            self.graph.add_edge(
                PCGEdge(
                    source=predicate.node_id,
                    target=vuln_node.node_id,
                    edge_type="data" if kind == "assignment" else "control",
                    rationale=f"{token} influences vulnerability via {kind}",
                )
            )
            worklist.extend(self._tokens_for_line(line_no))
        self.trace.append("Static backward slice nodes: " + ", ".join(self.graph.nodes))
        return StaticAnalysisResult(self.graph, self.trace)

    def _register_node(self, node_type: str, description: str, line: int) -> PCGNode:
        node = PCGNode(
            node_id=next_node_id(self.seq, node_type[:1]),
            node_type=node_type,
            description=description,
            location=line,
        )
        self.graph.add_node(node)
        self.trace.append(f"Registered {node_type} node {node.node_id} @ line {line}")
        return node

    def _make_node_for_line(self, line_no: int, token: str, kind: str) -> PCGNode:
        node_type = "assignment" if kind == "assignment" else "predicate"
        description = self.lines[line_no - 1].strip()
        existing = self._node_for_line(line_no)
        if existing:
            return existing
        return self._register_node(node_type, description, line_no)

    def _node_for_line(self, line_no: int) -> PCGNode | None:
        for node in self.graph.nodes.values():
            if node.location == line_no:
                return node
        return None

    def _tokens_for_line(self, line_no: int) -> List[str]:
        if line_no <= 0 or line_no > len(self.lines):
            return []
        line = self.lines[line_no - 1]
        tokens = [tok for tok in _IDENTIFIER.findall(line) if tok not in _CONTROL_KEYWORDS]
        return list({tok for tok in tokens})

    def _find_def_use(self, token: str) -> Tuple[int, str] | None:
        for idx in range(self.vuln_line - 1, 0, -1):
            line = self.lines[idx - 1]
            if token not in line:
                continue
            if self._is_assignment(line, token):
                return idx, "assignment"
            if self._is_control(line):
                return idx, "predicate"
        return None

    @staticmethod
    def _is_assignment(line: str, token: str) -> bool:
        return bool(re.search(rf"\b{re.escape(token)}\b\s*=", line))

    @staticmethod
    def _is_control(line: str) -> bool:
        stripped = line.strip()
        return stripped.startswith(_CONTROL_KEYWORDS)
