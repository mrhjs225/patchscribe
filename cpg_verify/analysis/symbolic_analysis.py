"""
Basic symbolic path enumeration sketch built for demonstrative purposes.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from ..pcg import PCGEdge, PCGNode, ProgramCausalGraph, next_node_id


@dataclass
class SymbolicAnalysisResult:
    graph: ProgramCausalGraph
    path_conditions: List[str]


class SymbolicExplorer:
    def __init__(self, source: str, vuln_line: int) -> None:
        self.lines = source.splitlines()
        self.vuln_line = vuln_line
        self.seq: Dict[str, int] = {}
        self.graph = ProgramCausalGraph()
        self.conditions: List[str] = []

    def run(self) -> SymbolicAnalysisResult:
        vulnerability_node = self._register_node(
            "vulnerability", self.lines[self.vuln_line - 1].strip(), self.vuln_line
        )
        for line_no, line in enumerate(self.lines, start=1):
            stripped = line.strip()
            if not stripped.startswith("if"):
                continue
            condition = stripped[stripped.find("(") + 1 : stripped.rfind(")")].strip()
            if not condition:
                continue
            self.conditions.append(condition)
            node = self._register_node("predicate", condition, line_no)
            self.graph.add_edge(
                PCGEdge(
                    source=node.node_id,
                    target=vulnerability_node.node_id,
                    edge_type="symbolic",
                    rationale=f"Condition '{condition}' satisfied on path",
                )
            )
        return SymbolicAnalysisResult(self.graph, self.conditions)

    def _register_node(self, node_type: str, description: str, line: int) -> PCGNode:
        node = PCGNode(
            node_id=next_node_id(self.seq, node_type[:1]),
            node_type=node_type,
            description=description,
            location=line,
        )
        self.graph.add_node(node)
        return node
