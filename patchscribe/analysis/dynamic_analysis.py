"""
Lightweight taint-style dynamic analysis approximation for PoC purposes.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from ..pcg import PCGEdge, PCGNode, ProgramCausalGraph, next_node_id


@dataclass
class DynamicAnalysisResult:
    graph: ProgramCausalGraph
    executed_lines: List[int]


class TaintAnalyzer:
    def __init__(self, source: str, vuln_line: int, taint_sources: List[str]) -> None:
        self.lines = source.splitlines()
        self.vuln_line = vuln_line
        self.sources = taint_sources
        self.seq: Dict[str, int] = {}
        self.graph = ProgramCausalGraph()
        self.executed_lines: List[int] = []

    def run(self) -> DynamicAnalysisResult:
        vulnerability_node = self._register_node(
            "vulnerability", self.lines[self.vuln_line - 1].strip(), self.vuln_line
        )
        tainted_vars = self._identify_tainted_vars()
        for tainted in tainted_vars:
            node = self._register_node("predicate", tainted["description"], tainted["line"])
            self.graph.add_edge(
                PCGEdge(
                    source=node.node_id,
                    target=vulnerability_node.node_id,
                    edge_type="data",
                    rationale=f"Tainted value {tainted['var']} reaches vulnerability",
                )
            )
        return DynamicAnalysisResult(self.graph, self.executed_lines)

    def _identify_tainted_vars(self) -> List[Dict[str, object]]:
        tainted: List[Dict[str, object]] = []
        for line_no, line in enumerate(self.lines, start=1):
            for src in self.sources:
                if src in line:
                    var = self._extract_lhs(line)
                    if not var:
                        continue
                    tainted.append(
                        {
                            "var": var,
                            "line": line_no,
                            "description": f"{var} tainted via {src}",
                        }
                    )
                    self.executed_lines.append(line_no)
        if self.vuln_line not in self.executed_lines:
            self.executed_lines.append(self.vuln_line)
        return tainted

    @staticmethod
    def _extract_lhs(line: str) -> str | None:
        if "=" not in line:
            return None
        lhs = line.split("=")[0].strip().split()[-1]
        return lhs or None

    def _register_node(self, node_type: str, description: str, line: int) -> PCGNode:
        node = PCGNode(
            node_id=next_node_id(self.seq, node_type[:1]),
            node_type=node_type,
            description=description,
            location=line,
        )
        self.graph.add_node(node)
        return node
