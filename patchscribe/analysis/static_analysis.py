"""
Static analysis module for PatchScribe.
Performs basic static control and data flow analysis on C code.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Any
import re

from ..pcg import ProgramCausalGraph, PCGNode, PCGEdge, next_node_id


@dataclass
class StaticAnalysisResult:
    """Result of static analysis."""
    graph: ProgramCausalGraph
    trace: List[str]


class StaticAnalyzer:
    """
    Performs static analysis on C source code to identify
    control flow and data dependencies.
    """

    def __init__(self, program: str, vuln_location: int):
        self.program = program
        self.vuln_location = vuln_location
        self.lines = program.splitlines()
        self.seq: Dict[str, int] = {}

    def run(self) -> StaticAnalysisResult:
        """Execute static analysis."""
        graph = ProgramCausalGraph()
        trace = []

        # Extract function calls and variable assignments
        prev_node_id = None
        for line_num, line in enumerate(self.lines, start=1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("//"):
                continue

            # Detect function calls
            func_calls = re.findall(r'(\w+)\s*\(', line_stripped)
            for func_name in func_calls:
                node_id = next_node_id(self.seq, "s")
                node = PCGNode(
                    node_id=node_id,
                    node_type="operation",
                    description=f"call {func_name}",
                    location=line_num,
                )
                graph.add_node(node)
                trace.append(f"Line {line_num}: {func_name}")

                # Connect to previous node
                if prev_node_id:
                    edge = PCGEdge(
                        source=prev_node_id,
                        target=node_id,
                        edge_type="control_flow",
                        rationale="sequential execution",
                    )
                    graph.add_edge(edge)

                prev_node_id = node_id

            # Detect variable assignments
            assignments = re.findall(r'(\w+)\s*=', line_stripped)
            for var_name in assignments:
                if var_name in ['if', 'while', 'for', 'switch']:
                    continue
                node_id = next_node_id(self.seq, "s")
                node = PCGNode(
                    node_id=node_id,
                    node_type="data",
                    description=f"assign {var_name}",
                    location=line_num,
                )
                graph.add_node(node)

                if prev_node_id:
                    edge = PCGEdge(
                        source=prev_node_id,
                        target=node_id,
                        edge_type="data_flow",
                        rationale="assignment",
                    )
                    graph.add_edge(edge)

                prev_node_id = node_id

        return StaticAnalysisResult(graph=graph, trace=trace)
