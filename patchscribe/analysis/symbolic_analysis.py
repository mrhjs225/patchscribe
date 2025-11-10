"""
Symbolic execution analysis module for PatchScribe.
Performs lightweight symbolic analysis to identify path conditions.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Any
import re

from ..pcg import ProgramCausalGraph, PCGNode, PCGEdge, next_node_id


@dataclass
class SymbolicAnalysisResult:
    """Result of symbolic analysis."""
    graph: ProgramCausalGraph
    path_conditions: List[str]


class SymbolicExplorer:
    """
    Performs symbolic execution to identify path constraints
    and conditions that must be satisfied to reach vulnerable code.
    """

    def __init__(self, program: str, vuln_location: int):
        self.program = program
        self.vuln_location = vuln_location
        self.lines = program.splitlines()
        self.seq: Dict[str, int] = {}

    def run(self) -> SymbolicAnalysisResult:
        """Execute symbolic analysis."""
        graph = ProgramCausalGraph()
        path_conditions = []

        # Extract conditions that guard the vulnerable location
        condition_stack = []
        indent_stack = []

        for line_num, line in enumerate(self.lines, start=1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("//"):
                continue

            # Track indentation to understand scope
            indent = len(line) - len(line.lstrip())

            # Pop conditions that are out of scope
            while indent_stack and indent <= indent_stack[-1]:
                indent_stack.pop()
                if condition_stack:
                    condition_stack.pop()

            # Extract conditional expressions
            if_match = re.match(r'if\s*\((.+)\)', line_stripped)
            while_match = re.match(r'while\s*\((.+)\)', line_stripped)
            for_match = re.match(r'for\s*\(([^)]+)\)', line_stripped)

            if if_match:
                condition = if_match.group(1).rstrip('{').strip()
                condition_stack.append(condition)
                indent_stack.append(indent)
                path_conditions.append(condition)

                node_id = next_node_id(self.seq, "sym")
                node = PCGNode(
                    node_id=node_id,
                    node_type="predicate",
                    description=f"if ({condition})",
                    location=line_num,
                    metadata={"condition": condition},
                )
                graph.add_node(node)

                # If this guards the vulnerable location, mark it
                if line_num < self.vuln_location:
                    vuln_node_id = next_node_id(self.seq, "sym")
                    vuln_node = PCGNode(
                        node_id=vuln_node_id,
                        node_type="operation",
                        description="vulnerable operation",
                        location=self.vuln_location,
                    )
                    # Don't add duplicate vuln nodes
                    if vuln_node_id not in graph.nodes:
                        graph.add_node(vuln_node)

                    edge = PCGEdge(
                        source=node_id,
                        target=vuln_node_id,
                        edge_type="control_dependency",
                        rationale=f"condition guards vulnerable line",
                    )
                    graph.add_edge(edge)

            elif while_match:
                condition = while_match.group(1).rstrip('{').strip()
                condition_stack.append(condition)
                indent_stack.append(indent)
                path_conditions.append(condition)

                node_id = next_node_id(self.seq, "sym")
                node = PCGNode(
                    node_id=node_id,
                    node_type="predicate",
                    description=f"while ({condition})",
                    location=line_num,
                    metadata={"condition": condition, "loop": True},
                )
                graph.add_node(node)

            elif for_match:
                condition = for_match.group(1).strip()
                path_conditions.append(condition)

                node_id = next_node_id(self.seq, "sym")
                node = PCGNode(
                    node_id=node_id,
                    node_type="predicate",
                    description=f"for ({condition})",
                    location=line_num,
                    metadata={"condition": condition, "loop": True},
                )
                graph.add_node(node)

            # Check for vulnerable line
            if line_num == self.vuln_location and condition_stack:
                # Record all conditions that must be true to reach this line
                combined_conditions = " AND ".join(condition_stack)
                path_conditions.append(f"Path to vuln: {combined_conditions}")

        return SymbolicAnalysisResult(
            graph=graph,
            path_conditions=path_conditions
        )
