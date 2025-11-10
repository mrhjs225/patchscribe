"""
AST-based analysis module for PatchScribe.
Performs abstract syntax tree analysis on C code.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Any
import re

from ..pcg import ProgramCausalGraph, PCGNode, PCGEdge, next_node_id


@dataclass
class ASTAnalysisResult:
    """Result of AST analysis."""
    graph: ProgramCausalGraph
    trace: List[str]


class ASTAnalyzer:
    """
    Performs AST-based analysis on C source code to identify
    syntactic structures and their relationships.
    """

    def __init__(self, program: str, vuln_location: int):
        self.program = program
        self.vuln_location = vuln_location
        self.lines = program.splitlines()
        self.seq: Dict[str, int] = {}

    def run(self) -> ASTAnalysisResult:
        """Execute AST analysis."""
        graph = ProgramCausalGraph()
        trace = []

        # Simple pattern-based AST extraction
        # In a real implementation, this would use a C parser like pycparser
        prev_node_id = None

        for line_num, line in enumerate(self.lines, start=1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("//"):
                continue

            # Detect control structures
            if re.match(r'(if|while|for|switch)\s*\(', line_stripped):
                control_type = re.match(r'(\w+)', line_stripped).group(1)
                node_id = next_node_id(self.seq, "a")
                node = PCGNode(
                    node_id=node_id,
                    node_type="predicate",
                    description=f"{control_type} condition",
                    location=line_num,
                )
                graph.add_node(node)
                trace.append(f"Line {line_num}: {control_type} statement")

                if prev_node_id:
                    edge = PCGEdge(
                        source=prev_node_id,
                        target=node_id,
                        edge_type="ast_parent",
                        rationale="control structure",
                    )
                    graph.add_edge(edge)

                prev_node_id = node_id

            # Detect function definitions
            elif re.match(r'\w+\s+\w+\s*\([^)]*\)\s*\{?', line_stripped) and not line_stripped.startswith('//'):
                func_match = re.match(r'\w+\s+(\w+)\s*\(', line_stripped)
                if func_match:
                    func_name = func_match.group(1)
                    node_id = next_node_id(self.seq, "a")
                    node = PCGNode(
                        node_id=node_id,
                        node_type="operation",
                        description=f"function {func_name}",
                        location=line_num,
                    )
                    graph.add_node(node)
                    trace.append(f"Line {line_num}: function definition {func_name}")

                    if prev_node_id:
                        edge = PCGEdge(
                            source=prev_node_id,
                            target=node_id,
                            edge_type="ast_sibling",
                            rationale="function definition",
                        )
                        graph.add_edge(edge)

                    prev_node_id = node_id

            # Detect expressions and statements
            elif ';' in line_stripped:
                node_id = next_node_id(self.seq, "a")
                node = PCGNode(
                    node_id=node_id,
                    node_type="operation",
                    description="statement",
                    location=line_num,
                )
                graph.add_node(node)

                if prev_node_id:
                    edge = PCGEdge(
                        source=prev_node_id,
                        target=node_id,
                        edge_type="ast_parent",
                        rationale="statement sequence",
                    )
                    graph.add_edge(edge)

                prev_node_id = node_id

        return ASTAnalysisResult(graph=graph, trace=trace)
