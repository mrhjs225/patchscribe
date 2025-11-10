"""
Dynamic taint analysis module for PatchScribe.
Simulates taint propagation through the program.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Set, Any
import re

from ..pcg import ProgramCausalGraph, PCGNode, PCGEdge, next_node_id


@dataclass
class TaintAnalysisResult:
    """Result of dynamic taint analysis."""
    graph: ProgramCausalGraph
    executed_lines: List[int]


class TaintAnalyzer:
    """
    Performs taint analysis to track data flow from sources to sinks.
    """

    def __init__(self, program: str, vuln_location: int, taint_sources: List[str]):
        self.program = program
        self.vuln_location = vuln_location
        self.taint_sources = taint_sources
        self.lines = program.splitlines()
        self.seq: Dict[str, int] = {}

    def run(self) -> TaintAnalysisResult:
        """Execute taint analysis."""
        graph = ProgramCausalGraph()
        executed_lines = []
        tainted_vars: Set[str] = set()

        # Track taint propagation
        for line_num, line in enumerate(self.lines, start=1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("//"):
                continue

            executed_lines.append(line_num)

            # Check for taint sources
            for source in self.taint_sources:
                if source in line_stripped:
                    # Extract variable being assigned
                    assignment_match = re.match(r'(\w+)\s*=', line_stripped)
                    func_call_match = re.search(rf'{source}\s*\([^)]*\)', line_stripped)

                    if assignment_match:
                        var_name = assignment_match.group(1)
                        tainted_vars.add(var_name)

                        node_id = next_node_id(self.seq, "t")
                        node = PCGNode(
                            node_id=node_id,
                            node_type="data",
                            description=f"taint source: {var_name} from {source}",
                            location=line_num,
                            metadata={"tainted": True, "source": source},
                        )
                        graph.add_node(node)

                    elif func_call_match:
                        # Direct function call that taints input
                        node_id = next_node_id(self.seq, "t")
                        node = PCGNode(
                            node_id=node_id,
                            node_type="operation",
                            description=f"taint source: {source}",
                            location=line_num,
                            metadata={"tainted": True, "source": source},
                        )
                        graph.add_node(node)

            # Track taint propagation through assignments
            if '=' in line_stripped and not any(kw in line_stripped for kw in ['==', '!=', '<=', '>=']):
                assignment_match = re.match(r'(\w+)\s*=\s*(.+)', line_stripped)
                if assignment_match:
                    lhs = assignment_match.group(1)
                    rhs = assignment_match.group(2)

                    # Check if RHS contains tainted variables
                    rhs_tainted = any(tvar in rhs for tvar in tainted_vars)

                    if rhs_tainted:
                        tainted_vars.add(lhs)

                        node_id = next_node_id(self.seq, "t")
                        node = PCGNode(
                            node_id=node_id,
                            node_type="data",
                            description=f"taint propagation: {lhs}",
                            location=line_num,
                            metadata={"tainted": True},
                        )
                        graph.add_node(node)

            # Detect tainted data reaching vulnerable operations
            vulnerable_ops = ['strcpy', 'strcat', 'sprintf', 'memcpy', 'gets', 'scanf']
            for op in vulnerable_ops:
                if op in line_stripped:
                    # Check if any argument is tainted
                    func_match = re.search(rf'{op}\s*\(([^)]+)\)', line_stripped)
                    if func_match:
                        args = func_match.group(1)
                        args_tainted = any(tvar in args for tvar in tainted_vars)

                        if args_tainted:
                            node_id = next_node_id(self.seq, "t")
                            sink_node = PCGNode(
                                node_id=node_id,
                                node_type="operation",
                                description=f"tainted sink: {op}",
                                location=line_num,
                                metadata={"tainted": True, "sink": op},
                            )
                            graph.add_node(sink_node)

                            # Add edge from sources to sink
                            for existing_node in graph.nodes.values():
                                if existing_node.metadata.get("tainted") and existing_node.node_id != node_id:
                                    edge = PCGEdge(
                                        source=existing_node.node_id,
                                        target=node_id,
                                        edge_type="taint_flow",
                                        rationale="tainted data flow to sink",
                                    )
                                    graph.add_edge(edge)

        return TaintAnalysisResult(graph=graph, executed_lines=executed_lines)
