"""
Aggregator that combines static, dynamic, and symbolic analyses into a unified PCG.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .analysis.ast_analysis import ASTAnalyzer
from .analysis.dynamic_analysis import TaintAnalyzer
from .analysis.static_analysis import StaticAnalyzer
from .analysis.symbolic_analysis import SymbolicExplorer
from .tools import AngrExplorer, ClangStaticAnalyzer
from .pcg import PCGEdge, PCGNode, ProgramCausalGraph, next_node_id


@dataclass
class PCGBuilderConfig:
    taint_sources: List[str] = field(
        default_factory=lambda: ["gets", "fgets", "scanf", "read", "recv"]
    )


class PCGBuilder:
    def __init__(self, program: str, vuln_info: Dict[str, object], config: PCGBuilderConfig | None = None) -> None:
        self.program = program
        self.vuln_info = vuln_info
        self.config = config or PCGBuilderConfig()
        self.seq: Dict[str, int] = {}

    def build(self) -> Tuple[ProgramCausalGraph, Dict[str, object]]:
        static = StaticAnalyzer(self.program, self.vuln_info["location"]).run()
        ast_result = ASTAnalyzer(self.program, self.vuln_info["location"]).run()
        clang_result = ClangStaticAnalyzer(self.program).run(self.vuln_info["location"])
        dynamic = TaintAnalyzer(
            self.program,
            self.vuln_info["location"],
            self.config.taint_sources,
        ).run()
        symbolic = SymbolicExplorer(self.program, self.vuln_info["location"]).run()
        angr_result = AngrExplorer(self.program).run()
        graphs = [static.graph, ast_result.graph, dynamic.graph, symbolic.graph]
        if clang_result:
            graphs.append(self._graph_from_clang(clang_result))
        if angr_result:
            graphs.append(self._graph_from_angr(angr_result))
        combined = self._merge_graphs(graphs)
        metadata = {
            "static_trace": static.trace,
            "ast_trace": ast_result.trace,
            "dynamic_lines": dynamic.executed_lines,
            "symbolic_conditions": symbolic.path_conditions,
            "clang_nodes": [node.__dict__ for node in clang_result.nodes] if clang_result else [],
            "angr_paths": [path.__dict__ for path in angr_result.paths] if angr_result else [],
        }
        return combined, metadata

    def _merge_graphs(self, graphs: List[ProgramCausalGraph]) -> ProgramCausalGraph:
        merged = ProgramCausalGraph()
        node_lookup: Dict[Tuple[int, str, str], str] = {}
        for graph in graphs:
            for node in graph.nodes.values():
                key = (node.location or -1, node.node_type, node.description)
                if key not in node_lookup:
                    new_id = next_node_id(self.seq, node.node_type[:1])
                    merged_node = PCGNode(
                        node_id=new_id,
                        node_type=node.node_type,
                        description=node.description,
                        location=node.location,
                        metadata={"origin": node.metadata.get("origin", node.node_id)},
                    )
                    merged.add_node(merged_node)
                    node_lookup[key] = new_id
        for graph in graphs:
            location_index = {
                (node.location or -1, node.node_type, node.description): node_lookup[(node.location or -1, node.node_type, node.description)]
                for node in graph.nodes.values()
            }
            for edge in graph.edges:
                src_node = graph.nodes[edge.source]
                dst_node = graph.nodes[edge.target]
                src_key = (src_node.location or -1, src_node.node_type, src_node.description)
                dst_key = (dst_node.location or -1, dst_node.node_type, dst_node.description)
                if src_key not in location_index or dst_key not in location_index:
                    continue
                merged.add_edge(
                    PCGEdge(
                        source=location_index[src_key],
                        target=location_index[dst_key],
                        edge_type=edge.edge_type,
                        rationale=edge.rationale,
                    )
                )
        return merged

    def _graph_from_clang(self, result) -> ProgramCausalGraph:
        graph = ProgramCausalGraph()
        id_map: Dict[str, str] = {}
        for node in result.nodes:
            node_id = next_node_id(self.seq, "c")
            id_map[node.usr] = node_id
            pcg_node = PCGNode(
                node_id=node_id,
                node_type="predicate",
                description=node.spelling,
                location=node.location,
            )
            graph.add_node(pcg_node)
        for edge in result.edges:
            if edge["source"] == edge["target"]:
                continue
            src = id_map.get(edge["source"])
            if not src:
                src = next_node_id(self.seq, "c")
                id_map[edge["source"]] = src
                graph.add_node(
                    PCGNode(
                        node_id=src,
                        node_type="predicate",
                        description=edge["source"],
                        location=edge.get("line"),
                    )
                )
            dst = id_map.get(edge["target"])
            if not dst:
                dst = next_node_id(self.seq, "c")
                id_map[edge["target"]] = dst
                graph.add_node(
                    PCGNode(
                        node_id=dst,
                        node_type="predicate",
                        description=edge["target"],
                        location=edge.get("line"),
                    )
                )
            graph.add_edge(
                PCGEdge(source=src, target=dst, edge_type="clang", rationale="clang dependency")
            )
        return graph

    def _graph_from_angr(self, result) -> ProgramCausalGraph:
        graph = ProgramCausalGraph()
        for path in result.paths:
            node_id = next_node_id(self.seq, "a")
            graph.add_node(
                PCGNode(
                    node_id=node_id,
                    node_type="predicate",
                    description="; ".join(path.predicates) or "angr_path",
                    location=None,
                )
            )
        return graph
