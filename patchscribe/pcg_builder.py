"""
Aggregator that combines static, dynamic, symbolic, and absence analyses into a unified PCG.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .analysis.ast_analysis import ASTAnalyzer
from .analysis.dynamic_analysis import TaintAnalyzer
from .analysis.static_analysis import StaticAnalyzer
from .analysis.symbolic_analysis import SymbolicExplorer
from .analysis.absence_analysis import AbsenceAnalyzer, AbsenceAnalysisResult, AbsenceFinding
from .tools import AngrExplorer, ClangStaticAnalyzer
from .pcg import PCGEdge, PCGNode, ProgramCausalGraph, next_node_id

# Import enhanced analyzers if available
try:
    from .analysis.static_analysis_llvm import create_static_analyzer
    LLVM_STATIC_AVAILABLE = True
except ImportError:
    LLVM_STATIC_AVAILABLE = False

try:
    from .analysis.ast_analysis_pycparser import create_ast_analyzer
    PYCPARSER_AVAILABLE = True
except ImportError:
    PYCPARSER_AVAILABLE = False

# Import LLVM backward slicer
try:
    from .tools.llvm_slicer import create_backward_slicer
    LLVM_SLICER_AVAILABLE = True
except ImportError:
    LLVM_SLICER_AVAILABLE = False


@dataclass
class PCGBuilderConfig:
    taint_sources: List[str] = field(
        default_factory=lambda: ["gets", "fgets", "scanf", "read", "recv"]
    )
    use_llvm_slicing: bool = True  # Use LLVM backward slicing if available
    apply_causal_filtering: bool = True  # Apply IsCausalRelation filtering (40% reduction)
    apply_transitive_reduction: bool = True  # Apply transitive reduction
    strict_dependencies: bool = True  # Require LLVM/Clang tooling (no silent fallback)
    require_precise_static: bool = True  # Disallow regex-only static analysis
    enable_absence_detection: bool = True  # Emit MissingGuard nodes


class PCGBuilder:
    def __init__(self, program: str, vuln_info: Dict[str, object], config: PCGBuilderConfig | None = None) -> None:
        self.program = program
        self.vuln_info = vuln_info
        self.config = config or PCGBuilderConfig()
        self.seq: Dict[str, int] = {}
        self.lines = self.program.splitlines()
        allow_relaxed = (
            os.environ.get("PATCHSCRIBE_ALLOW_HEURISTICS", "").strip().lower()
            in {"1", "true", "yes"}
        )
        self._strict_analysis = self.config.strict_dependencies and not allow_relaxed
        self._ensure_dependencies()
        self.absence_labels = self._normalize_absence_labels()

    def build(self) -> Tuple[ProgramCausalGraph, Dict[str, object]]:
        analyzer_usage: Dict[str, object] = {}
        fallback_modes: List[str] = []

        # Step 1: LLVM backward slicing (if enabled and available)
        slice_result = None
        if self.config.use_llvm_slicing and LLVM_SLICER_AVAILABLE:
            slicer = create_backward_slicer(self.program)
            slice_result = slicer.slice(self.vuln_info["location"])
            analyzer_usage["llvm_slice"] = bool(slice_result)
        else:
            analyzer_usage["llvm_slice"] = False

        # Use enhanced analyzers if available, otherwise fallback to regex-based
        if LLVM_STATIC_AVAILABLE:
            static_analyzer = create_static_analyzer(self.program, self.vuln_info["location"])
            static = static_analyzer.run()
            analyzer_usage["static"] = "llvm"
        else:
            static = StaticAnalyzer(self.program, self.vuln_info["location"]).run()
            analyzer_usage["static"] = "regex"
            fallback_modes.append("static_regex")

        if PYCPARSER_AVAILABLE:
            ast_analyzer = create_ast_analyzer(self.program, self.vuln_info["location"])
            ast_result = ast_analyzer.run()
            analyzer_usage["ast"] = "pycparser"
        else:
            ast_result = ASTAnalyzer(self.program, self.vuln_info["location"]).run()
            analyzer_usage["ast"] = "regex"
            fallback_modes.append("ast_regex")

        clang_result = ClangStaticAnalyzer(self.program).run(self.vuln_info["location"])
        analyzer_usage["clang"] = bool(clang_result)
        dynamic = TaintAnalyzer(
            self.program,
            self.vuln_info["location"],
            self.config.taint_sources,
        ).run()
        analyzer_usage["dynamic"] = "taint_sim"
        symbolic = SymbolicExplorer(self.program, self.vuln_info["location"]).run()
        analyzer_usage["symbolic"] = "heuristic"
        angr_result = AngrExplorer(self.program).run()
        analyzer_usage["angr"] = bool(angr_result)
        absence_result: AbsenceAnalysisResult | None = None
        if self.config.enable_absence_detection:
            absence_result = AbsenceAnalyzer(
                self.program,
                self.vuln_info["location"],
                expected_patterns=self.absence_labels,
            ).run()
            analyzer_usage["absence"] = True
        graphs = [static.graph, ast_result.graph, dynamic.graph, symbolic.graph]

        # Add LLVM slice graph if available
        if slice_result:
            graphs.append(self._graph_from_slice(slice_result))

        if clang_result:
            graphs.append(self._graph_from_clang(clang_result))
        if angr_result:
            graphs.append(self._graph_from_angr(angr_result))
        if absence_result:
            graphs.append(absence_result.graph)

        combined = self._merge_graphs(graphs)
        self._enrich_node_metadata(combined)
        if absence_result and absence_result.findings:
            self._attach_absence_nodes(combined, absence_result.findings)

        # Step 2: Apply causal relation filtering (40% edge reduction)
        if self.config.apply_causal_filtering:
            combined = self._filter_causal_relations(combined)

        # Step 3: Apply transitive reduction
        pre_reduction_edges = len(combined.edges)
        if self.config.apply_transitive_reduction:
            combined = self._apply_transitive_reduction(combined)
        post_reduction_edges = len(combined.edges)

        edge_metrics = self._summarize_edges(combined)
        node_metrics = self._summarize_nodes(combined)
        metadata = {
            "static_trace": static.trace,
            "ast_trace": ast_result.trace,
            "dynamic_lines": dynamic.executed_lines,
            "symbolic_conditions": symbolic.path_conditions,
            "clang_nodes": [node.__dict__ for node in clang_result.nodes] if clang_result else [],
            "angr_paths": [path.__dict__ for path in angr_result.paths] if angr_result else [],
            "slice_result": {
                "size": slice_result.slice_size if slice_result else 0,
                "data_deps": len(slice_result.data_dependencies) if slice_result else 0,
                "control_deps": len(slice_result.control_dependencies) if slice_result else 0,
            } if slice_result else None,
            "absence_findings": [
                finding.to_dict() for finding in (absence_result.findings if absence_result else [])
            ],
            "pcg_summary": {
                "node_count": len(combined.nodes),
                "edge_count": len(combined.edges),
                "missing_guard_count": sum(
                    1 for node in combined.nodes.values() if node.node_type == "missing_guard"
                ),
                "edge_type_counts": edge_metrics,
                "node_type_counts": node_metrics,
            },
            "absence_metrics": absence_result.metrics if absence_result else None,
            "analyzer_usage": analyzer_usage,
            "fallback_modes": fallback_modes,
            "reduction_stats": {
                "before": pre_reduction_edges,
                "after": post_reduction_edges,
                "removed": max(0, pre_reduction_edges - post_reduction_edges),
            },
        }
        return combined, metadata

    def _ensure_dependencies(self) -> None:
        """Fail fast if strict analysis is requested but dependencies are missing."""
        if not self._strict_analysis:
            return

        missing: List[str] = []
        if self.config.use_llvm_slicing and not LLVM_SLICER_AVAILABLE:
            missing.append("llvm_slicer")
        if self.config.require_precise_static and not LLVM_STATIC_AVAILABLE:
            missing.append("llvm_static")
        if missing:
            raise RuntimeError(
                "Precise analysis requested but dependencies unavailable: "
                + ", ".join(missing)
                + ". Set PATCHSCRIBE_ALLOW_HEURISTICS=1 to fall back for testing."
            )

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

    def _graph_from_slice(self, slice_result) -> ProgramCausalGraph:
        """
        Convert LLVM backward slice result to PCG.

        Args:
            slice_result: BackwardSliceResult from LLVM slicer

        Returns:
            ProgramCausalGraph with slice statements as nodes
        """
        graph = ProgramCausalGraph()
        id_map: Dict[int, str] = {}

        # Create nodes from slice statements
        for stmt in slice_result.statements:
            node_id = next_node_id(self.seq, "l")
            id_map[stmt.line_number] = node_id
            graph.add_node(
                PCGNode(
                    node_id=node_id,
                    node_type=stmt.statement_type,
                    description=stmt.statement[:100],
                    location=stmt.line_number,
                    metadata={"depends_on": stmt.depends_on},
                )
            )

        # Add data dependencies as edges
        for from_line, to_line in slice_result.data_dependencies:
            if from_line in id_map and to_line in id_map:
                graph.add_edge(
                    PCGEdge(
                        source=id_map[from_line],
                        target=id_map[to_line],
                        edge_type="data_flow",
                        rationale="LLVM SSA def-use chain",
                    )
                )

        # Add control dependencies as edges
        for from_line, to_line in slice_result.control_dependencies:
            if from_line in id_map and to_line in id_map:
                graph.add_edge(
                    PCGEdge(
                        source=id_map[from_line],
                        target=id_map[to_line],
                        edge_type="control_flow",
                        rationale="LLVM control dependence",
                    )
                )

        return graph

    def _filter_causal_relations(self, graph: ProgramCausalGraph) -> ProgramCausalGraph:
        """
        Apply IsCausalRelation filtering to remove non-security-relevant edges.

        Paper describes (Section 4.1):
        - Keep data-dep if target uses value in security-relevant operation
          (pointer deref, array index, malloc size, format string)
        - Keep control-dep if branch affects security-critical statement
        - Keep resource init/cleanup affecting safety

        Expected: ~40% edge reduction while preserving security-relevant paths

        Args:
            graph: Input PCG

        Returns:
            Filtered PCG with security-relevant edges only
        """
        # Security-relevant patterns
        security_patterns = {
            # Pointer/array operations
            "deref", "dereference", "pointer", "->", "*", "[", "]",
            # Memory operations
            "malloc", "calloc", "realloc", "free", "alloc", "memcpy", "memset", "strcpy", "strcat",
            # Input/output operations
            "read", "write", "recv", "send", "gets", "fgets", "scanf", "printf", "sprintf",
            # Bounds checking
            "size", "length", "len", "count", "index", "bound", "limit",
            # Validation
            "check", "validate", "verify", "assert",
        }

        filtered_graph = ProgramCausalGraph()

        # Keep all nodes
        for node in graph.nodes.values():
            filtered_graph.add_node(node)

        # Filter edges based on security relevance
        for edge in graph.edges:
            src_node = graph.nodes[edge.source]
            dst_node = graph.nodes[edge.target]

            # Always keep edges to/from vulnerability-related nodes
            if self._is_security_relevant_node(src_node, security_patterns) or \
               self._is_security_relevant_node(dst_node, security_patterns):
                filtered_graph.add_edge(edge)
            # For data flow edges, check if target uses value in security-relevant way
            elif edge.edge_type == "data_flow":
                if self._is_security_relevant_operation(dst_node, security_patterns):
                    filtered_graph.add_edge(edge)
            # For control flow edges, check if branch affects security-critical statement
            elif edge.edge_type == "control_flow":
                if self._is_security_critical_branch(src_node, dst_node, security_patterns):
                    filtered_graph.add_edge(edge)

        return filtered_graph

    def _is_security_relevant_node(self, node: PCGNode, patterns: set) -> bool:
        """Check if node is security-relevant based on patterns."""
        description = node.description.lower()
        return any(pattern in description for pattern in patterns)

    def _is_security_relevant_operation(self, node: PCGNode, patterns: set) -> bool:
        """Check if node performs security-relevant operation."""
        description = node.description.lower()
        # Check for pointer/array operations
        if any(op in description for op in ["->", "*", "[", "]"]):
            return True
        # Check for security-sensitive functions
        return any(pattern in description for pattern in patterns)

    def _is_security_critical_branch(self, src: PCGNode, dst: PCGNode, patterns: set) -> bool:
        """Check if control flow edge represents security-critical branching."""
        # Branches that check bounds, validation, or error conditions are critical
        src_desc = src.description.lower()
        dst_desc = dst.description.lower()
        critical_keywords = {"check", "validate", "verify", "assert", "null", "size", "length", "bound"}
        return any(kw in src_desc or kw in dst_desc for kw in critical_keywords)

    def _apply_transitive_reduction(self, graph: ProgramCausalGraph) -> ProgramCausalGraph:
        """
        Apply transitive reduction to remove redundant edges.

        Paper describes (Section 4.1):
        - Uses Aho-Garey-Ullman algorithm
        - Complexity: O(|V|^3)
        - Expected: Reduces 42 edges to 18 while preserving causal paths

        Args:
            graph: Input PCG

        Returns:
            Transitively reduced PCG
        """
        # Build adjacency matrix for transitive closure
        nodes = list(graph.nodes.keys())
        n = len(nodes)
        node_to_idx = {node_id: i for i, node_id in enumerate(nodes)}

        # Initialize reachability matrix
        reach = [[False] * n for _ in range(n)]

        # Set direct edges
        for edge in graph.edges:
            if edge.source in node_to_idx and edge.target in node_to_idx:
                i = node_to_idx[edge.source]
                j = node_to_idx[edge.target]
                reach[i][j] = True

        # Compute transitive closure using Warshall's algorithm
        for k in range(n):
            for i in range(n):
                for j in range(n):
                    reach[i][j] = reach[i][j] or (reach[i][k] and reach[k][j])

        # Create reduced graph
        reduced = ProgramCausalGraph()

        # Keep all nodes
        for node in graph.nodes.values():
            reduced.add_node(node)

        # Keep only non-transitive edges
        for edge in graph.edges:
            if edge.source not in node_to_idx or edge.target not in node_to_idx:
                reduced.add_edge(edge)
                continue

            src_idx = node_to_idx[edge.source]
            dst_idx = node_to_idx[edge.target]

            # Check if there's an alternative path from src to dst
            has_alternative_path = False
            for k in range(n):
                if k != src_idx and k != dst_idx:
                    if reach[src_idx][k] and reach[k][dst_idx]:
                        has_alternative_path = True
                        break

            # Keep edge if it's not redundant (no alternative path)
            if not has_alternative_path:
                reduced.add_edge(edge)

        return reduced

    def _attach_absence_nodes(
        self,
        graph: ProgramCausalGraph,
        findings: List[AbsenceFinding],
    ) -> None:
        """Connect MissingGuard nodes to the most relevant vulnerability nodes."""
        vuln_nodes = [
            node for node in graph.nodes.values() if node.node_type == "vulnerability"
        ]
        vuln_target = vuln_nodes[0].node_id if vuln_nodes else None

        for finding in findings:
            evidence = getattr(finding, "evidence", {}) or {}
            node_id = evidence.get("node_id")
            line = getattr(finding, "line", None)
            rationale = getattr(finding, "rationale", "")

            if not node_id or node_id not in graph.nodes:
                continue

            target_id = (
                self._find_node_at_line(graph, line)
                if line is not None
                else None
            )
            if not target_id:
                target_id = vuln_target

            if not target_id:
                continue

            graph.add_edge(
                PCGEdge(
                    source=node_id,
                    target=target_id,
                    edge_type="absence",
                    rationale=rationale or "missing guard influences vulnerability",
                )
            )

    def _find_node_at_line(self, graph: ProgramCausalGraph, line: int | None) -> str | None:
        if line is None:
            return None
        for node in graph.nodes.values():
            if node.node_id.startswith("m"):
                continue
            if node.location == line:
                return node.node_id
        return None

    @staticmethod
    def _summarize_edges(graph: ProgramCausalGraph) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for edge in graph.edges:
            counts[edge.edge_type] = counts.get(edge.edge_type, 0) + 1
        return counts

    @staticmethod
    def _summarize_nodes(graph: ProgramCausalGraph) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for node in graph.nodes.values():
            counts[node.node_type] = counts.get(node.node_type, 0) + 1
        return counts

    def _enrich_node_metadata(self, graph: ProgramCausalGraph) -> None:
        """Populate identifier/datatype/value_range metadata for SCM + SMT layers."""
        for node in graph.nodes.values():
            metadata = node.metadata or {}
            identifier = metadata.get("identifier") or self._infer_identifier(node)
            datatype = metadata.get("datatype") or self._infer_datatype(node)
            value_range = metadata.get("value_range") or self._infer_value_range(node)
            if identifier:
                metadata["identifier"] = identifier
            if datatype:
                metadata["datatype"] = datatype
            if value_range:
                metadata["value_range"] = value_range
            node.metadata = metadata

    def _infer_identifier(self, node: PCGNode) -> str:
        description = node.description or ""
        tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", description)
        if tokens:
            return tokens[0]
        line_text = self._line_text(node.location)
        matches = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", line_text)
        return matches[0] if matches else node.node_id

    def _infer_datatype(self, node: PCGNode) -> str:
        desc = (node.description or "").lower()
        if "pointer" in desc or "*" in desc or "->" in desc:
            return "pointer"
        if "len" in desc or "size" in desc or "[" in desc:
            return "size"
        if node.node_type in {"predicate", "missing_guard", "vulnerability"}:
            return "bool"
        return "int"

    def _infer_value_range(self, node: PCGNode) -> List[str]:
        line = self._line_text(node.location).strip()
        ranges: List[str] = []
        if not line:
            return ranges
        for match in re.finditer(r"(<=|>=|<|>)\s*([0-9]+)", line):
            ranges.append(f"{match.group(1)} {match.group(2)}")
        for match in re.finditer(r"\[(\d+)\]", line):
            ranges.append(f"< {match.group(1)}")
        if "NULL" in line or "null" in line.lower():
            ranges.append("!= NULL")
        return ranges

    def _line_text(self, line_number: int | None) -> str:
        if line_number and 1 <= line_number <= len(self.lines):
            return self.lines[line_number - 1]
        return ""

    def _normalize_absence_labels(self) -> List[str]:
        labels = self.vuln_info.get("absence_labels")
        normalized: List[str] = []
        if not labels:
            return normalized
        if isinstance(labels, dict):
            for pattern, count in labels.items():
                if not isinstance(pattern, str):
                    continue
                repeats = 1
                if isinstance(count, int) and count > 1:
                    repeats = count
                normalized.extend([pattern] * repeats)
            return normalized
        if isinstance(labels, (list, tuple, set)):
            for entry in labels:
                if isinstance(entry, str):
                    normalized.append(entry)
                elif isinstance(entry, dict) and isinstance(entry.get("pattern"), str):
                    normalized.append(entry["pattern"])
        return normalized
