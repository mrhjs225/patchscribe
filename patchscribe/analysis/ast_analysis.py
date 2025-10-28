"""
AST-driven causal analysis using pycparser to supplement heuristic PCG construction.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence

from ..pcg import PCGEdge, PCGNode, ProgramCausalGraph, next_node_id

try:  # pragma: no cover - optional dependency
    from pycparser import c_parser, c_ast, c_generator
except Exception:  # pragma: no cover - pycparser not installed
    c_parser = None
    c_ast = None
    c_generator = None


@dataclass
class ASTAnalysisResult:
    graph: ProgramCausalGraph
    trace: List[str]


class ASTAnalyzer:
    """
    Lightweight visitor over a pycparser AST that extracts assignment and predicate
    nodes which mention variables present in the vulnerability line. This offers a
    more structured signal than regex-based heuristics while remaining defensive
    against parse failures.
    """

    def __init__(self, source: str, vuln_line: int) -> None:
        self.source = source
        self.vuln_line = vuln_line
        self.seq: Dict[str, int] = {}
        self.trace: List[str] = []
        self.generator = c_generator.CGenerator() if c_generator else None

    def run(self) -> ASTAnalysisResult:
        graph = ProgramCausalGraph()
        if not c_parser or not self.generator:
            self.trace.append("pycparser unavailable - skipping AST analysis")
            return ASTAnalysisResult(graph, self.trace)
        parser = c_parser.CParser()
        preprocessed = self._strip_includes(self.source)
        try:
            ast = parser.parse(preprocessed)
        except Exception as exc:  # pragma: no cover - parse errors
            self.trace.append(f"pycparser parse failure: {exc}")
            return ASTAnalysisResult(graph, self.trace)

        vulnerability_line = self._clamp_line(self.vuln_line, self.source)
        vuln_text = self._line_at(vulnerability_line)
        vuln_tokens = _tokenize(vuln_text)

        vuln_node = self._register_node(
            graph,
            node_type="vulnerability",
            description=vuln_text.strip() or "vulnerability",
            line=vulnerability_line,
        )

        visitor = _CausalVisitor(
            graph=graph,
            generator=self.generator,
            vuln_tokens=vuln_tokens,
            vuln_line=vulnerability_line,
            register=self._register_node,
            trace=self.trace,
        )
        visitor.visit(ast)

        # Connect discovered nodes that precede the vulnerability.
        for node in list(graph.nodes.values()):
            if node.node_id == vuln_node.node_id:
                continue
            if node.location and node.location > vulnerability_line:
                continue
            graph.add_edge(
                PCGEdge(
                    source=node.node_id,
                    target=vuln_node.node_id,
                    edge_type="ast",
                    rationale="AST dependency mentioning vulnerability tokens",
                )
            )
        return ASTAnalysisResult(graph, self.trace)

    @staticmethod
    def _strip_includes(source: str) -> str:
        lines = []
        for line in source.splitlines():
            if line.lstrip().startswith("#include"):
                continue
            lines.append(line)
        return "\n".join(lines)

    def _line_at(self, line_no: int) -> str:
        lines = self.source.splitlines()
        if 1 <= line_no <= len(lines):
            return lines[line_no - 1]
        return ""

    @staticmethod
    def _clamp_line(line_no: int, source: str) -> int:
        lines = source.splitlines()
        if not lines:
            return 1
        return max(1, min(line_no, len(lines)))

    def _register_node(
        self,
        graph: ProgramCausalGraph,
        *,
        node_type: str,
        description: str,
        line: int | None,
    ) -> PCGNode:
        node = PCGNode(
            node_id=next_node_id(self.seq, node_type[:1]),
            node_type=node_type,
            description=description.strip(),
            location=line,
            metadata={"origin": "pycparser"},
        )
        graph.add_node(node)
        self.trace.append(f"AST node {node.node_id} ({node_type}) @ line {line}: {description.strip()}")
        return node


# Only define _CausalVisitor if pycparser is available
if c_ast is not None:
    class _CausalVisitor(c_ast.NodeVisitor):  # type: ignore[misc]
        def __init__(
            self,
            *,
            graph: ProgramCausalGraph,
            generator,
            vuln_tokens: Sequence[str],
            vuln_line: int,
            register,
            trace: List[str],
        ) -> None:
            self.graph = graph
            self.gen = generator
            self.tokens = set(vuln_tokens)
            self.vuln_line = vuln_line
            self.register = register
            self.trace = trace

        # Generic visit ensures traversal continues even when specific handlers fail.
        def generic_visit(self, node):  # pragma: no cover - pycparser internals
            for _, child in node.children():
                self.visit(child)

        def visit_Assignment(self, node):  # type: ignore[override]
            coord = getattr(node, "coord", None)
            line = getattr(coord, "line", None)
            if not line or line > self.vuln_line:
                return
            text = self.gen.visit(node)
            if not self._mentions_vulnerability(text):
                return
            self.register(
                self.graph,
                node_type="assignment",
                description=text,
                line=line,
            )

        def visit_FuncCall(self, node):  # type: ignore[override]
            coord = getattr(node, "coord", None)
            line = getattr(coord, "line", None)
            if not line or line > self.vuln_line:
                return
            text = self.gen.visit(node)
            if not self._mentions_vulnerability(text):
                return
            self.register(
                self.graph,
                node_type="call",
                description=text,
                line=line,
            )

        def visit_If(self, node):  # type: ignore[override]
            coord = getattr(node, "coord", None)
            line = getattr(coord, "line", None)
            if not line or line > self.vuln_line:
                return
            cond_text = self.gen.visit(node.cond)
            if not self._mentions_vulnerability(cond_text):
                return
            self.register(
                self.graph,
                node_type="predicate",
                description=cond_text,
                line=line,
            )
            # Continue traversal into branches to discover additional dependencies.
            self.visit(node.iftrue)
            if node.iffalse:
                self.visit(node.iffalse)

        def _mentions_vulnerability(self, text: str) -> bool:
            if not text:
                return False
            for token in self.tokens:
                if token and token in text:
                    return True
            return False
else:
    # Fallback when pycparser is not available
    _CausalVisitor = None  # type: ignore[misc,assignment]


def _tokenize(line: str) -> List[str]:
    tokens: List[str] = []
    current = []
    for ch in line:
        if ch.isalnum() or ch == "_":
            current.append(ch)
            continue
        if current:
            tokens.append("".join(current))
            current = []
    if current:
        tokens.append("".join(current))
    return tokens
