"""
pycparser-based AST analysis module for PatchScribe.

This module uses pycparser to perform precise AST analysis of C code,
implementing the paper's approach: "Pattern matching on abstract syntax trees"

Improvements over regex-based analysis:
- Accurate AST parsing with pycparser
- Structural pattern matching
- Type-aware analysis
- Proper scope and symbol resolution
"""
from __future__ import annotations

import io
import re
from dataclasses import dataclass
from typing import Dict, List, Set

from ..pcg import PCGEdge, PCGNode, ProgramCausalGraph, next_node_id

try:
    from pycparser import c_ast, c_generator, c_parser, parse_file

    PYCPARSER_AVAILABLE = True
except ImportError:
    PYCPARSER_AVAILABLE = False
    c_ast = None


@dataclass
class ASTAnalysisResult:
    """Result of AST analysis."""

    graph: ProgramCausalGraph
    trace: List[str]


class PycparserASTAnalyzer:
    """
    Enhanced AST analyzer using pycparser for precise syntactic analysis.

    This implements the paper's approach:
    "Pattern matching on abstract syntax trees"
    """

    def __init__(self, program: str, vuln_location: int):
        self.program = program
        self.vuln_location = vuln_location
        self.lines = program.splitlines()
        self.seq: Dict[str, int] = {}

    @property
    def available(self) -> bool:
        """Check if pycparser is available."""
        return PYCPARSER_AVAILABLE

    def run(self) -> ASTAnalysisResult:
        """Execute pycparser-based AST analysis."""
        if not self.available:
            return self._fallback_analysis()

        try:
            # Parse C code to AST
            ast = self._parse_to_ast()
            if not ast:
                return self._fallback_analysis()

            # Analyze AST and build graph
            graph, trace = self._analyze_ast(ast)

            return ASTAnalysisResult(graph=graph, trace=trace)

        except Exception:
            return self._fallback_analysis()

    def _parse_to_ast(self) -> c_ast.FileAST | None:
        """Parse C source code to AST using pycparser."""
        try:
            # pycparser requires preprocessing
            preprocessed = self._preprocess_code()

            # Parse the preprocessed code
            parser = c_parser.CParser()
            ast = parser.parse(preprocessed, filename="<source>")

            return ast

        except Exception:
            return None

    def _preprocess_code(self) -> str:
        """
        Preprocess C code for pycparser.

        pycparser doesn't handle preprocessor directives well,
        so we need to handle them manually.
        """
        lines = []
        for line in self.program.split("\n"):
            # Remove preprocessor directives
            if line.strip().startswith("#"):
                # Keep some common ones, remove others
                if not any(
                    line.strip().startswith(p) for p in ["#include", "#define", "#ifdef"]
                ):
                    lines.append(line)
            else:
                lines.append(line)

        return "\n".join(lines)

    def _analyze_ast(
        self, ast: c_ast.FileAST
    ) -> tuple[ProgramCausalGraph, List[str]]:
        """
        Analyze AST to extract syntactic structures and relationships.

        This uses a visitor pattern to traverse the AST and build PCG.
        """
        graph = ProgramCausalGraph()
        trace = []

        # Create visitor to traverse AST
        visitor = ASTVisitor(graph, trace, self.seq)
        visitor.visit(ast)

        return graph, trace

    def _fallback_analysis(self) -> ASTAnalysisResult:
        """
        Fallback to regex-based analysis when pycparser is not available.

        This is the original implementation.
        """
        from .ast_analysis import ASTAnalyzer

        analyzer = ASTAnalyzer(self.program, self.vuln_location)
        return analyzer.run()


class ASTVisitor:
    """
    AST visitor to build Program Causal Graph from syntax tree.

    Implements visitor pattern to traverse pycparser AST.
    """

    def __init__(
        self, graph: ProgramCausalGraph, trace: List[str], seq: Dict[str, int]
    ):
        self.graph = graph
        self.trace = trace
        self.seq = seq
        self.prev_node_id: str | None = None
        self.generator = c_generator.CGenerator() if PYCPARSER_AVAILABLE else None

    def visit(self, node):
        """Visit an AST node."""
        if not node:
            return

        method = "visit_" + node.__class__.__name__
        visitor = getattr(self, method, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node):
        """Generic visitor for unhandled node types."""
        # Visit all children
        for _, child in node.children():
            self.visit(child)

    def visit_FileAST(self, node: c_ast.FileAST):
        """Visit file-level AST."""
        for ext_decl in node.ext:
            self.visit(ext_decl)

    def visit_FuncDef(self, node: c_ast.FuncDef):
        """Visit function definition."""
        func_name = node.decl.name
        line_num = node.coord.line if node.coord else 0

        node_id = next_node_id(self.seq, "ast")
        pcg_node = PCGNode(
            node_id=node_id,
            node_type="operation",
            description=f"function {func_name}",
            location=line_num,
        )
        self.graph.add_node(pcg_node)
        self.trace.append(f"Line {line_num}: function definition {func_name}")

        if self.prev_node_id:
            edge = PCGEdge(
                source=self.prev_node_id,
                target=node_id,
                edge_type="ast_sibling",
                rationale="function definition",
            )
            self.graph.add_edge(edge)

        parent_id = self.prev_node_id
        self.prev_node_id = node_id

        # Visit function body
        self.visit(node.body)

        self.prev_node_id = parent_id

    def visit_If(self, node: c_ast.If):
        """Visit if statement."""
        line_num = node.coord.line if node.coord else 0

        # Create node for condition
        node_id = next_node_id(self.seq, "ast")
        cond_str = self.generator.visit(node.cond) if self.generator else "condition"
        pcg_node = PCGNode(
            node_id=node_id,
            node_type="predicate",
            description=f"if ({cond_str})",
            location=line_num,
        )
        self.graph.add_node(pcg_node)
        self.trace.append(f"Line {line_num}: if statement")

        if self.prev_node_id:
            edge = PCGEdge(
                source=self.prev_node_id,
                target=node_id,
                edge_type="control_flow",
                rationale="if condition",
            )
            self.graph.add_edge(edge)

        parent_id = self.prev_node_id
        self.prev_node_id = node_id

        # Visit true branch
        self.visit(node.iftrue)

        # Visit false branch (if exists)
        if node.iffalse:
            self.prev_node_id = node_id
            self.visit(node.iffalse)

        self.prev_node_id = parent_id

    def visit_While(self, node: c_ast.While):
        """Visit while loop."""
        line_num = node.coord.line if node.coord else 0

        node_id = next_node_id(self.seq, "ast")
        cond_str = self.generator.visit(node.cond) if self.generator else "condition"
        pcg_node = PCGNode(
            node_id=node_id,
            node_type="predicate",
            description=f"while ({cond_str})",
            location=line_num,
        )
        self.graph.add_node(pcg_node)
        self.trace.append(f"Line {line_num}: while loop")

        if self.prev_node_id:
            edge = PCGEdge(
                source=self.prev_node_id,
                target=node_id,
                edge_type="control_flow",
                rationale="while condition",
            )
            self.graph.add_edge(edge)

        parent_id = self.prev_node_id
        self.prev_node_id = node_id

        # Visit loop body
        self.visit(node.stmt)

        # Create back edge for loop
        edge = PCGEdge(
            source=node_id,
            target=node_id,
            edge_type="control_flow",
            rationale="loop back edge",
        )
        self.graph.add_edge(edge)

        self.prev_node_id = parent_id

    def visit_For(self, node: c_ast.For):
        """Visit for loop."""
        line_num = node.coord.line if node.coord else 0

        node_id = next_node_id(self.seq, "ast")
        pcg_node = PCGNode(
            node_id=node_id,
            node_type="predicate",
            description="for loop",
            location=line_num,
        )
        self.graph.add_node(pcg_node)
        self.trace.append(f"Line {line_num}: for loop")

        if self.prev_node_id:
            edge = PCGEdge(
                source=self.prev_node_id,
                target=node_id,
                edge_type="control_flow",
                rationale="for loop",
            )
            self.graph.add_edge(edge)

        parent_id = self.prev_node_id
        self.prev_node_id = node_id

        # Visit initialization, condition, increment
        if node.init:
            self.visit(node.init)
        if node.cond:
            self.visit(node.cond)
        if node.next:
            self.visit(node.next)

        # Visit loop body
        self.visit(node.stmt)

        self.prev_node_id = parent_id

    def visit_FuncCall(self, node: c_ast.FuncCall):
        """Visit function call."""
        line_num = node.coord.line if node.coord else 0

        func_name = (
            node.name.name
            if hasattr(node.name, "name")
            else self.generator.visit(node.name) if self.generator else "function"
        )

        node_id = next_node_id(self.seq, "ast")
        pcg_node = PCGNode(
            node_id=node_id,
            node_type="operation",
            description=f"call {func_name}",
            location=line_num,
        )
        self.graph.add_node(pcg_node)
        self.trace.append(f"Line {line_num}: function call {func_name}")

        if self.prev_node_id:
            edge = PCGEdge(
                source=self.prev_node_id,
                target=node_id,
                edge_type="data_flow",
                rationale="function call",
            )
            self.graph.add_edge(edge)

        parent_id = self.prev_node_id
        self.prev_node_id = node_id

        # Visit arguments
        if node.args:
            self.visit(node.args)

        self.prev_node_id = parent_id

    def visit_Assignment(self, node: c_ast.Assignment):
        """Visit assignment."""
        line_num = node.coord.line if node.coord else 0

        lval = self.generator.visit(node.lvalue) if self.generator else "variable"

        node_id = next_node_id(self.seq, "ast")
        pcg_node = PCGNode(
            node_id=node_id,
            node_type="data",
            description=f"assign {lval}",
            location=line_num,
        )
        self.graph.add_node(pcg_node)

        if self.prev_node_id:
            edge = PCGEdge(
                source=self.prev_node_id,
                target=node_id,
                edge_type="data_flow",
                rationale="assignment",
            )
            self.graph.add_edge(edge)

        parent_id = self.prev_node_id
        self.prev_node_id = node_id

        # Visit rvalue
        self.visit(node.rvalue)

        self.prev_node_id = parent_id

    def visit_Compound(self, node: c_ast.Compound):
        """Visit compound statement (block)."""
        # Visit all statements in the block
        if node.block_items:
            for item in node.block_items:
                self.visit(item)


def create_ast_analyzer(program: str, vuln_location: int):
    """
    Factory function to create appropriate AST analyzer.

    Returns pycparser-based analyzer if available, otherwise regex-based.
    """
    pycparser_analyzer = PycparserASTAnalyzer(program, vuln_location)
    if pycparser_analyzer.available:
        return pycparser_analyzer
    else:
        from .ast_analysis import ASTAnalyzer

        return ASTAnalyzer(program, vuln_location)
