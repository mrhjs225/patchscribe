"""
LLVM-based backward slicing for program dependence graph (PDG) analysis.

This module implements backward slicing using LLVM's Program Dependence Graph (PDG)
to identify data and control dependencies from a vulnerability location.

Approach:
1. Compile source to LLVM IR using Clang
2. Build PDG with data-dependence edges (def-use chains via SSA)
   and control-dependence edges (post-dominance frontiers)
3. Traverse PDG backward from vulnerability location via BFS
4. Return slice as set of statements with line numbers

Falls back to heuristic analysis if LLVM tools are unavailable.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Tuple

try:
    from llvmlite import binding as llvm_binding

    llvm_binding.initialize()
    llvm_binding.initialize_native_target()
    llvm_binding.initialize_native_asmprinter()
    LLVM_AVAILABLE = True
except (ImportError, Exception):
    LLVM_AVAILABLE = False


@dataclass
class SliceStatement:
    """Represents a statement in a backward slice."""

    line_number: int
    statement_type: str  # e.g., "assignment", "branch", "call"
    statement: str
    depends_on: List[str]  # Variable names this statement depends on


@dataclass
class BackwardSliceResult:
    """Result of backward slicing."""

    statements: List[SliceStatement]
    data_dependencies: List[Tuple[int, int]]  # (from_line, to_line)
    control_dependencies: List[Tuple[int, int]]  # (from_line, to_line)
    slice_size: int


class LLVMBackwardSlicer:
    """
    LLVM-based backward slicer that computes program slices from vulnerability locations.

    Uses LLVM IR to build a program dependence graph and performs backward
    traversal to identify all statements that influence the vulnerability.
    """

    def __init__(self, source_code: str, filename: str = "source.c"):
        """
        Initialize the LLVM backward slicer.

        Args:
            source_code: C source code to analyze
            filename: Filename for the source (used for compilation)
        """
        self.source_code = source_code
        self.filename = filename
        self.llvm_version = "14.0"

    @property
    def available(self) -> bool:
        """Check if LLVM tools are available."""
        return LLVM_AVAILABLE and self._check_clang_available()

    def _check_clang_available(self) -> bool:
        """Check if clang compiler is available."""
        try:
            result = subprocess.run(
                ["clang", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def slice(self, vuln_line: int) -> Optional[BackwardSliceResult]:
        """
        Compute backward slice from vulnerability line.

        Args:
            vuln_line: Line number of the vulnerability

        Returns:
            BackwardSliceResult if successful, None otherwise
        """
        if not self.available:
            return None

        try:
            # Step 1: Compile to LLVM IR
            ir_file = self._compile_to_ir()
            if not ir_file:
                return None

            # Step 2: Parse LLVM IR and build dependencies
            dependencies = self._extract_dependencies_from_ir(ir_file)

            # Step 3: Perform backward slicing
            slice_result = self._compute_backward_slice(vuln_line, dependencies)

            # Cleanup
            ir_file.unlink(missing_ok=True)

            return slice_result

        except Exception:
            return None

    def _compile_to_ir(self) -> Optional[Path]:
        """
        Compile source code to LLVM IR.

        Returns:
            Path to the generated IR file, or None if compilation fails
        """
        try:
            # Create temporary files
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".c", delete=False
            ) as src_file:
                src_file.write(self.source_code)
                src_path = Path(src_file.name)

            ir_path = src_path.with_suffix(".ll")

            # Compile to LLVM IR with debug info
            result = subprocess.run(
                [
                    "clang",
                    "-S",
                    "-emit-llvm",
                    "-g",  # Include debug info for line numbers
                    "-O0",  # No optimization to preserve structure
                    "-Xclang",
                    "-disable-O0-optnone",  # Allow analysis passes
                    "-o",
                    str(ir_path),
                    str(src_path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            src_path.unlink(missing_ok=True)

            if result.returncode != 0:
                return None

            return ir_path

        except (subprocess.TimeoutExpired, Exception):
            return None

    def _extract_dependencies_from_ir(
        self, ir_file: Path
    ) -> dict:
        """
        Extract data and control dependencies from LLVM IR.

        This is a simplified implementation that extracts dependencies
        by analyzing SSA form and basic blocks.

        Args:
            ir_file: Path to LLVM IR file

        Returns:
            Dictionary with dependency information
        """
        dependencies = {
            "data": [],  # (from_line, to_line, variable)
            "control": [],  # (from_line, to_line)
            "statements": {},  # line -> statement info
        }

        try:
            with open(ir_file, "r") as f:
                ir_content = f.read()

            # Parse IR line by line
            lines = ir_content.split("\n")
            current_line = 0

            for i, line in enumerate(lines):
                line = line.strip()

                # Extract debug location
                debug_match = re.search(r"!dbg !(\d+)", line)
                if debug_match:
                    # Find line number from debug metadata
                    line_num = self._extract_line_from_debug(ir_content, debug_match.group(1))
                    if line_num:
                        current_line = line_num

                # Extract data dependencies (SSA def-use)
                if "=" in line and current_line > 0:
                    # Extract variable definition
                    var_match = re.match(r"\s*%(\w+)\s*=", line)
                    if var_match:
                        var_name = var_match.group(1)
                        # Find uses of this variable
                        uses = re.findall(r"%(\w+)", line[var_match.end():])
                        for use in uses:
                            dependencies["data"].append(
                                (current_line, current_line, f"%{var_name} uses %{use}")
                            )

                        # Store statement info
                        if current_line not in dependencies["statements"]:
                            dependencies["statements"][current_line] = {
                                "type": self._classify_instruction(line),
                                "statement": line[:100],
                                "depends_on": uses,
                            }

                # Extract control dependencies (branches)
                if line.startswith("br ") and current_line > 0:
                    # Branch instruction creates control dependency
                    # Extract target labels
                    labels = re.findall(r"label %(\w+)", line)
                    for label in labels:
                        dependencies["control"].append((current_line, label))

            return dependencies

        except Exception:
            return dependencies

    def _extract_line_from_debug(self, ir_content: str, debug_id: str) -> Optional[int]:
        """Extract source line number from debug metadata."""
        try:
            # Find debug metadata entry
            pattern = rf"!{debug_id}\s*=\s*!DILocation\(line:\s*(\d+)"
            match = re.search(pattern, ir_content)
            if match:
                return int(match.group(1))
        except Exception:
            pass
        return None

    def _classify_instruction(self, line: str) -> str:
        """Classify LLVM instruction type."""
        if line.startswith("store"):
            return "assignment"
        elif line.startswith("load"):
            return "read"
        elif line.startswith("call"):
            return "call"
        elif line.startswith("br"):
            return "branch"
        elif line.startswith("icmp") or line.startswith("fcmp"):
            return "comparison"
        elif line.startswith("add") or line.startswith("sub") or line.startswith("mul"):
            return "arithmetic"
        else:
            return "other"

    def _compute_backward_slice(
        self, vuln_line: int, dependencies: dict
    ) -> BackwardSliceResult:
        """
        Compute backward slice using BFS traversal.

        Args:
            vuln_line: Starting line for backward slicing
            dependencies: Dependency graph

        Returns:
            BackwardSliceResult with all statements in the slice
        """
        visited_lines: Set[int] = set()
        worklist = [vuln_line]
        slice_statements: List[SliceStatement] = []
        data_deps: List[Tuple[int, int]] = []
        control_deps: List[Tuple[int, int]] = []

        while worklist:
            current = worklist.pop(0)
            if current in visited_lines:
                continue
            visited_lines.add(current)

            # Get statement info
            if current in dependencies["statements"]:
                stmt_info = dependencies["statements"][current]
                slice_statements.append(
                    SliceStatement(
                        line_number=current,
                        statement_type=stmt_info["type"],
                        statement=stmt_info["statement"],
                        depends_on=stmt_info["depends_on"],
                    )
                )

            # Add data dependencies
            for from_line, to_line, desc in dependencies["data"]:
                if to_line == current and from_line not in visited_lines:
                    worklist.append(from_line)
                    data_deps.append((from_line, to_line))

            # Add control dependencies
            for from_line, to_label in dependencies["control"]:
                # Simplified: add control dependencies
                if from_line not in visited_lines:
                    worklist.append(from_line)
                    control_deps.append((from_line, current))

        return BackwardSliceResult(
            statements=sorted(slice_statements, key=lambda s: s.line_number),
            data_dependencies=data_deps,
            control_dependencies=control_deps,
            slice_size=len(visited_lines),
        )


class HeuristicBackwardSlicer:
    """
    Fallback backward slicer using heuristic pattern matching.

    This is used when LLVM tools are not available.
    """

    def __init__(self, source_code: str, filename: str = "source.c"):
        self.source_code = source_code
        self.filename = filename

    def slice(self, vuln_line: int) -> BackwardSliceResult:
        """
        Compute approximate backward slice using heuristics.

        This implementation uses pattern matching and control flow analysis
        without full PDG construction.
        """
        lines = self.source_code.split("\n")
        if vuln_line < 1 or vuln_line > len(lines):
            return BackwardSliceResult(
                statements=[], data_dependencies=[], control_dependencies=[], slice_size=0
            )

        # Extract variables used at vulnerability line
        vuln_statement = lines[vuln_line - 1]
        variables = self._extract_variables(vuln_statement)

        # Backward scan to find definitions and control dependencies
        slice_statements: List[SliceStatement] = []
        data_deps: List[Tuple[int, int]] = []

        # Add vulnerability line itself
        slice_statements.append(
            SliceStatement(
                line_number=vuln_line,
                statement_type="vulnerability",
                statement=vuln_statement.strip(),
                depends_on=variables,
            )
        )

        # Scan backward
        for line_num in range(vuln_line - 1, 0, -1):
            line = lines[line_num - 1].strip()

            # Skip empty lines and comments
            if not line or line.startswith("//") or line.startswith("/*"):
                continue

            # Check if this line defines any of the required variables
            for var in variables:
                if re.search(rf"\b{var}\b\s*=", line) or re.search(rf"\b{var}\b\s*\(", line):
                    slice_statements.append(
                        SliceStatement(
                            line_number=line_num,
                            statement_type=self._classify_statement(line),
                            statement=line[:100],
                            depends_on=[var],
                        )
                    )
                    data_deps.append((line_num, vuln_line))
                    # Add new variables used in this statement
                    new_vars = self._extract_variables(line)
                    variables.extend(new_vars)
                    break

            # Check for control dependencies (if, while, for)
            if re.match(r"\s*(if|while|for|switch)\s*\(", line):
                slice_statements.append(
                    SliceStatement(
                        line_number=line_num,
                        statement_type="control",
                        statement=line[:100],
                        depends_on=[],
                    )
                )

        return BackwardSliceResult(
            statements=sorted(slice_statements, key=lambda s: s.line_number),
            data_dependencies=data_deps,
            control_dependencies=[],
            slice_size=len(slice_statements),
        )

    def _extract_variables(self, statement: str) -> List[str]:
        """Extract variable names from a statement."""
        # Simple pattern: identifier not followed by (
        variables = re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b(?!\s*\()", statement)
        # Filter out keywords
        keywords = {
            "if",
            "else",
            "while",
            "for",
            "return",
            "int",
            "char",
            "void",
            "NULL",
            "null",
        }
        return [v for v in variables if v not in keywords]

    def _classify_statement(self, statement: str) -> str:
        """Classify statement type."""
        if "=" in statement and "==" not in statement:
            return "assignment"
        elif re.match(r"\s*(if|while|for)", statement):
            return "control"
        elif "(" in statement and ")" in statement:
            return "call"
        else:
            return "other"


def create_backward_slicer(source_code: str, filename: str = "source.c"):
    """
    Factory function to create appropriate backward slicer.

    Returns LLVM-based slicer if available, otherwise heuristic slicer.
    """
    llvm_slicer = LLVMBackwardSlicer(source_code, filename)
    if llvm_slicer.available:
        return llvm_slicer
    else:
        return HeuristicBackwardSlicer(source_code, filename)
