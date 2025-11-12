"""
Patch synthesis guided by intervention specifications and layered heuristics.
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple

from .intervention import InterventionSpec
from .pcg import PCGNode, ProgramCausalGraph
from .llm import LLMClient, LLMUnavailable, PromptOptions

# Import SpecificationLevel for type hints (avoid circular import)
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .spec_builder import SpecificationLevel


@dataclass
class PatchResult:
    patched_code: str
    diff: str
    applied_guards: List[str] = field(default_factory=list)
    method: str = "heuristic"
    llm_metadata: Optional[dict] = None
    notes: List[str] = field(default_factory=list)


class PatchGenerator:
    def __init__(
        self,
        graph: ProgramCausalGraph,
        program: str,
        vuln_line: int,
        signature: str,
        llm_client: LLMClient | None = None,
        spec_level: Optional["SpecificationLevel"] = None,  # NEW: Unified prompt
        strategy: str = "formal",  # Deprecated, kept for compatibility
        natural_context: str | None = None,  # Deprecated
        prompt_options: PromptOptions | None = None,
    ) -> None:
        self.graph = graph
        self.program = program
        self.vuln_line = vuln_line
        self.signature = signature
        self.llm_client = llm_client or LLMClient()
        self.spec_level = spec_level  # NEW
        self.strategy = strategy
        self.natural_context = natural_context
        self.prompt_options = prompt_options

    def generate(self, spec: InterventionSpec) -> PatchResult:
        # Only attempt LLM-guided patch. If it fails, return noop.
        llm_result = self._try_llm_patch(spec)
        if llm_result:
            return llm_result

        # LLM patch generation failed - return noop result.
        return PatchResult(patched_code=self.program, diff="", applied_guards=[], method="noop")

    def _try_llm_patch(self, spec: InterventionSpec) -> PatchResult | None:
        if not spec.interventions:
            return None
        try:
            patched = self.llm_client.generate_patch(
                original_code=self.program,
                vulnerability_signature=self.signature,
                interventions=[intervention.__dict__ for intervention in spec.interventions],
                spec_level=self.spec_level,  # NEW: Use unified prompt
                strategy=self.strategy,  # Keep for backward compatibility
                natural_context=self.natural_context,
                prompt_options=self.prompt_options,
            )
        except LLMUnavailable:
            return None
        if not patched or patched.strip() == self.program.strip():
            return None
        diff = self._diff(self.program, patched)
        return PatchResult(
            patched_code=patched,
            diff=diff,
            method=f"llm[{self.strategy}]",
            llm_metadata={
                "endpoint": self.llm_client.config.endpoint,
                "model": self.llm_client.config.model,
            },
        )

    def _spec_guard_patch(self, spec: InterventionSpec) -> PatchResult | None:
        if not spec.interventions:
            return None
        lines = self.program.splitlines()
        insertions: List[str] = []
        notes: List[str] = []
        for intervention in spec.interventions:
            if intervention.enforce.startswith("INSERT GUARD"):
                guard = "if (!input) {\n        return -1;\n    }"
                insertions.append(guard)
                notes.append("auto_guard_from_feedback")
                continue
            condition = self._condition_from_intervention(intervention.enforce)
            if not condition:
                node = self._node_at_line(intervention.target_line)
                condition = self._extract_condition(node.description) if node else None
            if not condition:
                continue
            guard = self._make_guard(condition)
            insertions.append(guard)
            notes.append(f"guard_for:{condition}")

        insertions = self._deduplicate(insertions)
        if not insertions:
            return None
        vuln_index = self._clamp_index(self.vuln_line, len(lines))
        indent = self._leading_spaces(lines[vuln_index - 1] if lines else "")
        guard_lines = [self._indent_guard(guard, indent) for guard in insertions]
        patched_lines = (
            lines[: vuln_index - 1] + guard_lines + [lines[vuln_index - 1]] + lines[vuln_index:]
        )
        patched_program = "\n".join(patched_lines)
        diff = self._diff_lines(lines, patched_lines)
        return PatchResult(
            patched_code=patched_program,
            diff=diff,
            applied_guards=insertions,
            method="heuristic_guard",
            notes=notes,
        )

    def _apply_known_mitigations(self) -> PatchResult | None:
        transformed_code = self.program
        notes: List[str] = []

        transforms = [
            self._replace_gets_with_fgets,
            self._strengthen_strcpy,
            self._harden_scanf_s,
        ]

        for transform in transforms:
            transformed_code, message = transform(transformed_code)
            if message:
                notes.append(message)

        if transformed_code == self.program:
            return None

        diff = self._diff(self.program, transformed_code)
        return PatchResult(
            patched_code=transformed_code,
            diff=diff,
            method="heuristic_transform",
            notes=notes,
        )

    def _replace_gets_with_fgets(self, code: str) -> Tuple[str, Optional[str]]:
        pattern = re.compile(r"gets\(\s*(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*;")

        def repl(match: re.Match[str]) -> str:
            buf = match.group("buf")
            return f"fgets({buf}, sizeof({buf}), stdin);"

        new_code, count = pattern.subn(repl, code)
        if count:
            return new_code, "replace_gets_with_fgets"
        return code, None

    def _strengthen_strcpy(self, code: str) -> Tuple[str, Optional[str]]:
        pattern = re.compile(
            r"strcpy\(\s*(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*(?P<src>[^)]+)\)"
        )

        def repl(match: re.Match[str]) -> str:
            dst = match.group("dst")
            src = match.group("src").strip()
            body = (
                f"strncpy({dst}, {src}, sizeof({dst}) - 1);\n"
                f"{dst}[sizeof({dst}) - 1] = '\\0';"
            )
            return body

        new_code, count = pattern.subn(repl, code)
        if count:
            return new_code, "harden_strcpy_to_strncpy"
        return code, None

    def _harden_scanf_s(self, code: str) -> Tuple[str, Optional[str]]:
        pattern = re.compile(
            r"scanf\(\s*\"%s\"\s*,\s*(?P<buf>[A-Za-z_][A-Za-z0-9_]*)\s*\)"
        )

        def repl(match: re.Match[str]) -> str:
            buf = match.group("buf")
            return f"scanf(\"%255s\", {buf})"

        new_code, count = pattern.subn(repl, code)
        if count:
            return new_code, "limit_scanf_string_width"
        return code, None

    def _condition_from_intervention(self, enforce: str) -> Optional[str]:
        prefix = "ENFORCE NOT "
        if not enforce.startswith(prefix):
            return None
        variable = enforce[len(prefix) :].strip()
        node_id = self._node_id_from_variable(variable)
        node: PCGNode | None = self.graph.nodes.get(node_id) if node_id else None
        if not node:
            return None
        return self._extract_condition(node.description) or node.description

    def _node_id_from_variable(self, variable: str) -> Optional[str]:
        if not variable:
            return None
        if variable.startswith("V_"):
            return variable[2:]
        return variable

    def _node_at_line(self, line: int) -> PCGNode | None:
        for node in self.graph.nodes.values():
            if node.location == line:
                return node
        return None

    @staticmethod
    def _extract_condition(line: str) -> Optional[str]:
        stripped = line.strip()
        if stripped.startswith("if") and "(" in stripped and ")" in stripped:
            start = stripped.find("(") + 1
            end = stripped.rfind(")")
            return stripped[start:end].strip()
        if stripped and any(op in stripped for op in ("<", ">", "==", "!=", "<=", ">=")):
            return stripped
        return None

    @staticmethod
    def _make_guard(condition: str) -> str:
        # The guard enforces the negation of the vulnerable predicate.
        negated = f"({condition})"
        return (
            f"if {negated} {{\n"
            "        return -1;\n"
            "    }}"
        )

    @staticmethod
    def _indent_guard(guard: str, indent: str) -> str:
        indented_lines = []
        for line in guard.splitlines():
            if not line:
                indented_lines.append(indent)
            else:
                indented_lines.append(f"{indent}{line}")
        return "\n".join(indented_lines)

    @staticmethod
    def _leading_spaces(line: str) -> str:
        return line[: len(line) - len(line.lstrip(" "))]

    @staticmethod
    def _deduplicate(items: Iterable[str]) -> List[str]:
        seen = set()
        unique: List[str] = []
        for item in items:
            normalized = item.strip()
            if normalized in seen:
                continue
            seen.add(normalized)
            unique.append(item)
        return unique

    @staticmethod
    def _clamp_index(index: int, length: int) -> int:
        if length <= 0:
            return 1
        return max(1, min(index, length))

    @staticmethod
    def _diff(original: str, patched: str) -> str:
        return PatchGenerator._diff_lines(original.splitlines(), patched.splitlines())

    @staticmethod
    def _diff_lines(original: List[str], patched: List[str]) -> str:
        return "\n".join(
            difflib.unified_diff(
                original,
                patched,
                fromfile="original.c",
                tofile="patched.c",
                lineterm="",
            )
        )
