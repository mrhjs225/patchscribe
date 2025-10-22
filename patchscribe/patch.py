"""
Patch synthesis guided by intervention specifications and lightweight heuristics.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from .intervention import InterventionSpec
from .pcg import ProgramCausalGraph
from .llm import LLMClient, LLMUnavailable


@dataclass
class PatchResult:
    patched_code: str
    diff: str
    applied_guards: List[str] = field(default_factory=list)
    method: str = "heuristic"
    llm_metadata: Optional[dict] = None


class PatchGenerator:
    def __init__(
        self,
        graph: ProgramCausalGraph,
        program: str,
        vuln_line: int,
        signature: str,
        llm_client: LLMClient | None = None,
        strategy: str = "formal",
        natural_context: str | None = None,
    ) -> None:
        self.graph = graph
        self.program = program
        self.vuln_line = vuln_line
        self.signature = signature
        self.llm_client = llm_client or LLMClient()
        self.strategy = strategy
        self.natural_context = natural_context

    def generate(self, spec: InterventionSpec) -> PatchResult:
        llm_result = self._try_llm_patch(spec)
        if llm_result:
            return llm_result
        return self._heuristic_patch(spec)

    def _try_llm_patch(self, spec: InterventionSpec) -> PatchResult | None:
        if not spec.interventions:
            return None
        try:
            patched = self.llm_client.generate_patch(
                original_code=self.program,
                vulnerability_signature=self.signature,
                interventions=[intervention.__dict__ for intervention in spec.interventions],
                strategy=self.strategy,
                natural_context=self.natural_context,
            )
        except LLMUnavailable:
            return None
        if not patched:
            return None
        diff = self._diff(self.program, patched)
        return PatchResult(
            patched_code=patched,
            diff=diff,
            applied_guards=[],
            method=f"llm[{self.strategy}]",
            llm_metadata={"endpoint": self.llm_client.config.endpoint, "model": self.llm_client.config.model},
        )

    def _heuristic_patch(self, spec: InterventionSpec) -> PatchResult:
        lines = self.program.splitlines()
        insertions: List[str] = []
        for intervention in spec.interventions:
            if intervention.enforce.startswith("INSERT GUARD"):
                insertions.append("if (!input) {\n        return -1;\n    }")
                continue
            node = self._node_at_line(intervention.target_line)
            if not node:
                continue
            condition = self._extract_condition(node.description)
            if not condition:
                continue
            guard = self._make_guard(condition)
            insertions.append(guard)
        if not insertions:
            return PatchResult(patched_code=self.program, diff="", applied_guards=[], method="noop")
        insertions = self._deduplicate(insertions)
        indent = self._leading_spaces(lines[self._clamp_index(self.vuln_line, len(lines)) - 1])
        guard_lines = [f"{indent}{guard}" for guard in insertions]
        vuln_index = self._clamp_index(self.vuln_line, len(lines))
        patched_lines = (
            lines[: vuln_index - 1]
            + guard_lines
            + [lines[vuln_index - 1]]
            + lines[vuln_index:]
        )
        patched_program = "\n".join(patched_lines)
        diff = self._diff_lines(lines, patched_lines)
        return PatchResult(
            patched_code=patched_program,
            diff=diff,
            applied_guards=insertions,
            method="heuristic",
        )

    def _node_at_line(self, line: int):
        for node in self.graph.nodes.values():
            if node.location == line:
                return node
        return None

    @staticmethod
    def _extract_condition(line: str) -> str | None:
        stripped = line.strip()
        if stripped.startswith("if") and "(" in stripped and ")" in stripped:
            start = stripped.find("(") + 1
            end = stripped.rfind(")")
            return stripped[start:end].strip()
        return None

    @staticmethod
    def _make_guard(condition: str) -> str:
        return f"if ({condition}) {{\n        return -1;\n    }}"

    @staticmethod
    def _leading_spaces(line: str) -> str:
        return line[: len(line) - len(line.lstrip(" "))]

    @staticmethod
    def _deduplicate(items: Iterable[str]) -> List[str]:
        seen = set()
        unique: List[str] = []
        for item in items:
            if item in seen:
                continue
            seen.add(item)
            unique.append(item)
        return unique

    @staticmethod
    def _clamp_index(index: int, length: int) -> int:
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
