"""
Patch effect analysis that compares pre- and post-patch causal conditions.
"""
from __future__ import annotations

from collections import Counter
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .analysis.absence_analysis import AbsenceAnalyzer
from .pcg_builder import PCGBuilder, PCGBuilderConfig
from .scm import SCMBuilder
from .stage1_cache import Stage1Data


@dataclass
class PatchEffect:
    signature_found: bool
    original_condition: str
    patched_condition: str
    vulnerability_removed: bool
    diagnostics: Dict[str, object]

    def as_dict(self) -> Dict[str, object]:
        return {
            "signature_found": self.signature_found,
            "original_condition": self.original_condition,
            "patched_condition": self.patched_condition,
            "vulnerability_removed": self.vulnerability_removed,
            "diagnostics": self.diagnostics,
        }


class PatchEffectAnalyzer:
    def __init__(self, config: PCGBuilderConfig | None = None) -> None:
        self.config = config or PCGBuilderConfig()

    def analyze(
        self,
        original_condition: str,
        patched_code: str,
        signature: str,
        *,
        baseline_stage1: Stage1Data | None = None,
        vuln_info: Dict[str, object] | None = None,
    ) -> PatchEffect:
        vuln_meta = vuln_info or {}
        location = self._find_signature_line(patched_code, signature)
        signature_found = location is not None and bool(signature)
        effective_line = location or int(vuln_meta.get("location") or 1)
        cwe_id = vuln_meta.get("cwe_id", "Unknown")
        local_info = {
            "location": effective_line,
            "cwe_id": cwe_id,
            "absence_labels": (vuln_meta.get("absence_labels") or []),
        }
        graph, diagnostics = PCGBuilder(patched_code, local_info, self.config).build()
        scm_builder = SCMBuilder(graph, cwe_id)
        patched_scm = scm_builder.derive()
        patched_condition = patched_scm.vulnerable_condition or "False"

        baseline_absence = self._counter_from_findings(
            (baseline_stage1.analysis_stats or {}).get("absence_findings", [])
        ) if baseline_stage1 else Counter()
        resolution_rate, remaining, patched_absence, patched_counter = (
            self._evaluate_absence_resolution(
                patched_code,
                effective_line,
                baseline_absence,
            )
        )
        new_missing = dict((patched_counter - baseline_absence).items())

        original_complexity = self._condition_complexity(original_condition)
        patched_complexity = self._condition_complexity(patched_condition)
        condition_changed = (
            patched_condition in {"False", ""}
            or patched_condition != original_condition
            or patched_complexity < original_complexity
        )
        coverage_sufficient = resolution_rate >= 0.6 or not baseline_absence
        vulnerability_removed = (not signature_found) or (
            condition_changed and coverage_sufficient and not remaining
        )

        diagnostics_payload = {
            "pcg_summary": diagnostics.get("pcg_summary"),
            "signature_present": signature_found,
            "absence_resolution_rate": resolution_rate,
            "remaining_missing_guards": remaining,
            "new_missing_guards": new_missing,
            "patched_absence_metrics": patched_absence.metrics,
            "baseline_missing_guards": dict(baseline_absence),
            "scm_metrics": scm_builder.metrics,
            "patched_condition_complexity": patched_complexity,
            "original_condition_complexity": original_complexity,
        }

        return PatchEffect(
            signature_found=signature_found,
            original_condition=original_condition,
            patched_condition=patched_condition,
            vulnerability_removed=vulnerability_removed,
            diagnostics=diagnostics_payload,
        )

    @staticmethod
    def _find_signature_line(program: str, signature: str) -> Optional[int]:
        if not signature:
            return None
        lines = program.splitlines()
        for idx, line in enumerate(lines, start=1):
            if signature in line:
                return idx
        return None

    @staticmethod
    def _counter_from_findings(findings: Sequence[Dict[str, object]]) -> Counter[str]:
        counter: Counter[str] = Counter()
        for finding in findings or []:
            pattern = finding.get("pattern")
            if isinstance(pattern, str):
                counter[pattern] += 1
        return counter

    def _evaluate_absence_resolution(
        self,
        patched_code: str,
        vuln_line: int,
        baseline: Counter[str],
    ) -> Tuple[float, Dict[str, int], AbsenceAnalyzer, Counter[str]]:
        analyzer = AbsenceAnalyzer(patched_code, vuln_line)
        result = analyzer.run()
        patched_counter = Counter(f.pattern for f in result.findings)
        remaining: Dict[str, int] = {}
        for pattern, count in baseline.items():
            patched_count = patched_counter.get(pattern, 0)
            if patched_count:
                remaining[pattern] = min(count, patched_count)
        resolved = sum(baseline.values()) - sum(remaining.values())
        total = sum(baseline.values())
        if total:
            resolution_rate = resolved / total
        else:
            resolution_rate = 1.0 if not patched_counter else 0.0
        return resolution_rate, remaining, result, patched_counter

    @staticmethod
    def _condition_complexity(condition: str) -> int:
        variables = PatchEffectAnalyzer._extract_variables(condition)
        return len(variables)

    @staticmethod
    def _extract_variables(expression: str) -> List[str]:
        tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expression or "")
        reserved = {"AND", "OR", "NOT", "True", "False"}
        return [token for token in tokens if token not in reserved]
