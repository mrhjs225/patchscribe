"""
Evaluation utilities for aggregating CPG-Verify PoC results into basic metrics.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from .pipeline import CPGVerifyPipeline, PipelineArtifacts


@dataclass
class CaseEvaluation:
    case_id: str
    expected_success: bool
    actual_success: bool
    verification: Dict[str, object]
    patch_summary: Dict[str, object]
    effect: Dict[str, object]
    iterations: List[Dict[str, object]]
    explanations: Dict[str, str]

    def as_dict(self) -> Dict[str, object]:
        return {
            "case_id": self.case_id,
            "expected_success": self.expected_success,
            "actual_success": self.actual_success,
            "verification": self.verification,
            "patch": self.patch_summary,
            "effect": self.effect,
            "iterations": self.iterations,
            "explanations": self.explanations,
        }


@dataclass
class EvaluationReport:
    cases: List[CaseEvaluation]
    metrics: Dict[str, float]

    def as_dict(self) -> Dict[str, object]:
        return {
            "cases": [case.as_dict() for case in self.cases],
            "metrics": self.metrics,
        }


class Evaluator:
    def __init__(self, pipeline: CPGVerifyPipeline | None = None) -> None:
        self.pipeline = pipeline or CPGVerifyPipeline()

    def run(self, cases: Iterable[Dict[str, object]]) -> EvaluationReport:
        evaluations: List[CaseEvaluation] = []
        total = 0
        successes = 0
        expectation_matches = 0
        false_positives = 0
        false_negatives = 0
        ground_truth_matches = 0
        ground_truth_total = 0

        for case in cases:
            total += 1
            artifacts = self.pipeline.run(case)
            actual_success = artifacts.verification.overall
            expected = case.get("expected_success", False)
            if actual_success:
                successes += 1
            if actual_success == expected:
                expectation_matches += 1
            if actual_success and not expected:
                false_positives += 1
            if not actual_success and expected:
                false_negatives += 1

            matches_ground_truth = _compare_ground_truth(
                artifacts.patch.patched_code,
                case.get("ground_truth"),
            )
            if case.get("ground_truth") is not None:
                ground_truth_total += 1
                if matches_ground_truth:
                    ground_truth_matches += 1
            evaluations.append(
                CaseEvaluation(
                    case_id=case["id"],
                    expected_success=expected,
                    actual_success=actual_success,
                    verification=artifacts.verification.as_dict(),
                    patch_summary={
                        "guards": artifacts.patch.applied_guards,
                        "diff": artifacts.patch.diff,
                        "method": artifacts.patch.method,
                        "matches_ground_truth": matches_ground_truth,
                    },
                    effect=artifacts.effect,
                    iterations=artifacts.iterations,
                   explanations={
                        "formal": artifacts.explanations.formal_summary,
                        "natural_template": artifacts.explanations.natural_template,
                        "natural_llm": artifacts.explanations.natural_llm,
                        "prompt_context": artifacts.explanations.prompt_context,
                        "llm_prompt": artifacts.explanations.llm_prompt,
                    },
                )
            )

        metrics = {
            "total_cases": float(total),
            "success_rate": successes / total if total else 0.0,
            "expectation_match_rate": expectation_matches / total if total else 0.0,
            "false_positive_rate": false_positives / total if total else 0.0,
            "false_negative_rate": false_negatives / total if total else 0.0,
            "vulnerability_elimination_rate": _effect_rate(evaluations),
            "ground_truth_match_rate": ground_truth_matches / ground_truth_total if ground_truth_total else 0.0,
        }
        return EvaluationReport(cases=evaluations, metrics=metrics)


def _effect_rate(evaluations: Iterable[CaseEvaluation]) -> float:
    evaluations = list(evaluations)
    if not evaluations:
        return 0.0
    eliminated = sum(1 for case in evaluations if case.effect.get("vulnerability_removed"))
    return eliminated / len(evaluations)


def _compare_ground_truth(patched: str, ground_truth: Optional[str]) -> Optional[bool]:
    if ground_truth is None:
        return None
    return _normalize_code(patched) == _normalize_code(ground_truth)


def _normalize_code(code: str | None) -> str:
    if not code:
        return ""
    return "\n".join(line.rstrip() for line in code.strip().splitlines())
