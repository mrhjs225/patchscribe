"""
Evaluation utilities for aggregating PatchScribe PoC results into basic metrics.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from .pipeline import PatchScribePipeline, PipelineArtifacts


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
    explanation_metrics: Dict[str, object]
    # New: consistency and formal specs
    consistency: Dict[str, object] | None = None
    first_attempt_success: bool | None = None

    def as_dict(self) -> Dict[str, object]:
        result = {
            "case_id": self.case_id,
            "expected_success": self.expected_success,
            "actual_success": self.actual_success,
            "verification": self.verification,
            "patch": self.patch_summary,
            "effect": self.effect,
            "iterations": self.iterations,
            "explanations": self.explanations,
            "explanation_metrics": self.explanation_metrics,
        }
        if self.consistency is not None:
            result["consistency"] = self.consistency
        if self.first_attempt_success is not None:
            result["first_attempt_success"] = self.first_attempt_success
        return result


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
    def __init__(self, pipeline: PatchScribePipeline | None = None) -> None:
        self.pipeline = pipeline or PatchScribePipeline()

    def run(self, cases: Iterable[Dict[str, object]]) -> EvaluationReport:
        evaluations: List[CaseEvaluation] = []
        total = 0
        successes = 0
        expectation_matches = 0
        false_positives = 0
        false_negatives = 0
        ground_truth_matches = 0
        ground_truth_total = 0
        checklist_total = 0.0
        checklist_count = 0
        llm_totals: Dict[str, float] = {"accuracy": 0.0, "clarity": 0.0, "causality": 0.0}
        llm_counts = 0
        
        # New metrics
        first_attempt_successes = 0
        first_attempt_count = 0
        consistency_passes = 0
        consistency_count = 0
        triple_verification_passes = 0  # verification + consistency

        for case in cases:
            total += 1
            artifacts = self.pipeline.run(case)
            actual_success = artifacts.verification.overall
            expected = case.get("expected_success", False)
            
            # Check consistency
            consistency_pass = False
            if artifacts.consistency:
                consistency_pass = artifacts.consistency.overall
                consistency_count += 1
                if consistency_pass:
                    consistency_passes += 1
            
            # Triple verification (symbolic + model + fuzzing + consistency)
            triple_pass = actual_success and consistency_pass
            if triple_pass:
                triple_verification_passes += 1
            
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
            
            explanation_metrics = artifacts.explanation_metrics
            
            # First attempt success
            first_attempt = explanation_metrics.get("first_attempt_success")
            if first_attempt is not None:
                first_attempt_count += 1
                if first_attempt:
                    first_attempt_successes += 1
            
            coverage = explanation_metrics.get("checklist_coverage")
            if isinstance(coverage, (int, float)):
                checklist_total += float(coverage)
                checklist_count += 1
            llm_scores = explanation_metrics.get("llm_scores")
            if isinstance(llm_scores, dict):
                have_score = False
                for key in ("accuracy", "clarity", "causality"):
                    value = llm_scores.get(key)
                    if isinstance(value, (int, float)):
                        llm_totals[key] += float(value)
                        have_score = True
                if have_score:
                    llm_counts += 1
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
                        "notes": artifacts.patch.notes,
                    },
                    effect=artifacts.effect,
                    iterations=artifacts.iterations,
                    explanations={
                        "formal": artifacts.explanations.formal_summary,
                        "natural_template": artifacts.explanations.natural_template,
                        "natural_llm": artifacts.explanations.natural_llm,
                        "prompt_context": artifacts.explanations.prompt_context,
                        "llm_prompt": artifacts.explanations.llm_prompt,
                        # Add formal specifications (E_bug and E_patch)
                        "E_bug": artifacts.E_bug.as_dict() if artifacts.E_bug else None,
                        "E_patch": artifacts.E_patch.as_dict() if artifacts.E_patch else None,
                    },
                    explanation_metrics=explanation_metrics,
                    consistency=artifacts.consistency.as_dict() if artifacts.consistency else None,
                    first_attempt_success=first_attempt,
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
            "avg_explanation_checklist": checklist_total / checklist_count if checklist_count else 0.0,
            # New metrics
            "first_attempt_success_rate": first_attempt_successes / first_attempt_count if first_attempt_count else 0.0,
            "consistency_pass_rate": consistency_passes / consistency_count if consistency_count else 0.0,
            "triple_verification_pass_rate": triple_verification_passes / total if total else 0.0,
        }
        if llm_counts:
            metrics.update(
                {
                    f"avg_llm_{key}": llm_totals[key] / llm_counts
                    for key in ("accuracy", "clarity", "causality")
                }
            )
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
