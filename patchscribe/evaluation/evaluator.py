"""
Evaluation utilities for aggregating PatchScribe PoC results into basic metrics.
"""
from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
import multiprocessing as mp
from typing import Dict, Iterable, List, Optional

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

from ..pipeline import PatchScribePipeline, PipelineArtifacts
from ..llm import LLMConfig


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
    performance: Dict[str, object] | None = None
    patch_quality: Dict[str, object] | None = None
    ast_similarity: Dict[str, object] | None = None  # AST-based ground truth similarity
    success_judgment: Dict[str, object] | None = None

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
        if self.performance is not None:
            result["performance"] = self.performance
        if self.patch_quality is not None:
            result["patch_quality"] = self.patch_quality
        if self.ast_similarity is not None:
            result["ast_similarity"] = self.ast_similarity
        if self.success_judgment is not None:
            result["success_judgment"] = self.success_judgment
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
    def __init__(
        self,
        pipeline: PatchScribePipeline | None = None,
        max_workers: int | None = None,
    ) -> None:
        self.pipeline = pipeline or PatchScribePipeline()
        self.max_workers = max_workers or mp.cpu_count()

    def _compute_metrics(self, evaluations: List[CaseEvaluation]) -> Dict[str, float]:
        """Calculate metrics from evaluation results list"""
        total = len(evaluations)
        if total == 0:
            return {
                "total_cases": 0.0,
                "success_rate": 0.0,
                "expectation_match_rate": 0.0,
                "false_positive_rate": 0.0,
                "false_negative_rate": 0.0,
                "vulnerability_elimination_rate": 0.0,
                "ground_truth_match_rate": 0.0,
                "avg_explanation_checklist": 0.0,
                "first_attempt_success_rate": 0.0,
                "consistency_pass_rate": 0.0,
                "triple_verification_pass_rate": 0.0,
            }

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
        patch_quality_totals: Dict[str, float] = {"safety": 0.0, "completeness": 0.0, "regression_risk": 0.0, "explanation_alignment": 0.0}
        patch_quality_counts = 0
        first_attempt_successes = 0
        first_attempt_count = 0
        consistency_passes = 0
        consistency_accepts = 0
        consistency_count = 0
        triple_verification_passes = 0
        syn_eq_count = 0
        sem_eq_count = 0
        plausible_count = 0

        for evaluation in evaluations:
            if evaluation.actual_success:
                successes += 1
            if evaluation.actual_success == evaluation.expected_success:
                expectation_matches += 1
            if evaluation.actual_success and not evaluation.expected_success:
                false_positives += 1
            if not evaluation.actual_success and evaluation.expected_success:
                false_negatives += 1

            # Ground truth match
            if evaluation.patch_summary.get("matches_ground_truth") is not None:
                ground_truth_total += 1
                if evaluation.patch_summary.get("matches_ground_truth"):
                    ground_truth_matches += 1

            # Consistency check
            if evaluation.consistency:
                consistency_count += 1
                consistency_pass = evaluation.consistency.get("overall", False)
                accepted = evaluation.consistency.get("accepted")
                if accepted is None:
                    accepted = consistency_pass
                if consistency_pass:
                    consistency_passes += 1
                if accepted:
                    consistency_accepts += 1
                # Triple verification still requires strict pass
                if evaluation.actual_success and consistency_pass:
                    triple_verification_passes += 1

            # First attempt success
            if evaluation.first_attempt_success is not None:
                first_attempt_count += 1
                if evaluation.first_attempt_success:
                    first_attempt_successes += 1

            # Explanation metrics
            coverage = evaluation.explanation_metrics.get("checklist_coverage")
            if isinstance(coverage, (int, float)):
                checklist_total += float(coverage)
                checklist_count += 1

            llm_scores = evaluation.explanation_metrics.get("llm_scores")
            if isinstance(llm_scores, dict):
                have_score = False
                for key in ("accuracy", "clarity", "causality"):
                    value = llm_scores.get(key)
                    if isinstance(value, (int, float)):
                        llm_totals[key] += float(value)
                        have_score = True
                if have_score:
                    llm_counts += 1

            patch_quality = evaluation.patch_quality or {}
            scores = patch_quality.get("scores") if isinstance(patch_quality, dict) else None
            if isinstance(scores, dict) and scores:
                have_patch_score = False
                for key in ("safety", "completeness", "regression_risk", "explanation_alignment"):
                    value = scores.get(key)
                    if isinstance(value, (int, float)):
                        patch_quality_totals[key] += float(value)
                        have_patch_score = True
                if have_patch_score:
                    patch_quality_counts += 1

            success_meta = evaluation.success_judgment or {}
            if success_meta.get("syn_eq"):
                syn_eq_count += 1
            elif success_meta.get("sem_eq"):
                sem_eq_count += 1
            elif success_meta.get("plausible"):
                plausible_count += 1

        # Calculate AST similarity averages
        ast_similarity_count = 0
        ast_overall_total = 0.0
        ast_structural_total = 0.0
        ast_token_total = 0.0

        for evaluation in evaluations:
            if evaluation.ast_similarity:
                ast_similarity_count += 1
                ast_overall_total += evaluation.ast_similarity.get("overall_similarity", 0.0)
                ast_structural_total += evaluation.ast_similarity.get("structural_similarity", 0.0)
                ast_token_total += evaluation.ast_similarity.get("token_similarity", 0.0)

        metrics = {
            "total_cases": float(total),
            "success_rate": successes / total if total else 0.0,
            "expectation_match_rate": expectation_matches / total if total else 0.0,
            "false_positive_rate": false_positives / total if total else 0.0,
            "false_negative_rate": false_negatives / total if total else 0.0,
            "vulnerability_elimination_rate": _effect_rate(evaluations),
            "ground_truth_match_rate": ground_truth_matches / ground_truth_total if ground_truth_total else 0.0,
            "avg_explanation_checklist": checklist_total / checklist_count if checklist_count else 0.0,
            "first_attempt_success_rate": first_attempt_successes / first_attempt_count if first_attempt_count else 0.0,
            "consistency_pass_rate": consistency_accepts / consistency_count if consistency_count else 0.0,
            "consistency_strict_rate": consistency_passes / consistency_count if consistency_count else 0.0,
            "triple_verification_pass_rate": triple_verification_passes / total if total else 0.0,
            "syn_eq_rate": syn_eq_count / total if total else 0.0,
            "sem_eq_rate": sem_eq_count / total if total else 0.0,
            "plausible_rate": plausible_count / total if total else 0.0,
        }

        # Add AST similarity metrics if available
        if ast_similarity_count > 0:
            metrics.update({
                "avg_ast_overall_similarity": ast_overall_total / ast_similarity_count,
                "avg_ast_structural_similarity": ast_structural_total / ast_similarity_count,
                "avg_ast_token_similarity": ast_token_total / ast_similarity_count,
            })
        if llm_counts:
            metrics.update(
                {
                    f"avg_llm_{key}": llm_totals[key] / llm_counts
                    for key in ("accuracy", "clarity", "causality")
                }
            )
        if patch_quality_counts:
            metrics.update(
                {
                    f"avg_patch_{key}": patch_quality_totals[key] / patch_quality_counts
                    for key in ("safety", "completeness", "regression_risk", "explanation_alignment")
                }
            )
        return metrics

    def run_parallel(self, cases: Iterable[Dict[str, object]]) -> EvaluationReport:
        """Evaluate cases in parallel"""
        cases_list = list(cases)
        if not cases_list:
            return EvaluationReport(cases=[], metrics=self._compute_metrics([]))

        evaluations: List[CaseEvaluation] = []

        # Parallel execution using ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            # Create futures for each case
            future_to_idx = {
                executor.submit(
                    _evaluate_case_wrapper,
                    case,
                    idx,
                    self.pipeline,
                ): idx
                for idx, case in enumerate(cases_list, 1)
            }

            # Setup progress bar
            if tqdm is not None:
                progress_bar = tqdm(
                    total=len(cases_list),
                    desc="Evaluating cases",
                    unit="case"
                )
            else:
                progress_bar = None

            # Collect results as they complete
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    evaluation = future.result()
                    evaluations.append(evaluation)
                    if progress_bar is not None:
                        progress_bar.update(1)
                        # Add success/failure status to progress bar description
                        success_count = sum(1 for e in evaluations if e.actual_success)
                        progress_bar.set_postfix({"success": f"{success_count}/{len(evaluations)}"})
                except Exception as exc:
                    if progress_bar is not None:
                        progress_bar.close()
                    print(f"Case {idx} generated an exception: {exc}")
                    raise

            if progress_bar is not None:
                progress_bar.close()

        # Calculate metrics
        metrics = self._compute_metrics(evaluations)
        return EvaluationReport(cases=evaluations, metrics=metrics)

    def run_sequential(self, cases: Iterable[Dict[str, object]]) -> EvaluationReport:
        """Evaluate cases sequentially to avoid overlapping Ollama requests."""
        cases_list = list(cases)
        if not cases_list:
            return EvaluationReport(cases=[], metrics=self._compute_metrics([]))

        evaluations: List[CaseEvaluation] = []
        progress_bar = None
        if tqdm is not None:
            progress_bar = tqdm(total=len(cases_list), desc="Evaluating cases", unit="case")

        for idx, case in enumerate(cases_list, 1):
            evaluation = _evaluate_case_wrapper(case, idx, self.pipeline)
            evaluations.append(evaluation)
            if progress_bar is not None:
                progress_bar.update(1)
                success_count = sum(1 for e in evaluations if e.actual_success)
                progress_bar.set_postfix({"success": f"{success_count}/{len(evaluations)}"})

        if progress_bar is not None:
            progress_bar.close()

        metrics = self._compute_metrics(evaluations)
        return EvaluationReport(cases=evaluations, metrics=metrics)

    def run(self, cases: Iterable[Dict[str, object]]) -> EvaluationReport:
        """
        Evaluate cases. Uses parallel execution by default.
        Set max_workers=1 for sequential execution.
        """
        if self.max_workers <= 1:
            return self.run_sequential(cases)
        else:
            return self.run_parallel(cases)



def _effect_rate(evaluations: Iterable[CaseEvaluation]) -> float:
    evaluations = list(evaluations)
    if not evaluations:
        return 0.0
    eliminated = sum(1 for case in evaluations if case.effect.get("vulnerability_removed"))
    return eliminated / len(evaluations)


def _compare_ground_truth(patched: str, ground_truth: Optional[str]) -> Optional[bool]:
    """
    Compare patched code with ground truth using AST-based similarity.

    Returns True if patches are structurally similar (>= 0.7 similarity threshold).
    Falls back to text comparison if AST analysis fails.
    """
    if ground_truth is None:
        return None

    # Try AST-based comparison first
    try:
        from .ast_similarity import calculate_ast_similarity
        result = calculate_ast_similarity(patched, ground_truth)
        # Use 0.7 threshold for structural similarity
        return result.overall_similarity >= 0.7
    except Exception:
        # Fall back to text-based comparison
        return _normalize_code(patched) == _normalize_code(ground_truth)


def _normalize_code(code: str | None) -> str:
    if not code:
        return ""
    return "\n".join(line.rstrip() for line in code.strip().splitlines())


def _evaluate_case_wrapper(
    case: Dict[str, object],
    case_number: int,
    pipeline: PatchScribePipeline,
) -> CaseEvaluation:
    """
    Wrapper function for parallel execution.
    ProcessPoolExecutor cannot directly call instance methods,
    so a module-level function is required.

    Note: Success judgment is NOT performed here - it will be done by evaluate_results.py
    """
    artifacts = pipeline.run(case)

    # Success judgment is deferred to evaluate_results.py
    # Here we only check ground truth match
    generated_patch = artifacts.patch.patched_code or ""
    actual_success = _compare_ground_truth(generated_patch, case.get("ground_truth")) or False

    expected = case.get("expected_success", False)
    case_identifier = (
        case.get("id")
        or case.get("case_id")
        or case.get("filename")
        or f"case_{case_number}"
    )

    matches_ground_truth = _compare_ground_truth(
        artifacts.patch.patched_code,
        case.get("ground_truth"),
    )

    # Calculate AST similarity if ground truth is available
    ast_similarity_info = None
    ground_truth = case.get("ground_truth")
    if ground_truth:
        try:
            from .ast_similarity import calculate_ast_similarity
            result = calculate_ast_similarity(artifacts.patch.patched_code, ground_truth)
            ast_similarity_info = {
                "overall_similarity": result.overall_similarity,
                "structural_similarity": result.structural_similarity,
                "token_similarity": result.token_similarity,
                "edit_distance": result.edit_distance,
                "matched_nodes": result.matched_nodes,
                "total_nodes": result.total_nodes,
            }
        except Exception:
            # If AST similarity calculation fails, just skip it
            pass

    explanation_metrics = artifacts.explanation_metrics
    first_attempt = explanation_metrics.get("first_attempt_success")

    natural_text = (
        artifacts.explanations.natural_llm
        or artifacts.explanations.natural_template
        or ""
    )
    if natural_text:
        natural_text = natural_text.strip()

    e_bug_dict = artifacts.E_bug.as_dict() if artifacts.E_bug else None
    e_patch_dict = artifacts.E_patch.as_dict() if artifacts.E_patch else None

    if e_bug_dict is not None and natural_text:
        e_bug_dict = {**e_bug_dict, "text": natural_text}
    if e_patch_dict is not None and natural_text:
        e_patch_dict = {**e_patch_dict, "text": natural_text}

    return CaseEvaluation(
        case_id=case_identifier,
        expected_success=expected,
        actual_success=actual_success,
        verification=artifacts.verification.as_dict(),
        patch_summary={
            "guards": artifacts.patch.applied_guards,
            "diff": artifacts.patch.diff,
            "method": artifacts.patch.method,
            "matches_ground_truth": matches_ground_truth,
            "notes": artifacts.patch.notes,
            "patched_code": artifacts.patch.patched_code,
        },
        effect=artifacts.effect,
        iterations=artifacts.iterations,
        explanations={
            "formal": artifacts.explanations.formal_summary,
            "natural_template": artifacts.explanations.natural_template,
            "natural_llm": artifacts.explanations.natural_llm,
            "prompt_context": artifacts.explanations.prompt_context,
            "llm_prompt": artifacts.explanations.llm_prompt,
            "E_bug": e_bug_dict,
            "E_patch": e_patch_dict,
        },
        explanation_metrics=explanation_metrics,
        consistency=artifacts.consistency.as_dict() if artifacts.consistency else None,
        first_attempt_success=first_attempt,
        performance=artifacts.performance.as_dict() if artifacts.performance else None,
        patch_quality=artifacts.patch_quality,
        ast_similarity=ast_similarity_info,
        success_judgment=None,  # Will be populated by evaluate_results.py
    )
