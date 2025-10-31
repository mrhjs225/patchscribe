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

from .pipeline import PatchScribePipeline, PipelineArtifacts
from .llm import LLMConfig


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
        provider = LLMConfig.from_env().provider
        self._force_sequential = provider == "ollama"
        if self._force_sequential:
            if max_workers and max_workers != 1:
                print(
                    "Warning: PATCHSCRIBE_LLM_PROVIDER=ollama detected; forcing sequential "
                    "evaluation to avoid parallel requests to the Ollama daemon."
                )
            self.max_workers = 1
        else:
            self.max_workers = max_workers or mp.cpu_count()

    def _compute_metrics(self, evaluations: List[CaseEvaluation]) -> Dict[str, float]:
        """평가 결과 리스트로부터 메트릭을 계산"""
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
        first_attempt_successes = 0
        first_attempt_count = 0
        consistency_passes = 0
        consistency_count = 0
        triple_verification_passes = 0

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
                if consistency_pass:
                    consistency_passes += 1
                # Triple verification
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
        return metrics

    def run_parallel(self, cases: Iterable[Dict[str, object]]) -> EvaluationReport:
        """케이스를 병렬로 평가"""
        cases_list = list(cases)
        if not cases_list:
            return EvaluationReport(cases=[], metrics=self._compute_metrics([]))

        evaluations: List[CaseEvaluation] = []

        # ProcessPoolExecutor를 사용하여 병렬 실행
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            # 각 케이스에 대해 future 생성
            future_to_idx = {
                executor.submit(
                    _evaluate_case_wrapper,
                    case,
                    idx,
                    self.pipeline,
                ): idx
                for idx, case in enumerate(cases_list, 1)
            }

            # 진행 상황 표시 설정
            if tqdm is not None:
                progress_bar = tqdm(
                    total=len(cases_list),
                    desc="Evaluating cases",
                    unit="case"
                )
            else:
                progress_bar = None

            # 완료되는 대로 결과 수집
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    evaluation = future.result()
                    evaluations.append(evaluation)
                    if progress_bar is not None:
                        progress_bar.update(1)
                        # 성공/실패 상태를 진행바 설명에 추가
                        success_count = sum(1 for e in evaluations if e.actual_success)
                        progress_bar.set_postfix({"success": f"{success_count}/{len(evaluations)}"})
                except Exception as exc:
                    if progress_bar is not None:
                        progress_bar.close()
                    print(f"Case {idx} generated an exception: {exc}")
                    raise

            if progress_bar is not None:
                progress_bar.close()

        # 메트릭 계산
        metrics = self._compute_metrics(evaluations)
        return EvaluationReport(cases=evaluations, metrics=metrics)

    def run_sequential(self, cases: Iterable[Dict[str, object]]) -> EvaluationReport:
        """순차적으로 케이스를 평가하여 Ollama 요청이 겹치지 않도록 한다."""
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
        케이스를 평가. 기본적으로 병렬 실행을 사용.
        순차 실행이 필요한 경우 max_workers=1로 설정.
        """
        if self.max_workers <= 1:
            return self.run_sequential(cases)
        return self.run_parallel(cases)


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


def _evaluate_case_wrapper(
    case: Dict[str, object],
    case_number: int,
    pipeline: PatchScribePipeline,
) -> CaseEvaluation:
    """
    병렬 실행을 위한 wrapper 함수.
    ProcessPoolExecutor는 인스턴스 메서드를 직접 호출할 수 없으므로
    모듈 레벨 함수가 필요함.
    """
    artifacts = pipeline.run(case)
    actual_success = artifacts.verification.overall
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

    explanation_metrics = artifacts.explanation_metrics
    first_attempt = explanation_metrics.get("first_attempt_success")

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
        },
        effect=artifacts.effect,
        iterations=artifacts.iterations,
        explanations={
            "formal": artifacts.explanations.formal_summary,
            "natural_template": artifacts.explanations.natural_template,
            "natural_llm": artifacts.explanations.natural_llm,
            "prompt_context": artifacts.explanations.prompt_context,
            "llm_prompt": artifacts.explanations.llm_prompt,
            "E_bug": artifacts.E_bug.as_dict() if artifacts.E_bug else None,
            "E_patch": artifacts.E_patch.as_dict() if artifacts.E_patch else None,
        },
        explanation_metrics=explanation_metrics,
        consistency=artifacts.consistency.as_dict() if artifacts.consistency else None,
        first_attempt_success=first_attempt,
        performance=artifacts.performance.as_dict() if artifacts.performance else None,
    )
