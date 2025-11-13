#!/usr/bin/env python3
"""
Manual Evaluation Rubric for PatchScribe

This module implements the structured rubric for manual evaluation of patches
and explanations as described in the paper (Section 5.1.2).

Paper describes:
- 3 security experts (PhD students + industry engineer)
- Structured rubric (1-5 Likert scale)
- 4 dimensions: accuracy, completeness, clarity, causality
- Calibration session (2 hours, 10 gold-standard examples)
- Inter-rater reliability: Cohen's kappa = 0.78
- Disagreement resolution protocol
"""
from __future__ import annotations

import csv
import json
import statistics
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import numpy as np
from sklearn.metrics import cohen_kappa_score


class LikertScore(Enum):
    """5-point Likert scale for evaluation."""
    VERY_POOR = 1
    POOR = 2
    ACCEPTABLE = 3
    GOOD = 4
    EXCELLENT = 5


@dataclass
class EvaluationDimension:
    """Represents one dimension of the evaluation."""
    dimension_name: str
    score: LikertScore
    justification: str
    specific_issues: List[str]
    strengths: List[str]


@dataclass
class ManualEvaluation:
    """Complete manual evaluation by one evaluator."""
    evaluator_id: str
    case_id: str

    # Four main dimensions (Paper Section 5.1.2)
    accuracy: EvaluationDimension
    completeness: EvaluationDimension
    clarity: EvaluationDimension
    causality: EvaluationDimension

    # Overall assessment
    overall_score: float  # Average of four dimensions
    recommend_deployment: bool
    additional_comments: str

    # Metadata
    evaluation_time_minutes: int
    timestamp: str


class EvaluationRubric:
    """
    Structured rubric for evaluating patches and explanations.

    Implements the 4-dimension, 5-level Likert scale evaluation framework
    described in the paper.
    """

    @staticmethod
    def get_accuracy_guidelines() -> Dict[int, Dict[str, any]]:
        """
        Guidelines for evaluating accuracy dimension.

        Accuracy: Does the explanation correctly characterize the vulnerability?
        """
        return {
            1: {
                "label": "Very Poor",
                "description": "Incorrect vulnerability characterization",
                "criteria": [
                    "Misidentifies the root cause of the vulnerability",
                    "Provides incorrect causal relationships",
                    "Contains factual errors about the code behavior"
                ],
                "examples": [
                    "Claims buffer overflow when it's actually a null pointer dereference",
                    "Incorrect data flow analysis"
                ]
            },
            2: {
                "label": "Poor",
                "description": "Partially correct, missing key aspects",
                "criteria": [
                    "Identifies some aspects but misses critical details",
                    "Contains some correct causal relationships but incomplete",
                    "Has minor factual errors"
                ],
                "examples": [
                    "Identifies vulnerable line but misses contributing factors",
                    "Incomplete causal chain"
                ]
            },
            3: {
                "label": "Acceptable",
                "description": "Mostly correct, minor omissions",
                "criteria": [
                    "Correct characterization of main vulnerability",
                    "Most causal relationships are correct",
                    "Minor details may be missing"
                ],
                "examples": [
                    "Correctly identifies buffer overflow and main cause",
                    "Missing some edge cases"
                ]
            },
            4: {
                "label": "Good",
                "description": "Correct and complete",
                "criteria": [
                    "Accurate vulnerability characterization",
                    "All major causal relationships identified",
                    "No significant errors or omissions"
                ],
                "examples": [
                    "Comprehensive and accurate vulnerability description",
                    "Correct causal analysis"
                ]
            },
            5: {
                "label": "Excellent",
                "description": "Correct, complete, with insightful details",
                "criteria": [
                    "Perfect vulnerability characterization",
                    "Complete causal analysis with insights",
                    "Identifies subtle interactions and edge cases"
                ],
                "examples": [
                    "Exceptionally thorough analysis",
                    "Reveals non-obvious causal relationships"
                ]
            }
        }

    @staticmethod
    def get_completeness_guidelines() -> Dict[int, Dict[str, any]]:
        """
        Guidelines for evaluating completeness dimension.

        Completeness: Are all relevant factors and causal paths covered?
        """
        return {
            1: {
                "label": "Very Poor",
                "description": "Major gaps in explanation",
                "criteria": [
                    "Missing most causal paths",
                    "Critical factors not mentioned",
                    "Incomplete vulnerability description"
                ]
            },
            2: {
                "label": "Poor",
                "description": "Significant omissions",
                "criteria": [
                    "Missing several important causal paths",
                    "Some critical factors omitted",
                    "Partial vulnerability coverage"
                ]
            },
            3: {
                "label": "Acceptable",
                "description": "Covers main aspects, some gaps",
                "criteria": [
                    "Most important causal paths covered",
                    "Main factors identified",
                    "Minor omissions acceptable"
                ]
            },
            4: {
                "label": "Good",
                "description": "Comprehensive coverage",
                "criteria": [
                    "All major causal paths covered",
                    "All relevant factors identified",
                    "Minor details may be missing"
                ]
            },
            5: {
                "label": "Excellent",
                "description": "Exhaustive coverage",
                "criteria": [
                    "All causal paths thoroughly covered",
                    "Complete factor analysis",
                    "Even subtle aspects included"
                ]
            }
        }

    @staticmethod
    def get_clarity_guidelines() -> Dict[int, Dict[str, any]]:
        """
        Guidelines for evaluating clarity dimension.

        Clarity: Is the explanation understandable and well-structured?
        """
        return {
            1: {
                "label": "Very Poor",
                "description": "Confusing and hard to follow",
                "criteria": [
                    "Unclear language and terminology",
                    "Poor organization",
                    "Difficult to understand the main points"
                ]
            },
            2: {
                "label": "Poor",
                "description": "Somewhat unclear",
                "criteria": [
                    "Some unclear language",
                    "Suboptimal organization",
                    "Requires significant effort to understand"
                ]
            },
            3: {
                "label": "Acceptable",
                "description": "Mostly clear and understandable",
                "criteria": [
                    "Generally clear language",
                    "Reasonable organization",
                    "Main points are understandable"
                ]
            },
            4: {
                "label": "Good",
                "description": "Clear and well-organized",
                "criteria": [
                    "Clear, precise language",
                    "Good logical structure",
                    "Easy to follow and understand"
                ]
            },
            5: {
                "label": "Excellent",
                "description": "Exceptionally clear and pedagogical",
                "criteria": [
                    "Crystal-clear explanations",
                    "Excellent organization",
                    "Makes complex concepts accessible"
                ]
            }
        }

    @staticmethod
    def get_causality_guidelines() -> Dict[int, Dict[str, any]]:
        """
        Guidelines for evaluating causality dimension.

        Causality: Are causal relationships correctly identified and explained?
        """
        return {
            1: {
                "label": "Very Poor",
                "description": "Incorrect causal reasoning",
                "criteria": [
                    "Wrong causal relationships",
                    "Confuses correlation with causation",
                    "Missing actual causal links"
                ]
            },
            2: {
                "label": "Poor",
                "description": "Weak causal reasoning",
                "criteria": [
                    "Some correct causal links",
                    "Several incorrect or missing links",
                    "Unclear causal flow"
                ]
            },
            3: {
                "label": "Acceptable",
                "description": "Adequate causal reasoning",
                "criteria": [
                    "Main causal relationships correct",
                    "Minor gaps in causal chain",
                    "Generally sound reasoning"
                ]
            },
            4: {
                "label": "Good",
                "description": "Strong causal reasoning",
                "criteria": [
                    "Clear causal relationships",
                    "Complete causal chains",
                    "Well-reasoned explanations"
                ]
            },
            5: {
                "label": "Excellent",
                "description": "Exceptional causal reasoning",
                "criteria": [
                    "Perfect causal analysis",
                    "Identifies subtle causal interactions",
                    "Insightful causal explanations"
                ]
            }
        }


class InterRaterReliability:
    """
    Calculate inter-rater reliability metrics.

    Paper reports Cohen's kappa = 0.78 (substantial agreement)
    """

    @staticmethod
    def calculate_cohens_kappa(
        evaluations: List[ManualEvaluation],
        dimension: str
    ) -> float:
        """
        Calculate Cohen's kappa for a specific dimension.

        Args:
            evaluations: List of evaluations (must have at least 2 evaluators per case)
            dimension: Which dimension to calculate (accuracy/completeness/clarity/causality)

        Returns:
            Cohen's kappa coefficient (-1 to 1, higher is better)
        """
        # Group evaluations by case_id
        by_case: Dict[str, List[ManualEvaluation]] = {}
        for eval in evaluations:
            if eval.case_id not in by_case:
                by_case[eval.case_id] = []
            by_case[eval.case_id].append(eval)

        # Collect scores for pairs of raters
        all_scores_rater1 = []
        all_scores_rater2 = []

        for case_id, case_evals in by_case.items():
            if len(case_evals) >= 2:
                # Take first two evaluators for simplicity
                eval1 = case_evals[0]
                eval2 = case_evals[1]

                score1 = getattr(eval1, dimension).score.value
                score2 = getattr(eval2, dimension).score.value

                all_scores_rater1.append(score1)
                all_scores_rater2.append(score2)

        if len(all_scores_rater1) < 2:
            return 0.0

        return cohen_kappa_score(all_scores_rater1, all_scores_rater2)

    @staticmethod
    def calculate_all_kappas(evaluations: List[ManualEvaluation]) -> Dict[str, float]:
        """Calculate Cohen's kappa for all dimensions."""
        dimensions = ['accuracy', 'completeness', 'clarity', 'causality']
        return {
            dim: InterRaterReliability.calculate_cohens_kappa(evaluations, dim)
            for dim in dimensions
        }

    @staticmethod
    def calculate_agreement_percentage(
        evaluations: List[ManualEvaluation],
        dimension: str,
        tolerance: int = 0
    ) -> float:
        """
        Calculate percentage of cases where raters agree within tolerance.

        Args:
            evaluations: List of evaluations
            dimension: Which dimension to check
            tolerance: Allow scores to differ by this amount (0 = exact match)

        Returns:
            Percentage of cases with agreement (0-100)
        """
        by_case: Dict[str, List[ManualEvaluation]] = {}
        for eval in evaluations:
            if eval.case_id not in by_case:
                by_case[eval.case_id] = []
            by_case[eval.case_id].append(eval)

        agreements = 0
        total_cases = 0

        for case_id, case_evals in by_case.items():
            if len(case_evals) >= 2:
                total_cases += 1
                scores = [getattr(e, dimension).score.value for e in case_evals]

                # Check if all scores are within tolerance of each other
                if max(scores) - min(scores) <= tolerance:
                    agreements += 1

        if total_cases == 0:
            return 0.0

        return (agreements / total_cases) * 100


class DisagreementResolution:
    """
    Protocol for resolving disagreements between evaluators.

    Paper describes: Disagreements resolved through discussion and consensus.
    """

    @staticmethod
    def identify_disagreements(
        evaluations: List[ManualEvaluation],
        threshold: int = 2
    ) -> List[Dict[str, any]]:
        """
        Identify cases with significant disagreement.

        Args:
            evaluations: List of evaluations
            threshold: Score difference threshold (default: 2 points on Likert scale)

        Returns:
            List of disagreement cases with details
        """
        by_case: Dict[str, List[ManualEvaluation]] = {}
        for eval in evaluations:
            if eval.case_id not in by_case:
                by_case[eval.case_id] = []
            by_case[eval.case_id].append(eval)

        disagreements = []

        for case_id, case_evals in by_case.items():
            if len(case_evals) < 2:
                continue

            for dimension in ['accuracy', 'completeness', 'clarity', 'causality']:
                scores = [getattr(e, dimension).score.value for e in case_evals]

                if max(scores) - min(scores) >= threshold:
                    disagreements.append({
                        'case_id': case_id,
                        'dimension': dimension,
                        'scores': scores,
                        'evaluators': [e.evaluator_id for e in case_evals],
                        'difference': max(scores) - min(scores)
                    })

        return disagreements

    @staticmethod
    def resolve_by_median(evaluations: List[ManualEvaluation]) -> ManualEvaluation:
        """
        Resolve disagreements by taking median scores.

        Args:
            evaluations: List of evaluations for the same case

        Returns:
            Consensus evaluation with median scores
        """
        if not evaluations:
            raise ValueError("No evaluations provided")

        if len(evaluations) == 1:
            return evaluations[0]

        case_id = evaluations[0].case_id

        # Calculate median for each dimension
        def median_dimension(dim_name: str) -> EvaluationDimension:
            scores = [getattr(e, dim_name).score.value for e in evaluations]
            median_score = int(statistics.median(scores))

            # Aggregate justifications
            justifications = [getattr(e, dim_name).justification for e in evaluations]
            combined_just = " | ".join(f"Eval{i+1}: {j}" for i, j in enumerate(justifications))

            # Aggregate issues and strengths
            all_issues = []
            all_strengths = []
            for e in evaluations:
                all_issues.extend(getattr(e, dim_name).specific_issues)
                all_strengths.extend(getattr(e, dim_name).strengths)

            return EvaluationDimension(
                dimension_name=dim_name,
                score=LikertScore(median_score),
                justification=combined_just,
                specific_issues=list(set(all_issues)),
                strengths=list(set(all_strengths))
            )

        accuracy = median_dimension('accuracy')
        completeness = median_dimension('completeness')
        clarity = median_dimension('clarity')
        causality = median_dimension('causality')

        overall_score = np.mean([
            accuracy.score.value,
            completeness.score.value,
            clarity.score.value,
            causality.score.value
        ])

        return ManualEvaluation(
            evaluator_id='consensus',
            case_id=case_id,
            accuracy=accuracy,
            completeness=completeness,
            clarity=clarity,
            causality=causality,
            overall_score=overall_score,
            recommend_deployment=overall_score >= 3.0,
            additional_comments='Consensus evaluation from multiple raters',
            evaluation_time_minutes=sum(e.evaluation_time_minutes for e in evaluations) // len(evaluations),
            timestamp=evaluations[0].timestamp
        )


def export_evaluation_data(
    evaluations: List[ManualEvaluation],
    output_path: Path
) -> None:
    """
    Export evaluation data for analysis.

    Args:
        evaluations: List of manual evaluations
        output_path: Path to save JSON file
    """
    data = {
        'evaluations': [asdict(e) for e in evaluations],
        'statistics': {
            'total_evaluations': len(evaluations),
            'total_cases': len(set(e.case_id for e in evaluations)),
            'evaluators': list(set(e.evaluator_id for e in evaluations)),
            'mean_overall_score': np.mean([e.overall_score for e in evaluations]),
            'std_overall_score': np.std([e.overall_score for e in evaluations])
        }
    }

    # Calculate inter-rater reliability if multiple evaluators
    if len(set(e.evaluator_id for e in evaluations)) >= 2:
        data['inter_rater_reliability'] = InterRaterReliability.calculate_all_kappas(evaluations)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2, default=str)

    print(f"✅ Evaluation data exported to: {output_path}")


def present_evaluation_interface(
    case_id: str,
    patch_code: str,
    e_bug: Dict,
    e_patch: Dict,
    evaluator_id: str
) -> ManualEvaluation:
    """
    Present evaluation interface for manual assessment.

    This is a command-line interface for now. In practice, this would be
    a web interface or GUI.

    Args:
        case_id: Identifier for this case
        patch_code: The generated patch code
        e_bug: E_bug explanation
        e_patch: E_patch explanation
        evaluator_id: ID of the evaluator

    Returns:
        Completed manual evaluation
    """
    print("\n" + "=" * 80)
    print(f"MANUAL EVALUATION: Case {case_id}")
    print("=" * 80)

    print("\n[PATCH CODE]")
    print(patch_code)

    print("\n[E_BUG EXPLANATION]")
    print(json.dumps(e_bug, indent=2))

    print("\n[E_PATCH EXPLANATION]")
    print(json.dumps(e_patch, indent=2))

    print("\n" + "=" * 80)
    print("Please evaluate on a scale of 1-5 for each dimension:")
    print("  1 = Very Poor, 2 = Poor, 3 = Acceptable, 4 = Good, 5 = Excellent")
    print("=" * 80)

    # This is a stub - in practice, this would collect interactive input
    # For now, return a placeholder evaluation

    return ManualEvaluation(
        evaluator_id=evaluator_id,
        case_id=case_id,
        accuracy=EvaluationDimension(
            dimension_name='accuracy',
            score=LikertScore.GOOD,
            justification='Placeholder evaluation',
            specific_issues=[],
            strengths=[]
        ),
        completeness=EvaluationDimension(
            dimension_name='completeness',
            score=LikertScore.GOOD,
            justification='Placeholder evaluation',
            specific_issues=[],
            strengths=[]
        ),
        clarity=EvaluationDimension(
            dimension_name='clarity',
            score=LikertScore.GOOD,
            justification='Placeholder evaluation',
            specific_issues=[],
            strengths=[]
        ),
        causality=EvaluationDimension(
            dimension_name='causality',
            score=LikertScore.GOOD,
            justification='Placeholder evaluation',
            specific_issues=[],
            strengths=[]
        ),
        overall_score=4.0,
        recommend_deployment=True,
        additional_comments='Placeholder evaluation',
        evaluation_time_minutes=15,
        timestamp='2025-11-13T00:00:00'
    )


def manual_evaluation_to_dict(evaluation: ManualEvaluation) -> Dict[str, object]:
    """Serialize ManualEvaluation into a JSON-friendly dictionary."""
    def _dimension_dict(dimension: EvaluationDimension) -> Dict[str, object]:
        return {
            "dimension_name": dimension.dimension_name,
            "score": dimension.score.value,
            "label": dimension.score.name,
            "justification": dimension.justification,
            "specific_issues": list(dimension.specific_issues),
            "strengths": list(dimension.strengths),
        }

    return {
        "evaluator_id": evaluation.evaluator_id,
        "case_id": evaluation.case_id,
        "accuracy": _dimension_dict(evaluation.accuracy),
        "completeness": _dimension_dict(evaluation.completeness),
        "clarity": _dimension_dict(evaluation.clarity),
        "causality": _dimension_dict(evaluation.causality),
        "overall_score": evaluation.overall_score,
        "recommend_deployment": evaluation.recommend_deployment,
        "additional_comments": evaluation.additional_comments,
        "evaluation_time_minutes": evaluation.evaluation_time_minutes,
        "timestamp": evaluation.timestamp,
    }


def load_manual_evaluations_from_csv(path: Path) -> List[ManualEvaluation]:
    """
    Load manual evaluation data from a CSV file following the rubric template.
    """
    evaluations: List[ManualEvaluation] = []
    with path.open("r", encoding="utf-8-sig") as fp:
        reader = csv.DictReader(fp)
        for row in reader:
            case_id = (row.get("case_id") or row.get("id") or "").strip()
            evaluator_id = (row.get("evaluator_id") or row.get("reviewer") or "").strip()
            if not case_id or not evaluator_id:
                continue

            dimensions: Dict[str, EvaluationDimension] = {}
            for dim in ("accuracy", "completeness", "clarity", "causality"):
                score_value = row.get(f"{dim}_score") or row.get(dim)
                if not score_value:
                    continue
                try:
                    likert = LikertScore(int(score_value))
                except (ValueError, KeyError):
                    continue
                dimensions[dim] = EvaluationDimension(
                    dimension_name=dim,
                    score=likert,
                    justification=(row.get(f"{dim}_justification") or "").strip(),
                    specific_issues=_parse_semicolon_list(row.get(f"{dim}_issues")),
                    strengths=_parse_semicolon_list(row.get(f"{dim}_strengths")),
                )

            if len(dimensions) != 4:
                continue

            raw_overall = row.get("overall_score")
            if raw_overall:
                try:
                    overall_score = float(raw_overall)
                except ValueError:
                    overall_score = statistics.mean(dim.score.value for dim in dimensions.values())
            else:
                overall_score = statistics.mean(dim.score.value for dim in dimensions.values())

            recommend = (row.get("recommend_deployment") or "").strip().lower()
            recommend_flag = recommend in {"1", "true", "yes", "y"}

            additional_comments = (row.get("additional_comments") or "").strip()
            eval_minutes = row.get("evaluation_time_minutes") or row.get("duration_minutes") or "0"
            try:
                evaluation_time_minutes = int(eval_minutes)
            except ValueError:
                evaluation_time_minutes = 0

            timestamp = row.get("timestamp") or datetime.utcnow().isoformat()

            evaluations.append(
                ManualEvaluation(
                    evaluator_id=evaluator_id,
                    case_id=case_id,
                    accuracy=dimensions["accuracy"],
                    completeness=dimensions["completeness"],
                    clarity=dimensions["clarity"],
                    causality=dimensions["causality"],
                    overall_score=overall_score,
                    recommend_deployment=recommend_flag,
                    additional_comments=additional_comments,
                    evaluation_time_minutes=evaluation_time_minutes,
                    timestamp=timestamp,
                )
            )

    return evaluations


def _parse_semicolon_list(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    parts = [item.strip() for item in str(raw).split(";")]
    return [item for item in parts if item]
