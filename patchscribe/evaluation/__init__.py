"""Evaluation module for PatchScribe."""

# Import Evaluator from evaluator.py in this package
from .evaluator import Evaluator, EvaluationReport, CaseEvaluation

# Import manual rubric components
from .manual_rubric import (
    EvaluationRubric,
    ManualEvaluation,
    EvaluationDimension,
    LikertScore,
    InterRaterReliability,
    DisagreementResolution,
    export_evaluation_data,
    present_evaluation_interface,
)

__all__ = [
    # From evaluator.py
    'Evaluator',
    'EvaluationReport',
    'CaseEvaluation',
    # From manual_rubric.py
    'EvaluationRubric',
    'ManualEvaluation',
    'EvaluationDimension',
    'LikertScore',
    'InterRaterReliability',
    'DisagreementResolution',
    'export_evaluation_data',
    'present_evaluation_interface',
]
