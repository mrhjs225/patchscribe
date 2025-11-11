#!/usr/bin/env python3
"""
PatchScribe Comprehensive Analysis Script

Unified analysis tool for all Research Questions (RQ1-RQ4) based on the paper evaluation plan.
This script provides complete analysis for the PatchScribe paper evaluation, including:
- RQ1: Theory-Guided Patch Generation (LLM Judge-based)
- RQ2: Explanation Quality and Alignment
- RQ3: Scalability and Performance
- RQ4: Explanation Quality Metrics

Usage:
    # Analyze single result file
    python3 scripts/analyze.py results/local/qwen3-4b/c4_results.json

    # Analyze entire directory
    python3 scripts/analyze.py results/local

    # Run LLM judge evaluation without full analysis
    python3 scripts/analyze.py --run-judge results/local

    # Only produce judge scores
    python3 scripts/analyze.py --judge-only results/local/gpt-5-mini/c4_results.json

    # Merge distributed results and analyze
    python3 scripts/analyze.py --merge results/server*

    # Compare multiple models
    python3 scripts/analyze.py --compare results/local/model1 results/local/model2

    # Filter specific models
    python3 scripts/analyze.py results/local --models qwen3-4b deepseek-r1-7b

    # Show unified summary of all models and conditions
    python3 scripts/analyze.py --unified results/local
"""

import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
from collections import Counter, defaultdict
import statistics
import argparse

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from patchscribe.llm import LLMClient

try:
    from patchscribe.performance import categorize_complexity, measure_code_complexity
    HAS_COMPLEXITY = True
except ImportError:
    HAS_COMPLEXITY = False
    def categorize_complexity(loc: int) -> str:
        if loc < 50:
            return 'simple'
        elif loc < 100:
            return 'medium'
        else:
            return 'complex'

    def measure_code_complexity(code: str) -> Dict[str, Any]:
        return {'lines_of_code': len(code.splitlines())}


LLM_SCORE_KEYS = ("accuracy", "completeness", "clarity", "causality")


def _coerce_llm_value(payload: Dict[str, Any], *keys: str) -> Optional[float]:
    """Return the first numeric value found for the given keys."""
    for key in keys:
        value = payload.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    return None


def normalize_llm_scores(score_data: Dict[str, Any]) -> Dict[str, float]:
    """
    Ensure all LLM quality dimensions are present.
    Supports both old field names (accuracy, completeness, clarity, causality)
    and new field names (vulnerability_understanding, patch_understanding,
    causal_connection, actionability).

    If using new field names, they are mapped to old names for backward compatibility.
    """
    # Check if this is new format (developer-centric) or old format
    has_new_format = any(k in score_data for k in [
        'vulnerability_understanding',
        'patch_understanding',
        'causal_connection',
        'actionability'
    ])

    if has_new_format:
        # New format: map to old field names for backward compatibility
        vulnerability_understanding = _coerce_llm_value(score_data, "vulnerability_understanding") or 0.0
        patch_understanding = _coerce_llm_value(score_data, "patch_understanding") or 0.0
        causal_connection = _coerce_llm_value(score_data, "causal_connection") or 0.0
        actionability = _coerce_llm_value(score_data, "actionability") or 0.0

        # Collect all reasoning fields
        reasoning_parts = []
        for field in ['vulnerability_understanding_reasoning', 'patch_understanding_reasoning',
                     'causal_connection_reasoning', 'actionability_reasoning']:
            if field in score_data and score_data[field]:
                dimension = field.replace('_reasoning', '').replace('_', ' ').title()
                reasoning_parts.append(f"{dimension}: {score_data[field]}")

        reasoning = "\n".join(reasoning_parts) if reasoning_parts else ""

        return {
            'vulnerability_understanding': float(vulnerability_understanding),
            'patch_understanding': float(patch_understanding),
            'causal_connection': float(causal_connection),
            'actionability': float(actionability),
            'reasoning': reasoning,
            # Also provide old field names for full backward compatibility
            'accuracy': float(vulnerability_understanding),  # closest mapping
            'completeness': float(patch_understanding),      # closest mapping
            'clarity': float(causal_connection),             # closest mapping
            'causality': float(actionability),               # closest mapping
        }
    else:
        # Old format: keep existing logic
        accuracy = _coerce_llm_value(score_data, "accuracy") or 0.0
        clarity = _coerce_llm_value(score_data, "clarity") or 0.0
        causality = _coerce_llm_value(score_data, "causality") or 0.0
        completeness = _coerce_llm_value(score_data, "completeness", "coverage", "completeness_score")
        if completeness is None:
            # Use a conservative fallback so completeness stays within observed range.
            if clarity and causality:
                completeness = min(clarity, causality)
            elif clarity or accuracy:
                completeness = (clarity or accuracy)
            else:
                completeness = 0.0

        reasoning = score_data.get('reasoning') or score_data.get('reason') or ""

        return {
            'accuracy': float(accuracy),
            'completeness': float(completeness),
            'clarity': float(clarity),
            'causality': float(causality),
            'reasoning': reasoning,
        }


# ==================== DATA STRUCTURES ====================

@dataclass
class RQ1Result:
    """RQ1: Theory-Guided Generation Effectiveness

    Metrics:
    - LLM Judge success rate (SynEq, SemEq, Plausible)
    - Ground truth similarity (AST-based)
    - First-attempt success rate
    - Overall success rate
    - Vulnerability elimination rate
    """
    condition: str
    total_cases: int
    success_rate: float
    ground_truth_similarity: float
    first_attempt_success_rate: float
    consistency_pass_rate: float
    vulnerability_elimination_rate: float
    strict_consistency_rate: float = 0.0

    # Additional detailed metrics
    ast_structural_similarity: float = 0.0
    ast_token_similarity: float = 0.0

    # LLM Judge success judgment breakdown
    syn_eq_rate: float = 0.0
    sem_eq_rate: float = 0.0
    plausible_rate: float = 0.0
    syn_eq_count: int = 0
    sem_eq_count: int = 0
    plausible_count: int = 0
    failed_count: int = 0

    # Detailed case breakdowns
    syn_eq_cases: List[str] = None
    sem_eq_cases: List[str] = None
    plausible_cases: List[str] = None
    failed_cases: List[Tuple[str, str]] = None  # (case_id, reason)


@dataclass
class RQ2Result:
    """RQ2: Explanation Quality and Alignment

    Metrics:
    - Explanation completeness (checklist coverage)
    - LLM Judge explanation scores (accuracy, clarity, causality)
    - Consistency check effectiveness
    - E_bug ↔ E_patch alignment
    """
    condition: str
    total_cases: int

    # Explanation quality
    avg_checklist_coverage: float
    avg_explanation_accuracy: float = 0.0
    avg_explanation_clarity: float = 0.0
    avg_explanation_causality: float = 0.0

    # Consistency checking breakdown
    consistency_violations: Dict[str, int] = None
    consistency_pass_rate: float = 0.0
    confidence_tiers: Dict[str, int] = None

    # Patch quality (from LLM Judge)
    avg_patch_safety: float = 0.0
    avg_patch_completeness: float = 0.0
    avg_patch_regression_risk: float = 0.0


@dataclass
class RQ3Result:
    """RQ3: Scalability and Performance

    Metrics by complexity level (simple <50 LoC, medium 50-100, complex >100):
    - Time breakdown by phase
    - Total end-to-end time
    - Iteration count
    - Resource usage (memory, symbolic paths)
    """
    complexity_level: str
    case_count: int

    # Time metrics
    avg_phase1_time: Optional[float] = None  # Formalization
    avg_phase2_time: Optional[float] = None  # Generation
    avg_phase3_time: Optional[float] = None  # Verification
    avg_total_time: Optional[float] = None

    # Iteration metrics
    avg_iterations: float = 0.0

    # Resource metrics
    peak_memory_mb: Optional[float] = None
    avg_symbolic_paths: Optional[float] = None

    # Code complexity
    avg_loc: Optional[float] = None

    # Time distribution
    min_total_time: Optional[float] = None
    max_total_time: Optional[float] = None
    median_total_time: Optional[float] = None


@dataclass
class RQ4Result:
    """RQ4: Explanation Quality and Developer Trust

    Metrics:
    - Checklist-based coverage (automated)
    - Expert quality scores (accuracy, completeness, clarity)
    - Required elements detection
    """
    explanation_type: str

    # Checklist coverage
    avg_checklist_coverage: float

    # LLM-based quality scores (1-5 scale)
    avg_accuracy_score: float = 0.0
    avg_completeness_score: float = 0.0
    avg_clarity_score: float = 0.0
    avg_causality_score: float = 0.0

    # Element detection
    missing_item_frequency: Dict[str, int] = None

    # Coverage by explanation type
    ebug_coverage: float = 0.0
    epatch_coverage: float = 0.0

    # Sample counts
    total_evaluated: int = 0


# ==================== UTILITY FUNCTIONS ====================

def print_header(title: str, width: int = 80, char: str = "="):
    """Print formatted header"""
    print(f"\n{char * width}")
    print(f"  {title}")
    print(f"{char * width}")


def print_section(title: str, width: int = 80):
    """Print formatted section"""
    print(f"\n{'-' * width}")
    print(f"  {title}")
    print(f"{'-' * width}")


def should_include_model(model_name: str, model_filter: Optional[List[str]]) -> bool:
    """Check if model should be included based on filter"""
    if not model_filter:
        return True

    normalized_model = model_name.replace(':', '-').replace('/', '-').lower()

    for filter_name in model_filter:
        normalized_filter = filter_name.replace(':', '-').replace('/', '-').lower()
        # Exact match or filter is a substring of model (not vice versa)
        if normalized_model == normalized_filter or normalized_filter in normalized_model:
            return True

    return False


def compute_llm_averages(cases: List[Dict[str, Any]]) -> Tuple[Dict[str, float], int, Dict[str, int]]:
    """Compute aggregate LLM judge statistics across cases."""
    totals = {key: 0.0 for key in LLM_SCORE_KEYS}
    counts = {key: 0 for key in LLM_SCORE_KEYS}
    case_count = 0

    for case in cases:
        metrics = case.get('explanation_metrics')
        if not isinstance(metrics, dict):
            continue
        llm_scores = metrics.get('llm_scores')
        if not isinstance(llm_scores, dict):
            continue
        if any(key not in llm_scores for key in LLM_SCORE_KEYS):
            llm_scores.update(normalize_llm_scores(llm_scores))

        has_any = False
        for key in LLM_SCORE_KEYS:
            value = llm_scores.get(key)
            if isinstance(value, (int, float)):
                totals[key] += float(value)
                counts[key] += 1
                has_any = True

        if has_any:
            case_count += 1

    averages: Dict[str, float] = {}
    for key in LLM_SCORE_KEYS:
        if counts[key]:
            averages[f"avg_llm_{key}"] = totals[key] / counts[key]

    return averages, case_count, counts


def update_llm_metrics_summary(data: Dict[str, Any]) -> None:
    """Update the metrics section with averaged LLM judge scores."""
    cases = data.get('cases', [])
    averages, case_count, _ = compute_llm_averages(cases)
    metrics = data.setdefault('metrics', {})

    if averages:
        metrics.update(averages)
        metrics['llm_judge_cases'] = case_count
    else:
        for key in LLM_SCORE_KEYS:
            metrics.pop(f"avg_llm_{key}", None)
        metrics.pop('llm_judge_cases', None)


def safe_mean(values: List[Optional[float]]) -> Optional[float]:
    """Calculate mean of non-None values"""
    filtered = [v for v in values if v is not None]
    return statistics.mean(filtered) if filtered else None


def safe_median(values: List[Optional[float]]) -> Optional[float]:
    """Calculate median of non-None values"""
    filtered = [v for v in values if v is not None]
    return statistics.median(filtered) if filtered else None


def looks_like_timestamp(name: str) -> bool:
    """Check if directory name matches our YYYYMMDD-HHMMSS format."""
    try:
        datetime.strptime(name, "%Y%m%d-%H%M%S")
        return True
    except ValueError:
        return False


def resolve_model_results_dir(model_dir: Path) -> Path:
    """Return the most recent timestamped run directory if present."""
    if not model_dir.is_dir():
        return model_dir
    timestamp_dirs = sorted(
        [d for d in model_dir.iterdir() if d.is_dir() and looks_like_timestamp(d.name)],
        key=lambda d: d.name
    )
    if timestamp_dirs:
        return timestamp_dirs[-1]
    return model_dir


# ==================== MERGE FUNCTIONALITY ====================

def merge_distributed_results(server_dirs: List[Path], output_dir: Path,
                              verbose: bool = True,
                              model_filter: Optional[List[str]] = None) -> Path:
    """Merge distributed experiment results"""

    if verbose:
        print_header("Merging Distributed Results")
        print(f"\nFound {len(server_dirs)} server directories:")
        for d in server_dirs:
            print(f"  - {d}")

    output_dir.mkdir(parents=True, exist_ok=True)

    # Find all models
    models = set()
    for server_dir in server_dirs:
        if not server_dir.is_dir():
            continue
        model_dirs = [d for d in server_dir.iterdir()
                     if d.is_dir() and not d.name.startswith('.')]
        models.update(d.name for d in model_dirs)

    if not models:
        if verbose:
            print("⚠️  No model subdirectories found")
        models = {'_root'}

    # Apply model filter
    if model_filter:
        filtered_models = {m for m in models if should_include_model(m, model_filter)}
        if verbose:
            print(f"\nModel filter applied: {', '.join(model_filter)}")
            print(f"Filtered models: {', '.join(sorted(filtered_models))}")
            skipped = models - filtered_models
            if skipped:
                print(f"Skipped models: {', '.join(sorted(skipped))}")
        models = filtered_models
    else:
        if verbose:
            print(f"\nModels to merge: {', '.join(sorted(models))}")

    # Merge each model
    for model in sorted(models):
        if verbose:
            print(f"\n{'-' * 60}")
            print(f"Model: {model}")
            print(f"{'-' * 60}")

        model_output_dir = output_dir / model if model != '_root' else output_dir
        model_output_dir.mkdir(parents=True, exist_ok=True)

        # Merge each condition (C1-C4)
        for condition in ['c1', 'c2', 'c3', 'c4']:
            merged_cases = []

            for server_dir in server_dirs:
                if not server_dir.is_dir():
                    continue

                search_dir = server_dir / model if model != '_root' else server_dir

                if not search_dir.exists():
                    continue

                resolved_dir = resolve_model_results_dir(search_dir)
                result_files = list(resolved_dir.glob(f'{condition}_server*_results.json'))

                for result_file in result_files:
                    with open(result_file, 'r') as f:
                        data = json.load(f)

                    cases = data.get('cases', [])
                    merged_cases.extend(cases)

                    if verbose:
                        print(f"  {condition}: +{len(cases)} cases from {result_file.name}")

            if not merged_cases:
                continue

            # Recalculate metrics
            metrics = recalculate_metrics(merged_cases)

            # Save
            output_file = model_output_dir / f'{condition}_merged_results.json'
            merged_result = {
                'cases': merged_cases,
                'metrics': metrics,
                'model': model,
                'condition': condition,
                'merged_at': datetime.now().isoformat()
            }

            with open(output_file, 'w') as f:
                json.dump(merged_result, f, indent=2)

            if verbose:
                print(f"  ✅ {condition}: {len(merged_cases)} cases, "
                      f"success rate: {metrics.get('success_rate', 0):.1%}")

    # Merge incomplete patches
    if verbose:
        print(f"\n{'-' * 60}")
        print("Merging incomplete patches")
        print(f"{'-' * 60}")

    merged_incomplete = {}
    for server_dir in server_dirs:
        if not server_dir.is_dir():
            continue

        incomplete_files = list(server_dir.glob('incomplete_patches_server*.json'))

        for incomplete_file in incomplete_files:
            with open(incomplete_file, 'r') as f:
                data = json.load(f)

            for case_id, patches in data.items():
                if case_id not in merged_incomplete:
                    merged_incomplete[case_id] = []
                merged_incomplete[case_id].extend(patches)

            if verbose:
                print(f"  +{len(data)} cases from {incomplete_file.name}")

    if merged_incomplete:
        output_file = output_dir / 'incomplete_patches_merged.json'
        with open(output_file, 'w') as f:
            json.dump(merged_incomplete, f, indent=2)

        total_patches = sum(len(p) for p in merged_incomplete.values())
        if verbose:
            print(f"  ✅ Total: {len(merged_incomplete)} cases, {total_patches} patches")

    completion_msg = f"\n✅ Merge complete: {output_dir}/" if verbose else f"✅ Merge complete: {output_dir}/"
    print(completion_msg)

    return output_dir


def recalculate_metrics(cases: List[Dict]) -> Dict:
    """Recalculate metrics from case list"""
    if not cases:
        return {}

    total = len(cases)

    successes = sum(1 for case in cases if case.get('actual_success'))
    syn_eq_cases = 0
    sem_eq_cases = 0
    plausible_cases = 0

    # Ground truth matching
    ground_truth_matches = 0
    ground_truth_total = 0
    for case in cases:
        patch_summary = case.get('patch', {})
        matches = patch_summary.get('matches_ground_truth')
        if matches is not None:
            ground_truth_total += 1
            if matches:
                ground_truth_matches += 1

    # First attempt success
    first_attempt_successes = sum(1 for c in cases
                                  if c.get('first_attempt_success', False))
    first_attempt_count = sum(1 for c in cases
                             if c.get('first_attempt_success') is not None)

    # Consistency checks
    consistency_count = 0
    consistency_passes = 0
    consistency_accepts = 0

    for case in cases:
        success_meta = case.get('success_judgment') or {}
        if success_meta.get('syn_eq'):
            syn_eq_cases += 1
        elif success_meta.get('sem_eq'):
            sem_eq_cases += 1
        elif success_meta.get('plausible'):
            plausible_cases += 1

        consistency = case.get('consistency') or {}
        if consistency:
            consistency_count += 1
            if consistency.get('overall'):
                consistency_passes += 1
            accepted = consistency.get('accepted')
            if accepted is None:
                accepted = consistency.get('overall', False)
            if accepted:
                consistency_accepts += 1

    # AST similarity
    ast_count = 0
    ast_overall = ast_structural = ast_token = 0.0

    for case in cases:
        if case.get('ast_similarity'):
            ast_count += 1
            ast_overall += case['ast_similarity'].get('overall_similarity', 0.0)
            ast_structural += case['ast_similarity'].get('structural_similarity', 0.0)
            ast_token += case['ast_similarity'].get('token_similarity', 0.0)

    # Vulnerability elimination
    vuln_eliminated = sum(1 for c in cases
                         if c.get('effect', {}).get('vulnerability_removed', False))

    metrics = {
        "total_cases": float(total),
        "successful_cases": float(successes),
        "success_rate": successes / total if total else 0.0,
        "syn_eq_rate": syn_eq_cases / total if total else 0.0,
        "sem_eq_rate": sem_eq_cases / total if total else 0.0,
        "plausible_rate": plausible_cases / total if total else 0.0,
        "ground_truth_match_rate": ground_truth_matches / ground_truth_total if ground_truth_total else 0.0,
        "first_attempt_success_rate": first_attempt_successes / first_attempt_count if first_attempt_count else 0.0,
        "consistency_pass_rate": consistency_accepts / consistency_count if consistency_count else 0.0,
        "consistency_strict_rate": consistency_passes / consistency_count if consistency_count else 0.0,
        "vulnerability_elimination_rate": vuln_eliminated / total if total else 0.0,
    }

    if ast_count > 0:
        metrics.update({
            "avg_ast_overall_similarity": ast_overall / ast_count,
            "avg_ast_structural_similarity": ast_structural / ast_count,
            "avg_ast_token_similarity": ast_token / ast_count,
        })

    llm_averages, llm_case_count, _ = compute_llm_averages(cases)
    if llm_averages:
        metrics.update(llm_averages)
        metrics['llm_judge_cases'] = llm_case_count

    return metrics


def run_llm_judge_on_file(result_path: Path, *, batch_size: int = 5,
                          verbose: bool = True) -> bool:
    """Run LLM judge evaluation on a single results JSON file."""
    try:
        with open(result_path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        if verbose:
            print(f"❌ File not found: {result_path}")
        return False

    cases = data.get('cases', [])
    if not cases:
        if verbose:
            print(f"⚠️  No cases found in {result_path}")
        return False

    def _extract_text(payload: Any) -> str:
        if isinstance(payload, dict):
            for key in ('text', 'description', 'summary'):
                value = payload.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        elif isinstance(payload, str):
            return payload.strip()
        return ""

    prompts: List[str] = []
    valid_indices: List[int] = []

    for idx, case in enumerate(cases):
        explanations = case.get('explanations', {})
        e_bug = explanations.get('E_bug') if isinstance(explanations, dict) else None
        e_patch = explanations.get('E_patch') if isinstance(explanations, dict) else None

        ebug_text = _extract_text(e_bug)
        epatch_text = _extract_text(e_patch)
        if not ebug_text or not epatch_text:
            continue

        iterations = case.get('iterations') or []
        first_iter = iterations[0] if iterations else {}
        original_code = first_iter.get('original_code')
        patched_code = case.get('patch', {}).get('patched_code')
        if not patched_code:
            patched_code = first_iter.get('patched_code')
        vulnerability_sig = first_iter.get('vulnerability_signature')
        if not vulnerability_sig:
            vulnerability_sig = case.get('effect', {}).get('signature', '')

        if not original_code or not patched_code:
            continue

        prompt = LLMClient.build_explanation_judge_prompt(
            ebug_text=ebug_text,
            epatch_text=epatch_text,
            vulnerability_signature=vulnerability_sig or "",
            original_code=original_code,
            patched_code=patched_code,
        )

        prompts.append(prompt)
        valid_indices.append(idx)

    if not prompts:
        if verbose:
            print(f"⚠️  {result_path.name}: No valid explanations for judge evaluation")
        return False

    if verbose:
        print(f"🤖 {result_path.name}: Running LLM judge on {len(prompts)} case(s) (batch size {batch_size})")

    scores = LLMClient.batch_score_explanations(prompts, max_workers=batch_size)

    updated = False
    for idx, score_text in zip(valid_indices, scores):
        if not score_text:
            if verbose:
                case_id = cases[idx].get('case_id', f'case_{idx}')
                print(f"  ⚠️  No judge response for {case_id}")
            continue

        try:
            score_data = json.loads(score_text)
        except json.JSONDecodeError:
            if verbose:
                case_id = cases[idx].get('case_id', f'case_{idx}')
                print(f"  ⚠️  Invalid judge JSON for {case_id}")
            continue

        metrics = cases[idx].get('explanation_metrics')
        if not isinstance(metrics, dict):
            metrics = {}
            cases[idx]['explanation_metrics'] = metrics

        llm_scores = metrics.get('llm_scores')
        if not isinstance(llm_scores, dict):
            llm_scores = {}
            metrics['llm_scores'] = llm_scores

        normalized_scores = normalize_llm_scores(score_data)
        llm_scores.update(normalized_scores)
        metrics['llm_raw'] = score_text
        updated = True

    if not updated:
        if verbose:
            print(f"⚠️  {result_path.name}: Judge evaluation produced no usable scores")
        return False

    update_llm_metrics_summary(data)
    data['judge_evaluated_at'] = datetime.now().isoformat()

    with open(result_path, 'w') as f:
        json.dump(data, f, indent=2)

    if verbose:
        print(f"✅ {result_path.name}: Judge scores updated")

    return True


# ==================== RQ ANALYSIS FUNCTIONS ====================

class RQAnalyzer:
    """Comprehensive analyzer for all Research Questions"""

    def __init__(self, results_path: Path):
        self.results_path = results_path
        with open(results_path, 'r') as f:
            self.data = json.load(f)

        self.cases = self.data.get('cases', [])
        self.metrics = self.data.get('metrics', {})
        self.model = self.data.get('model', 'unknown')
        self.condition = self.data.get('condition', self._infer_condition())
        self.last_output_path: Optional[Path] = None
        self.last_markdown_path: Optional[Path] = None

        # Find dataset directories for complexity analysis
        self.dataset_dirs = self._find_dataset_dirs()
        self._case_source_cache: Dict[str, Optional[Path]] = {}

    def _infer_condition(self) -> str:
        """Infer condition from filename"""
        stem = self.results_path.stem
        if 'c1' in stem or 'baseline' in stem:
            return 'c1'
        elif 'c2' in stem or 'vague' in stem:
            return 'c2'
        elif 'c3' in stem or 'prehoc' in stem:
            return 'c3'
        elif 'c4' in stem or 'full' in stem:
            return 'c4'
        return 'unknown'

    def _find_dataset_dirs(self) -> List[Path]:
        """Find dataset directories for source code analysis"""
        candidates = [
            self.results_path.parents[2] / 'datasets',
            Path('datasets'),
            Path('data/datasets'),
        ]

        dirs = []
        for candidate in candidates:
            if candidate.exists() and candidate.is_dir():
                dirs.extend([d for d in candidate.glob('*') if d.is_dir()])

        return dirs

    def _find_case_source(self, case_id: str) -> Optional[Path]:
        """Locate source file for a case"""
        if case_id in self._case_source_cache:
            return self._case_source_cache[case_id]

        for dataset_dir in self.dataset_dirs:
            candidate = dataset_dir / case_id
            if candidate.exists():
                self._case_source_cache[case_id] = candidate
                return candidate

        self._case_source_cache[case_id] = None
        return None

    def _extract_complexity_metrics(self, case: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Measure LOC and complexity for a case"""
        case_id = case.get('case_id')
        if not case_id:
            return None

        source_path = self._find_case_source(case_id)
        if not source_path:
            return None

        if source_path.is_dir():
            # Try to find vulnerable file
            candidates = [
                source_path / name for name in
                ('vul.c', 'vul.cpp', 'vulnerable.c', 'buggy.c', 'main.c')
            ]
            candidates += sorted(source_path.glob('*.c')) + sorted(source_path.glob('*.cpp'))
            code_path = next((c for c in candidates if c.exists()), None)
        else:
            code_path = source_path

        if not code_path or not code_path.exists():
            return None

        try:
            code = code_path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            return None

        complexity = measure_code_complexity(code)
        loc = complexity.get('lines_of_code', 0)

        return {
            'loc': loc,
            'complexity_bucket': categorize_complexity(loc),
            'metrics': complexity
        }

    def analyze_rq1(self) -> RQ1Result:
        """
        RQ1: Theory-Guided Generation Effectiveness

        Research Question: Does pre-hoc formal bug specification (E_bug) lead
        to more accurate patches than post-hoc explanations or vague hints?

        Metrics:
        1. Triple verification pass rate
        2. Ground truth similarity (AST-based)
        3. First-attempt success rate
        4. Overall success rate
        5. Vulnerability elimination rate
        """

        total = len(self.cases)
        if total == 0:
            return RQ1Result(
                condition=self.condition,
                total_cases=0,
                success_rate=0.0,
                ground_truth_similarity=0.0,
                first_attempt_success_rate=0.0,
                consistency_pass_rate=0.0,
                vulnerability_elimination_rate=0.0,
                syn_eq_cases=[],
                sem_eq_cases=[],
                plausible_cases=[],
                failed_cases=[],
                strict_consistency_rate=0.0,
            )

        # Collect success judgment breakdown
        syn_eq_cases = []
        sem_eq_cases = []
        plausible_cases = []
        failed_cases = []

        for case in self.cases:
            case_id = case.get('case_id', 'unknown')
            success_meta = case.get('success_judgment') or {}

            if success_meta.get('syn_eq'):
                syn_eq_cases.append(case_id)
            elif success_meta.get('sem_eq'):
                sem_eq_cases.append(case_id)
            elif success_meta.get('plausible'):
                plausible_cases.append(case_id)
            else:
                reason = success_meta.get('reason', 'No reason provided')
                failed_cases.append((case_id, reason))

        # Use precomputed metrics if available
        result = RQ1Result(
            condition=self.condition,
            total_cases=total,
            success_rate=self.metrics.get('success_rate', 0.0),
            ground_truth_similarity=self.metrics.get('avg_ast_overall_similarity',
                                                     self.metrics.get('ground_truth_match_rate', 0.0)),
            first_attempt_success_rate=self.metrics.get('first_attempt_success_rate', 0.0),
            consistency_pass_rate=self.metrics.get('consistency_pass_rate', 0.0),
            strict_consistency_rate=self.metrics.get('consistency_strict_rate', 0.0),
            vulnerability_elimination_rate=self.metrics.get('vulnerability_elimination_rate', 0.0),
            ast_structural_similarity=self.metrics.get('avg_ast_structural_similarity', 0.0),
            ast_token_similarity=self.metrics.get('avg_ast_token_similarity', 0.0),
            syn_eq_rate=self.metrics.get('syn_eq_rate', 0.0),
            sem_eq_rate=self.metrics.get('sem_eq_rate', 0.0),
            plausible_rate=self.metrics.get('plausible_rate', 0.0),
            syn_eq_count=len(syn_eq_cases),
            sem_eq_count=len(sem_eq_cases),
            plausible_count=len(plausible_cases),
            failed_count=len(failed_cases),
            syn_eq_cases=syn_eq_cases,
            sem_eq_cases=sem_eq_cases,
            plausible_cases=plausible_cases,
            failed_cases=failed_cases,
        )

        return result

    def analyze_rq2(self) -> RQ2Result:
        """
        RQ2: Explanation Quality and Alignment

        Research Question: How effective are the generated explanations in terms of
        completeness, clarity, and alignment with the formal specifications (E_bug ↔ E_patch)?

        Metrics:
        1. Explanation quality (LLM Judge: accuracy, clarity, causality)
        2. Checklist coverage
        3. Consistency check effectiveness (E_bug ↔ E_patch alignment)
        4. Patch quality (LLM Judge: safety, completeness, regression risk)
        """

        total = len(self.cases)
        if total == 0:
            return RQ2Result(
                condition=self.condition,
                total_cases=0,
                avg_checklist_coverage=0.0,
                consistency_violations={},
                confidence_tiers={},
            )

        # Explanation quality metrics
        checklist_coverage_sum = 0.0
        checklist_count = 0

        explanation_accuracy_sum = 0.0
        explanation_clarity_sum = 0.0
        explanation_causality_sum = 0.0
        explanation_llm_count = 0

        # Patch quality metrics
        patch_safety_sum = 0.0
        patch_completeness_sum = 0.0
        patch_regression_risk_sum = 0.0
        patch_quality_count = 0

        # Consistency violation breakdown
        violation_counts = {
            'causal_coverage': 0,
            'intervention_validity': 0,
            'logical_consistency': 0,
            'completeness': 0
        }
        tier_counts: Dict[str, int] = {'pass': 0, 'review': 0, 'fail': 0}

        consistency_passes = 0
        consistency_count = 0

        for case in self.cases:
            # Explanation quality
            explanation_metrics = case.get('explanation_metrics', {})

            coverage = explanation_metrics.get('checklist_coverage')
            if coverage is not None:
                checklist_coverage_sum += coverage
                checklist_count += 1

            llm_scores = explanation_metrics.get('llm_scores', {})
            if llm_scores:
                if 'accuracy' in llm_scores:
                    explanation_accuracy_sum += llm_scores['accuracy']
                    explanation_llm_count += 1
                if 'clarity' in llm_scores:
                    explanation_clarity_sum += llm_scores['clarity']
                if 'causality' in llm_scores:
                    explanation_causality_sum += llm_scores['causality']

            # Patch quality
            patch_quality = case.get('patch_quality', {})
            if patch_quality:
                scores = patch_quality.get('scores', {})
                if scores:
                    if 'safety' in scores:
                        patch_safety_sum += scores['safety']
                        patch_quality_count += 1
                    if 'completeness' in scores:
                        patch_completeness_sum += scores['completeness']
                    if 'regression_risk' in scores:
                        patch_regression_risk_sum += scores['regression_risk']

            # Consistency checking
            consistency = case.get('consistency', {})
            if consistency:
                consistency_count += 1
                accepted = consistency.get('accepted')
                if accepted is None:
                    accepted = consistency.get('overall', False)
                if accepted:
                    consistency_passes += 1
                else:
                    # Count violation types
                    for dimension in violation_counts.keys():
                        dim_result = consistency.get(dimension, {})
                        if isinstance(dim_result, dict):
                            if not dim_result.get('success', True):
                                violation_counts[dimension] += 1
                        elif dim_result is False:
                            violation_counts[dimension] += 1
                tier = consistency.get('confidence_level')
                if not tier:
                    tier = 'pass' if consistency.get('overall') else 'fail'
                tier_counts[tier] = tier_counts.get(tier, 0) + 1

        result = RQ2Result(
            condition=self.condition,
            total_cases=total,
            avg_checklist_coverage=checklist_coverage_sum / checklist_count if checklist_count else 0.0,
            avg_explanation_accuracy=explanation_accuracy_sum / explanation_llm_count if explanation_llm_count else 0.0,
            avg_explanation_clarity=explanation_clarity_sum / explanation_llm_count if explanation_llm_count else 0.0,
            avg_explanation_causality=explanation_causality_sum / explanation_llm_count if explanation_llm_count else 0.0,
            consistency_violations=violation_counts,
            consistency_pass_rate=consistency_passes / consistency_count if consistency_count else 0.0,
            confidence_tiers=tier_counts,
            avg_patch_safety=patch_safety_sum / patch_quality_count if patch_quality_count else 0.0,
            avg_patch_completeness=patch_completeness_sum / patch_quality_count if patch_quality_count else 0.0,
            avg_patch_regression_risk=patch_regression_risk_sum / patch_quality_count if patch_quality_count else 0.0,
        )

        return result


    def analyze_rq3(self) -> List[RQ3Result]:
        """
        RQ3: Scalability and Performance

        Research Question: What is the time overhead of the three-phase workflow?

        Metrics by complexity (simple <50 LoC, medium 50-100, complex >100):
        1. Time breakdown by phase
        2. Total end-to-end time
        3. Iteration count
        4. Resource usage
        """

        if not self.cases:
            return []

        complexity_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for case in self.cases:
            perf = case.get('performance', {})

            # Get complexity info
            complexity_info = perf.get('code_complexity')
            if not complexity_info and HAS_COMPLEXITY:
                complexity_info = self._extract_complexity_metrics(case)

            # Get iteration count
            iteration_count = perf.get('iteration_count')
            if iteration_count is None:
                iteration_count = len(case.get('iterations', []))

            # Get phase breakdown
            phase_breakdown = perf.get('phase_breakdown', {})

            record = {
                'iteration_count': iteration_count,
                'phase1_time': phase_breakdown.get('phase1_formalization'),
                'phase2_time': phase_breakdown.get('phase2_generation'),
                'phase3_time': phase_breakdown.get('phase3_verification'),
                'total_time': perf.get('total_time_seconds'),
                'peak_memory': perf.get('peak_memory_mb'),
                'symbolic_paths': perf.get('symbolic_paths_explored'),
                'loc': None
            }

            # Determine complexity bucket
            if complexity_info:
                record['loc'] = complexity_info.get('lines_of_code') or complexity_info.get('loc')
                bucket = (complexity_info.get('complexity_bucket') or
                         complexity_info.get('bucket') or
                         complexity_info.get('category') or
                         'unknown')
            else:
                bucket = 'unknown'

            if bucket == 'unknown' and record['loc'] is not None:
                bucket = categorize_complexity(int(record['loc']))

            complexity_groups[bucket].append(record)

        # Generate results for each complexity level
        results: List[RQ3Result] = []

        for complexity, entries in sorted(complexity_groups.items()):
            if not entries:
                continue

            total_times = [e['total_time'] for e in entries]

            result = RQ3Result(
                complexity_level=complexity,
                case_count=len(entries),
                avg_phase1_time=safe_mean([e['phase1_time'] for e in entries]),
                avg_phase2_time=safe_mean([e['phase2_time'] for e in entries]),
                avg_phase3_time=safe_mean([e['phase3_time'] for e in entries]),
                avg_total_time=safe_mean(total_times),
                avg_iterations=safe_mean([e['iteration_count'] for e in entries]) or 0.0,
                peak_memory_mb=safe_mean([e['peak_memory'] for e in entries]),
                avg_symbolic_paths=safe_mean([e['symbolic_paths'] for e in entries]),
                avg_loc=safe_mean([e['loc'] for e in entries]),
                min_total_time=min(t for t in total_times if t is not None) if any(t is not None for t in total_times) else None,
                max_total_time=max(t for t in total_times if t is not None) if any(t is not None for t in total_times) else None,
                median_total_time=safe_median(total_times),
            )

            results.append(result)

        return results

    def analyze_rq4(self) -> RQ4Result:
        """
        RQ4: Explanation Quality and Developer Trust

        Research Question: Do the dual explanations (E_bug and E_patch)
        provide useful insights to developers?

        Metrics:
        1. Checklist-based coverage (automated)
        2. Expert quality scores
        3. Required elements detection
        """

        checklist_coverages = []
        accuracy_scores = []
        completeness_scores = []
        clarity_scores = []
        causality_scores = []

        ebug_coverages = []
        epatch_coverages = []

        missing_counter: Counter[str] = Counter()

        for case in self.cases:
            # Explanation metrics
            metrics = case.get('explanation_metrics', {})

            # Overall checklist coverage
            coverage = metrics.get('checklist_coverage')
            if coverage is not None:
                checklist_coverages.append(coverage)

            # E_bug and E_patch specific coverage
            if 'ebug_coverage' in metrics:
                ebug_coverages.append(metrics['ebug_coverage'])
            if 'epatch_coverage' in metrics:
                epatch_coverages.append(metrics['epatch_coverage'])

            # LLM-based quality scores
            llm_scores = metrics.get('llm_scores', {})
            if llm_scores:
                if 'accuracy' in llm_scores:
                    accuracy_scores.append(llm_scores['accuracy'])
                if 'completeness' in llm_scores:
                    completeness_scores.append(llm_scores['completeness'])
                if 'clarity' in llm_scores:
                    clarity_scores.append(llm_scores['clarity'])
                if 'causality' in llm_scores:
                    causality_scores.append(llm_scores['causality'])

            # Missing items
            missing_items = metrics.get('missing_items')
            if missing_items:
                missing_counter.update(missing_items)

        result = RQ4Result(
            explanation_type="Dual Explanations (E_bug + E_patch)",
            avg_checklist_coverage=statistics.mean(checklist_coverages) if checklist_coverages else 0.0,
            avg_accuracy_score=statistics.mean(accuracy_scores) if accuracy_scores else 0.0,
            avg_completeness_score=statistics.mean(completeness_scores) if completeness_scores else 0.0,
            avg_clarity_score=statistics.mean(clarity_scores) if clarity_scores else 0.0,
            avg_causality_score=statistics.mean(causality_scores) if causality_scores else 0.0,
            missing_item_frequency=dict(missing_counter) if missing_counter else {},
            ebug_coverage=statistics.mean(ebug_coverages) if ebug_coverages else 0.0,
            epatch_coverage=statistics.mean(epatch_coverages) if epatch_coverages else 0.0,
            total_evaluated=len(checklist_coverages),
        )

        return result

    def generate_comprehensive_report(self, output_path: Optional[Path] = None,
                                     verbose: bool = True) -> Dict:
        """Generate comprehensive analysis report for all RQs"""

        if verbose:
            print_header("COMPREHENSIVE RQ ANALYSIS")
            print(f"\nAnalyzing: {self.results_path.name}")
            print(f"Model: {self.model}")
            print(f"Condition: {self.condition}")
            print(f"Total cases: {len(self.cases)}")

        # Analyze all RQs
        rq1 = self.analyze_rq1()
        rq2 = self.analyze_rq2()
        rq3_list = self.analyze_rq3()
        rq4 = self.analyze_rq4()

        # Print results
        if verbose:
            self._print_rq1_results(rq1)
            self._print_rq2_results(rq2)
            self._print_rq3_results(rq3_list)
            self._print_rq4_results(rq4)

        # Compile report
        report = {
            'analyzed_at': datetime.now().isoformat(),
            'input_file': str(self.results_path),
            'model': self.model,
            'condition': self.condition,
            'total_cases': len(self.cases),
            'overall_metrics': self.metrics,
            'rq1_theory_guided_generation': asdict(rq1),
            'rq2_dual_verification': asdict(rq2),
            'rq3_scalability_performance': [asdict(r) for r in rq3_list],
            'rq4_explanation_quality': asdict(rq4),
        }

        # Save report
        if output_path is None:
            output_path = self.results_path.parent / f"{self.results_path.stem}_analysis.json"

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

        self.last_output_path = output_path

        if verbose:
            print(f"\n✅ Analysis saved: {output_path}")

        # Generate markdown report
        md_path = output_path.with_suffix('.md')
        self._generate_markdown_report(report, md_path)

        self.last_markdown_path = md_path

        if verbose:
            print(f"✅ Markdown report: {md_path}")

        return report

    def _print_rq1_results(self, rq1: RQ1Result):
        """Print RQ1 results"""
        print_section("RQ1: Theory-Guided Patch Generation (LLM Judge)")
        print(f"\nCondition: {rq1.condition}")
        print(f"  Total cases: {rq1.total_cases}")
        print(f"  Success rate: {rq1.success_rate:.1%}")
        print(f"  Ground truth similarity: {rq1.ground_truth_similarity:.1%}")
        print(f"  First attempt success: {rq1.first_attempt_success_rate:.1%}")
        print(f"  Consistency (accepted): {rq1.consistency_pass_rate:.1%}")
        print(f"  Consistency (strict):   {rq1.strict_consistency_rate:.1%}")
        print(f"  Vulnerability elimination: {rq1.vulnerability_elimination_rate:.1%}")

        if rq1.ast_structural_similarity > 0:
            print(f"\n  AST Similarity Details:")
            print(f"    Structural: {rq1.ast_structural_similarity:.1%}")
            print(f"    Token: {rq1.ast_token_similarity:.1%}")

        # LLM Judge Success Judgment Breakdown
        if rq1.syn_eq_count + rq1.sem_eq_count + rq1.plausible_count + rq1.failed_count > 0:
            print(f"\n  LLM Judge Success Breakdown:")
            print(f"    SynEq (Syntactic Equivalent):  {rq1.syn_eq_count:3d} ({rq1.syn_eq_rate:6.1%})")
            print(f"    SemEq (Semantic Equivalent):   {rq1.sem_eq_count:3d} ({rq1.sem_eq_rate:6.1%})")
            print(f"    Plausible:                     {rq1.plausible_count:3d} ({rq1.plausible_rate:6.1%})")
            print(f"    Failed:                        {rq1.failed_count:3d} ({rq1.failed_count/rq1.total_cases if rq1.total_cases else 0:6.1%})")

            # Show detailed case lists if available
            if rq1.syn_eq_cases:
                print(f"\n    SynEq Cases ({len(rq1.syn_eq_cases)}):")
                for case_id in rq1.syn_eq_cases[:10]:  # Show first 10
                    print(f"      - {case_id}")
                if len(rq1.syn_eq_cases) > 10:
                    print(f"      ... and {len(rq1.syn_eq_cases) - 10} more")

            if rq1.sem_eq_cases:
                print(f"\n    SemEq Cases ({len(rq1.sem_eq_cases)}):")
                for case_id in rq1.sem_eq_cases[:10]:
                    print(f"      - {case_id}")
                if len(rq1.sem_eq_cases) > 10:
                    print(f"      ... and {len(rq1.sem_eq_cases) - 10} more")

            if rq1.plausible_cases:
                print(f"\n    Plausible Cases ({len(rq1.plausible_cases)}):")
                for case_id in rq1.plausible_cases[:10]:
                    print(f"      - {case_id}")
                if len(rq1.plausible_cases) > 10:
                    print(f"      ... and {len(rq1.plausible_cases) - 10} more")

            if rq1.failed_cases:
                print(f"\n    Failed Cases ({len(rq1.failed_cases)}):")
                # Group failures by reason
                from collections import Counter
                failure_reasons = Counter(reason for _, reason in rq1.failed_cases)

                print(f"\n      Failure Reason Distribution:")
                for reason, count in failure_reasons.most_common():
                    print(f"        - {reason}: {count}")

                print(f"\n      Failed Case Details (showing first 5):")
                for case_id, reason in rq1.failed_cases[:5]:
                    # Truncate long reasons
                    display_reason = reason[:80] + "..." if len(reason) > 80 else reason
                    print(f"        - {case_id}")
                    print(f"          Reason: {display_reason}")
                if len(rq1.failed_cases) > 5:
                    print(f"        ... and {len(rq1.failed_cases) - 5} more failed cases")

    def _print_rq2_results(self, rq2: RQ2Result):
        """Print RQ2 results"""
        print_section("RQ2: Explanation Quality and Alignment")
        print(f"\nCondition: {rq2.condition}")
        print(f"  Total cases: {rq2.total_cases}")

        print(f"\n  Explanation Quality (LLM Judge):")
        print(f"    Checklist coverage: {rq2.avg_checklist_coverage:.1%}")
        print(f"    Accuracy score: {rq2.avg_explanation_accuracy:.2f}/5.0")
        print(f"    Clarity score: {rq2.avg_explanation_clarity:.2f}/5.0")
        print(f"    Causality score: {rq2.avg_explanation_causality:.2f}/5.0")

        print(f"\n  Patch Quality (LLM Judge):")
        print(f"    Safety score: {rq2.avg_patch_safety:.2f}/5.0")
        print(f"    Completeness score: {rq2.avg_patch_completeness:.2f}/5.0")
        print(f"    Regression risk: {rq2.avg_patch_regression_risk:.2f}/5.0")

        print(f"\n  Consistency Check (E_bug ↔ E_patch):")
        print(f"    Pass rate: {rq2.consistency_pass_rate:.1%}")

        if rq2.consistency_violations:
            print(f"\n  Consistency Violation Breakdown:")
            for vtype, count in rq2.consistency_violations.items():
                if count > 0:
                    print(f"    {vtype}: {count}")
        if rq2.confidence_tiers:
            print(f"\n  Confidence tiers:")
            for tier, count in rq2.confidence_tiers.items():
                print(f"    {tier}: {count}")

    def _print_rq3_results(self, rq3_list: List[RQ3Result]):
        """Print RQ3 results"""
        print_section("RQ3: Scalability and Performance")

        for rq3 in rq3_list:
            print(f"\nComplexity: {rq3.complexity_level}")
            print(f"  Cases: {rq3.case_count}")

            if rq3.avg_loc is not None:
                print(f"  Avg LOC: {rq3.avg_loc:.1f}")

            print(f"  Avg iterations: {rq3.avg_iterations:.1f}")

            if rq3.avg_total_time is not None:
                print(f"  Avg total time: {rq3.avg_total_time:.2f}s")
                print(f"    Range: {rq3.min_total_time:.2f}s - {rq3.max_total_time:.2f}s")
                print(f"    Median: {rq3.median_total_time:.2f}s")

                if rq3.avg_phase1_time is not None:
                    print(f"  Phase breakdown:")
                    print(f"    Phase 1 (Formalization): {rq3.avg_phase1_time:.2f}s")
                    print(f"    Phase 2 (Generation): {rq3.avg_phase2_time:.2f}s")
                    print(f"    Phase 3 (Verification): {rq3.avg_phase3_time:.2f}s")

            if rq3.peak_memory_mb is not None:
                print(f"  Peak memory: {rq3.peak_memory_mb:.1f} MB")

            if rq3.avg_symbolic_paths is not None:
                print(f"  Avg symbolic paths: {rq3.avg_symbolic_paths:.1f}")

    def _print_rq4_results(self, rq4: RQ4Result):
        """Print RQ4 results"""
        print_section("RQ4: Explanation Quality and Developer Trust")
        print(f"\nExplanation Type: {rq4.explanation_type}")
        print(f"  Cases evaluated: {rq4.total_evaluated}")
        print(f"  Avg checklist coverage: {rq4.avg_checklist_coverage:.1%}")

        if rq4.ebug_coverage > 0 or rq4.epatch_coverage > 0:
            print(f"\n  Coverage by type:")
            print(f"    E_bug: {rq4.ebug_coverage:.1%}")
            print(f"    E_patch: {rq4.epatch_coverage:.1%}")

        if rq4.avg_accuracy_score > 0:
            print(f"\n  LLM Quality Scores (1-5 scale):")
            print(f"    Accuracy: {rq4.avg_accuracy_score:.2f}")
            print(f"    Completeness: {rq4.avg_completeness_score:.2f}")
            print(f"    Clarity: {rq4.avg_clarity_score:.2f}")
            print(f"    Causality: {rq4.avg_causality_score:.2f}")
        else:
            print(f"\n  ⚠️  LLM quality scores not available")

        if rq4.missing_item_frequency:
            print(f"\n  Most frequent missing items:")
            for item, count in Counter(rq4.missing_item_frequency).most_common(5):
                print(f"    {item}: {count}")

    def _generate_markdown_report(self, report: Dict, output_path: Path):
        """Generate markdown summary report"""

        rq1 = RQ1Result(**report['rq1_theory_guided_generation'])
        rq2 = RQ2Result(**report['rq2_dual_verification'])
        rq3_list = [RQ3Result(**r) for r in report['rq3_scalability_performance']]
        rq4 = RQ4Result(**report['rq4_explanation_quality'])

        lines = [
            "# PatchScribe Comprehensive Analysis Report",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Source:** {self.results_path.name}  ",
            f"**Model:** {self.model}  ",
            f"**Condition:** {self.condition}  ",
            f"**Total Cases:** {len(self.cases)}  ",
            "",
            "---",
            "",
            "## RQ1: Theory-Guided Patch Generation (LLM Judge)",
            "",
            "**Research Question:** Does pre-hoc formal bug specification (E_bug) lead to more accurate patches?",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Success Rate | {rq1.success_rate:.1%} |",
            f"| Ground Truth Similarity | {rq1.ground_truth_similarity:.1%} |",
            f"| First Attempt Success | {rq1.first_attempt_success_rate:.1%} |",
            f"| Consistency (Accepted) | {rq1.consistency_pass_rate:.1%} |",
            f"| Consistency (Strict) | {rq1.strict_consistency_rate:.1%} |",
            f"| Vulnerability Elimination | {rq1.vulnerability_elimination_rate:.1%} |",
            "",
        ]

        if rq1.ast_structural_similarity > 0:
            lines.extend([
                "**AST Similarity Breakdown:**",
                f"- Structural: {rq1.ast_structural_similarity:.1%}",
                f"- Token: {rq1.ast_token_similarity:.1%}",
                "",
            ])

        # Add LLM Judge Success Breakdown
        if rq1.syn_eq_count + rq1.sem_eq_count + rq1.plausible_count + rq1.failed_count > 0:
            lines.extend([
                "**LLM Judge Success Breakdown:**",
                "",
                f"| Category | Count | Rate |",
                f"|----------|-------|------|",
                f"| SynEq (Syntactic Equivalent) | {rq1.syn_eq_count} | {rq1.syn_eq_rate:.1%} |",
                f"| SemEq (Semantic Equivalent) | {rq1.sem_eq_count} | {rq1.sem_eq_rate:.1%} |",
                f"| Plausible | {rq1.plausible_count} | {rq1.plausible_rate:.1%} |",
                f"| Failed | {rq1.failed_count} | {rq1.failed_count/rq1.total_cases if rq1.total_cases else 0:.1%} |",
                "",
            ])

            # Add failed cases details if any
            if rq1.failed_cases:
                failure_reasons = Counter(reason for _, reason in rq1.failed_cases)
                lines.extend([
                    f"**Failed Cases ({len(rq1.failed_cases)}):**",
                    "",
                    "Failure Reason Distribution:",
                    "",
                ])
                for reason, count in failure_reasons.most_common():
                    lines.append(f"- {reason}: {count}")
                lines.append("")

                # Show sample failed cases
                if len(rq1.failed_cases) <= 5:
                    lines.append("Failed Case Details:")
                else:
                    lines.append(f"Failed Case Details (showing first 5 of {len(rq1.failed_cases)}):")
                lines.append("")
                for case_id, reason in rq1.failed_cases[:5]:
                    display_reason = reason[:100] + "..." if len(reason) > 100 else reason
                    lines.append(f"- **{case_id}**")
                    lines.append(f"  - Reason: {display_reason}")
                lines.append("")

        lines.extend([
            "---",
            "",
            "## RQ2: Explanation Quality and Alignment",
            "",
            "**Research Question:** How effective are the generated explanations in terms of completeness, clarity, and alignment with formal specifications?",
            "",
            "### Explanation Quality (LLM Judge)",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Checklist Coverage | {rq2.avg_checklist_coverage:.1%} |",
            f"| Accuracy Score | {rq2.avg_explanation_accuracy:.2f}/5.0 |",
            f"| Clarity Score | {rq2.avg_explanation_clarity:.2f}/5.0 |",
            f"| Causality Score | {rq2.avg_explanation_causality:.2f}/5.0 |",
            "",
            "### Patch Quality (LLM Judge)",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Safety Score | {rq2.avg_patch_safety:.2f}/5.0 |",
            f"| Completeness Score | {rq2.avg_patch_completeness:.2f}/5.0 |",
            f"| Regression Risk | {rq2.avg_patch_regression_risk:.2f}/5.0 |",
            "",
            "### Consistency Check (E_bug ↔ E_patch)",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Pass Rate | {rq2.consistency_pass_rate:.1%} |",
            "",
        ])

        if rq2.confidence_tiers and any(rq2.confidence_tiers.values()):
            lines.extend([
                "| Tier | Cases |",
                "|------|-------|",
            ])
            for tier, count in rq2.confidence_tiers.items():
                lines.append(f"| {tier.title()} | {count} |")
            lines.append("")

        if rq2.consistency_violations and any(rq2.consistency_violations.values()):
            lines.extend([
                "**Consistency Violation Breakdown:**",
                "",
            ])
            for vtype, count in rq2.consistency_violations.items():
                if count > 0:
                    lines.append(f"- **{vtype}**: {count}")
            lines.append("")

        lines.extend([
            "---",
            "",
            "## RQ3: Scalability and Performance",
            "",
            "**Research Question:** What is the time overhead of the three-phase workflow?",
            "",
        ])

        for rq3 in rq3_list:
            lines.extend([
                f"### Complexity: {rq3.complexity_level}",
                "",
                f"| Metric | Value |",
                f"|--------|-------|",
                f"| Cases | {rq3.case_count} |",
            ])

            if rq3.avg_loc is not None:
                lines.append(f"| Avg LOC | {rq3.avg_loc:.1f} |")

            lines.append(f"| Avg Iterations | {rq3.avg_iterations:.1f} |")

            if rq3.avg_total_time is not None:
                lines.extend([
                    f"| Avg Total Time | {rq3.avg_total_time:.2f}s |",
                    f"| Min Total Time | {rq3.min_total_time:.2f}s |",
                    f"| Max Total Time | {rq3.max_total_time:.2f}s |",
                    f"| Median Total Time | {rq3.median_total_time:.2f}s |",
                ])

                phase_times = [
                    ("Phase 1 (Formalization)", rq3.avg_phase1_time),
                    ("Phase 2 (Generation)", rq3.avg_phase2_time),
                    ("Phase 3 (Verification)", rq3.avg_phase3_time),
                ]

                for label, value in phase_times:
                    if value is not None:
                        lines.append(f"| {label} | {value:.2f}s |")

            if rq3.peak_memory_mb is not None:
                lines.append(f"| Peak Memory | {rq3.peak_memory_mb:.1f} MB |")

            if rq3.avg_symbolic_paths is not None:
                lines.append(f"| Avg Symbolic Paths | {rq3.avg_symbolic_paths:.1f} |")

            lines.append("")

        lines.extend([
            "---",
            "",
            "## RQ4: Explanation Quality and Developer Trust",
            "",
            "**Research Question:** Do dual explanations provide useful insights to developers?",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Explanation Type | {rq4.explanation_type} |",
            f"| Cases Evaluated | {rq4.total_evaluated} |",
            f"| Avg Checklist Coverage | {rq4.avg_checklist_coverage:.1%} |",
        ])

        if rq4.ebug_coverage > 0 or rq4.epatch_coverage > 0:
            lines.extend([
                f"| E_bug Coverage | {rq4.ebug_coverage:.1%} |",
                f"| E_patch Coverage | {rq4.epatch_coverage:.1%} |",
            ])

        if rq4.avg_accuracy_score > 0:
            lines.extend([
                "",
                "### LLM Quality Scores (1-5 scale)",
                "",
                f"| Dimension | Score |",
                f"|-----------|-------|",
                f"| Accuracy | {rq4.avg_accuracy_score:.2f} |",
                f"| Completeness | {rq4.avg_completeness_score:.2f} |",
                f"| Clarity | {rq4.avg_clarity_score:.2f} |",
                f"| Causality | {rq4.avg_causality_score:.2f} |",
            ])

        if rq4.missing_item_frequency:
            lines.extend([
                "",
                "### Most Frequent Missing Items",
                "",
            ])
            for item, count in Counter(rq4.missing_item_frequency).most_common(10):
                lines.append(f"- **{item}**: {count}")

        lines.extend([
            "",
            "---",
            "",
            "## Overall Metrics",
            "",
        ])

        for key, value in self.metrics.items():
            if isinstance(value, float):
                lines.append(f"- **{key}**: {value:.4f}")
            else:
                lines.append(f"- **{key}**: {value}")

        output_path.write_text('\n'.join(lines))


# ==================== COMPARISON FUNCTIONALITY ====================

def generate_comparison_report(result_dirs: List[Path], output_dir: Path,
                               verbose: bool = True,
                               model_filter: Optional[List[str]] = None):
    """Generate multi-model comparison report"""

    if verbose:
        print_header("Generating Multi-Model Comparison Report")
        if model_filter:
            print(f"Model filter: {', '.join(model_filter)}")

    all_results = {}

    # Collect results from all directories
    for base_dir in result_dirs:
        if not base_dir.exists():
            continue

        if verbose:
            print(f"\nScanning: {base_dir}")

        # Find model directories
        for model_dir in base_dir.iterdir():
            if not model_dir.is_dir() or model_dir.name.startswith('.'):
                continue

            model_name = model_dir.name
            results_dir = resolve_model_results_dir(model_dir)

            # Apply model filter
            if not should_include_model(model_name, model_filter):
                continue

            # Find C4 results (full PatchScribe)
            c4_file = results_dir / "c4_merged_results.json"
            if not c4_file.exists():
                c4_file = results_dir / "c4_results.json"
            if not c4_file.exists():
                continue

            if verbose:
                print(f"  ✅ Found: {model_name}")

            # Load results
            with open(c4_file, 'r') as f:
                data = json.load(f)

            metrics = data.get('metrics', {})

            all_results[model_name] = {
                'source_file': str(c4_file),
                'metrics': {
                    'success_rate': metrics.get('success_rate', 0),
                    'consistency_pass_rate': metrics.get('consistency_pass_rate', 0),
                    'consistency_strict_rate': metrics.get('consistency_strict_rate',
                                                          metrics.get('consistency_pass_rate', 0)),
                    'first_attempt_success_rate': metrics.get('first_attempt_success_rate', 0),
                    'ground_truth_similarity': metrics.get('avg_ast_overall_similarity',
                                                          metrics.get('ground_truth_match_rate', 0)),
                    'total_cases': int(metrics.get('total_cases', 0)),
                }
            }

            # Collect other condition results (C1-C3)
            for condition in ['c1', 'c2', 'c3']:
                cond_file = results_dir / f"{condition}_merged_results.json"
                if not cond_file.exists():
                    cond_file = results_dir / f"{condition}_results.json"
                if not cond_file.exists():
                    continue

                with open(cond_file, 'r') as f:
                    cond_data = json.load(f)

                all_results[model_name][f'{condition}_success_rate'] = \
                    cond_data.get('metrics', {}).get('success_rate', 0)

    if not all_results:
        print("❌ No results found")
        return

    # Generate reports
    output_dir.mkdir(parents=True, exist_ok=True)

    # JSON report
    comparison = {
        'generated_at': datetime.now().isoformat(),
        'total_models': len(all_results),
        'models': all_results
    }

    json_file = output_dir / "comparison.json"
    with open(json_file, 'w') as f:
        json.dump(comparison, f, indent=2)

    # Markdown report
    md_lines = [
        "# PatchScribe Multi-Model Comparison Report",
        "",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Total Models:** {len(all_results)}  ",
        "",
        "---",
        "",
        "## C4 (Full PatchScribe) Results",
        "",
        "| Model | Success Rate | Consistency | Strict | First Attempt | GT Similarity | Cases |",
        "|-------|--------------|-------------|--------|---------------|---------------|-------|",
    ]

    # Sort by success rate
    sorted_models = sorted(all_results.items(),
                          key=lambda x: x[1]['metrics']['success_rate'],
                          reverse=True)

    for model_name, data in sorted_models:
        m = data['metrics']
        md_lines.append(
            f"| {model_name} | {m['success_rate']:.1%} | "
            f"{m['consistency_pass_rate']:.1%} | {m['consistency_strict_rate']:.1%} | "
            f"{m['first_attempt_success_rate']:.1%} | "
            f"{m['ground_truth_similarity']:.1%} | {m['total_cases']} |"
        )

    # Ablation study comparison
    has_conditions = any('c1_success_rate' in data for data in all_results.values())

    if has_conditions:
        md_lines.extend([
            "",
            "---",
            "",
            "## RQ1 Ablation Study: Condition Comparison",
            "",
            "| Model | C1 (Baseline) | C2 (Vague Hints) | C3 (Pre-hoc) | C4 (Full) | Improvement |",
            "|-------|---------------|------------------|--------------|-----------|-------------|",
        ])

        for model_name, data in sorted_models:
            c1 = data.get('c1_success_rate', 0)
            c2 = data.get('c2_success_rate', 0)
            c3 = data.get('c3_success_rate', 0)
            c4 = data['metrics']['success_rate']

            improvement = ((c4 - c1) / c1 * 100) if c1 > 0 else 0

            if c1 > 0 or c2 > 0 or c3 > 0:
                md_lines.append(
                    f"| {model_name} | {c1:.1%} | {c2:.1%} | {c3:.1%} | {c4:.1%} | +{improvement:.0f}% |"
                )

    # Key findings
    best_model = sorted_models[0]
    best_consistency = max(all_results.items(),
                          key=lambda x: x[1]['metrics']['consistency_pass_rate'])
    best_strict = max(all_results.items(),
                      key=lambda x: x[1]['metrics'].get('consistency_strict_rate', 0))
    best_first_attempt = max(all_results.items(),
                            key=lambda x: x[1]['metrics']['first_attempt_success_rate'])

    md_lines.extend([
        "",
        "---",
        "",
        "## Key Findings",
        "",
        f"- **Best Overall Model**: {best_model[0]} ({best_model[1]['metrics']['success_rate']:.1%} success rate)",
        f"- **Highest Consistency (accepted)**: {best_consistency[0]} ({best_consistency[1]['metrics']['consistency_pass_rate']:.1%})",
        f"- **Highest Consistency (strict)**: {best_strict[0]} ({best_strict[1]['metrics']['consistency_strict_rate']:.1%})",
        f"- **Best First Attempt**: {best_first_attempt[0]} ({best_first_attempt[1]['metrics']['first_attempt_success_rate']:.1%})",
        "",
    ])

    # Expected outcomes analysis (from paper)
    if has_conditions and len(sorted_models) > 0:
        c1_rates = [d.get('c1_success_rate', 0) for d in all_results.values() if d.get('c1_success_rate', 0) > 0]
        c3_rates = [d.get('c3_success_rate', 0) for d in all_results.values() if d.get('c3_success_rate', 0) > 0]
        c4_rates = [d['metrics']['success_rate'] for d in all_results.values() if d['metrics']['success_rate'] > 0]

        avg_c1 = statistics.mean(c1_rates) if c1_rates else 0.0
        avg_c3 = statistics.mean(c3_rates) if c3_rates else 0.0
        avg_c4 = statistics.mean(c4_rates) if c4_rates else 0.0

        if avg_c1 > 0:
            c3_improvement = ((avg_c3 - avg_c1) / avg_c1 * 100)
            c4_improvement = ((avg_c4 - avg_c1) / avg_c1 * 100)

            md_lines.extend([
                "### Comparison with Expected Outcomes (from Paper)",
                "",
                "The paper hypothesized:",
                "- C1 (baseline) → C3 (pre-hoc): ~67% improvement (30% → 50%)",
                "- C1 (baseline) → C4 (full): ~133% improvement (30% → 70%)",
                "",
                "**Actual Results:**",
                f"- Avg C1 success rate: {avg_c1:.1%}",
                f"- Avg C3 success rate: {avg_c3:.1%} (+{c3_improvement:.0f}% improvement)",
                f"- Avg C4 success rate: {avg_c4:.1%} (+{c4_improvement:.0f}% improvement)",
                "",
            ])

    md_file = output_dir / "comparison.md"
    with open(md_file, 'w') as f:
        f.write('\n'.join(md_lines))

    if verbose:
        print("\n" + "=" * 80)
        print("MODEL PERFORMANCE SUMMARY")
        print("=" * 70)
        print(f"{'Model':<30} {'Success':<12} {'Consistency':<12} {'1st Attempt':<12}")
        print("-" * 70)

        for model_name, data in sorted_models:
            m = data['metrics']
            print(f"{model_name:<30} {m['success_rate']:>10.1%}  "
                  f"{m['consistency_pass_rate']:>10.1%}  "
                  f"{m['first_attempt_success_rate']:>10.1%}")

        print("=" * 70)

    print(f"\n✅ Comparison report saved:")
    print(f"   JSON: {json_file}")
    print(f"   Markdown: {md_file}")


# ==================== UNIFIED SUMMARY ====================

def _weighted_average(metrics_list: List[Dict[str, Any]], key: str) -> float:
    """Compute weighted average for rate-based metrics using case counts as weights."""
    numerator = 0.0
    denominator = 0.0

    for metrics in metrics_list:
        value = metrics.get(key)
        weight = metrics.get('total_cases', 0)
        if value is None or weight in (None, 0):
            continue
        numerator += float(value) * float(weight)
        denominator += float(weight)

    return numerator / denominator if denominator else 0.0


def _mean_metric(metrics_list: List[Dict[str, Any]], key: str) -> float:
    """Compute simple mean for already-averaged metrics (e.g., LLM scores)."""
    values: List[float] = []
    for metrics in metrics_list:
        value = metrics.get(key)
        if isinstance(value, (int, float)) and value is not None:
            values.append(float(value))

    return statistics.mean(values) if values else 0.0


def _compute_aggregate_metrics(all_data: Dict[str, Dict[str, Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    """Aggregate metrics across all models for each condition."""
    aggregated: Dict[str, Dict[str, Any]] = {}

    for condition in ['c1', 'c2', 'c3', 'c4']:
        metrics_list: List[Dict[str, Any]] = []

        for condition_map in all_data.values():
            condition_metrics = condition_map.get(condition)
            if condition_metrics:
                metrics_list.append(condition_metrics)

        if not metrics_list:
            continue

        total_cases = sum(float(m.get('total_cases', 0)) for m in metrics_list)

        aggregated_entry = {
            'model_count': len(metrics_list),
            'total_cases': int(total_cases),
            'success_rate': _weighted_average(metrics_list, 'success_rate'),
            'consistency_pass_rate': _weighted_average(metrics_list, 'consistency_pass_rate'),
             'consistency_strict_rate': _weighted_average(metrics_list, 'consistency_strict_rate'),
            'first_attempt_success_rate': _weighted_average(metrics_list, 'first_attempt_success_rate'),
            'ground_truth_similarity': _weighted_average(metrics_list, 'ground_truth_similarity'),
            'vulnerability_elimination_rate': _weighted_average(metrics_list, 'vulnerability_elimination_rate'),
            'avg_llm_accuracy': _mean_metric(metrics_list, 'avg_llm_accuracy'),
            'avg_llm_completeness': _mean_metric(metrics_list, 'avg_llm_completeness'),
            'avg_llm_clarity': _mean_metric(metrics_list, 'avg_llm_clarity'),
            'avg_llm_causality': _mean_metric(metrics_list, 'avg_llm_causality'),
            'syn_eq_rate': _weighted_average(metrics_list, 'syn_eq_rate'),
            'sem_eq_rate': _weighted_average(metrics_list, 'sem_eq_rate'),
            'plausible_rate': _weighted_average(metrics_list, 'plausible_rate'),
        }

        aggregated[condition] = aggregated_entry

    return aggregated


def generate_unified_summary(base_dir: Path, output_dir: Path,
                             verbose: bool = True,
                             model_filter: Optional[List[str]] = None):
    """Generate unified summary across all models and conditions"""

    if verbose:
        print_header("Generating Unified Summary Report")
        print(f"Base directory: {base_dir}")
        if model_filter:
            print(f"Model filter: {', '.join(model_filter)}")

    # Data structure: {model_name: {condition: metrics}}
    all_data = defaultdict(dict)

    # Find all model directories (skip comparison/unified outputs)
    excluded_names = {'comparison', 'unified'}
    output_dir_resolved = output_dir.resolve()

    model_dirs: List[Path] = []
    for d in base_dir.iterdir():
        if not d.is_dir() or d.name.startswith('.'):
            continue
        if d.name in excluded_names:
            continue
        try:
            if d.resolve() == output_dir_resolved:
                continue
        except FileNotFoundError:
            # If the directory disappears between listdir and resolve, skip it
            continue
        model_dirs.append(d)

    for model_dir in sorted(model_dirs):
        model_name = model_dir.name
        results_dir = resolve_model_results_dir(model_dir)

        # Apply model filter
        if not should_include_model(model_name, model_filter):
            if verbose and model_filter:
                print(f"⏭️  Skipping {model_name} (filtered out)")
            continue

        if verbose:
            print(f"\n📊 Processing {model_name}...")

        # Load results for each condition
        for condition in ['c1', 'c2', 'c3', 'c4']:
            # Try different file patterns
            result_file = results_dir / f'{condition}_results.json'
            if not result_file.exists():
                result_file = results_dir / f'{condition}_merged_results.json'
            if not result_file.exists():
                continue

            try:
                with open(result_file, 'r') as f:
                    data = json.load(f)

                metrics = data.get('metrics', {})
                cases = data.get('cases', [])
                averages, _, _ = compute_llm_averages(cases)
                if averages:
                    metrics.update(averages)

                all_data[model_name][condition] = {
                    'total_cases': int(metrics.get('total_cases', len(cases))),
                    'success_rate': metrics.get('success_rate', 0.0),
                    'consistency_pass_rate': metrics.get('consistency_pass_rate', 0.0),
                    'consistency_strict_rate': metrics.get('consistency_strict_rate',
                                                           metrics.get('consistency_pass_rate', 0.0)),
                    'first_attempt_success_rate': metrics.get('first_attempt_success_rate', 0.0),
                    'ground_truth_similarity': metrics.get('avg_ast_overall_similarity',
                                                          metrics.get('ground_truth_match_rate', 0.0)),
                    'vulnerability_elimination_rate': metrics.get('vulnerability_elimination_rate', 0.0),
                    'avg_llm_accuracy': metrics.get('avg_llm_accuracy', 0.0),
                    'avg_llm_completeness': metrics.get('avg_llm_completeness', 0.0),
                    'avg_llm_clarity': metrics.get('avg_llm_clarity', 0.0),
                    'avg_llm_causality': metrics.get('avg_llm_causality', 0.0),
                    # LLM Judge success breakdown
                    'syn_eq_rate': metrics.get('syn_eq_rate', 0.0),
                    'sem_eq_rate': metrics.get('sem_eq_rate', 0.0),
                    'plausible_rate': metrics.get('plausible_rate', 0.0),
                }

                if verbose:
                    print(f"  ✅ {condition.upper()}: {metrics.get('success_rate', 0):.1%} success "
                          f"({int(metrics.get('total_cases', 0))} cases)")

            except Exception as e:
                if verbose:
                    print(f"  ⚠️  Failed to load {condition}: {e}")
                continue

    if not all_data:
        print("❌ No data found")
        return

    # Compute aggregate metrics across models
    aggregated_data = _compute_aggregate_metrics(all_data)

    # Generate reports
    output_dir.mkdir(parents=True, exist_ok=True)

    # JSON report
    unified_data = {
        'generated_at': datetime.now().isoformat(),
        'base_directory': str(base_dir),
        'total_models': len(all_data),
        'models': dict(all_data),
        'aggregate': aggregated_data
    }

    json_file = output_dir / "unified_summary.json"
    with open(json_file, 'w') as f:
        json.dump(unified_data, f, indent=2)

    # Generate comprehensive markdown report
    md_file = output_dir / "unified_summary.md"
    _generate_unified_markdown(all_data, aggregated_data, md_file)

    # Generate console output
    if verbose:
        _print_unified_console(all_data, aggregated_data)

    print(f"\n✅ Unified summary saved:")
    print(f"   JSON: {json_file}")
    print(f"   Markdown: {md_file}")


def _generate_unified_markdown(all_data: Dict[str, Dict[str, Dict]],
                               aggregated_data: Dict[str, Dict[str, Any]],
                               output_path: Path):
    """Generate unified markdown report"""

    lines = [
        "# PatchScribe Unified Summary Report",
        "",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Total Models:** {len(all_data)}  ",
        "",
        "---",
        "",
        "## Overall Success Rate Comparison",
        "",
        "| Model | C1 (Baseline) | C2 (Vague) | C3 (Pre-hoc) | C4 (Full) | Δ C1→C4 |",
        "|-------|---------------|------------|--------------|-----------|---------|",
    ]

    # Sort by C4 success rate
    sorted_models = sorted(all_data.items(),
                          key=lambda x: x[1].get('c4', {}).get('success_rate', 0),
                          reverse=True)

    for model_name, conditions in sorted_models:
        c1 = conditions.get('c1', {}).get('success_rate', 0)
        c2 = conditions.get('c2', {}).get('success_rate', 0)
        c3 = conditions.get('c3', {}).get('success_rate', 0)
        c4 = conditions.get('c4', {}).get('success_rate', 0)

        delta = c4 - c1 if c1 > 0 else 0

        lines.append(
            f"| {model_name} | {c1:.1%} | {c2:.1%} | {c3:.1%} | {c4:.1%} | "
            f"{'+' if delta >= 0 else ''}{delta:.1%} |"
        )

    if aggregated_data:
        agg_c1 = aggregated_data.get('c1', {}).get('success_rate', 0)
        agg_c2 = aggregated_data.get('c2', {}).get('success_rate', 0)
        agg_c3 = aggregated_data.get('c3', {}).get('success_rate', 0)
        agg_c4 = aggregated_data.get('c4', {}).get('success_rate', 0)
        delta = 0.0
        if aggregated_data.get('c1') and aggregated_data.get('c4'):
            delta = agg_c4 - agg_c1
        lines.append(
            f"| **All Models (weighted)** | {agg_c1:.1%} | {agg_c2:.1%} | {agg_c3:.1%} | "
            f"{agg_c4:.1%} | {'+' if delta >= 0 else ''}{delta:.1%} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## Detailed Metrics by Condition",
        "",
    ])

    # Detailed metrics for each condition
    for condition in ['c1', 'c2', 'c3', 'c4']:
        cond_label = {
            'c1': 'C1 (Baseline - No Explanation)',
            'c2': 'C2 (Vague Hints)',
            'c3': 'C3 (Pre-hoc Formal E_bug)',
            'c4': 'C4 (Full PatchScribe - E_bug + E_patch)'
        }.get(condition, condition.upper())

        lines.extend([
            f"### {cond_label}",
            "",
            "| Model | Cases | Success | Consistency | Strict | 1st Attempt | GT Similarity |",
            "|-------|-------|---------|-------------|--------|-------------|---------------|",
        ])

        # Sort by success rate for this condition
        models_with_cond = [(m, d[condition]) for m, d in all_data.items() if condition in d]
        models_with_cond.sort(key=lambda x: x[1].get('success_rate', 0), reverse=True)

        for model_name, metrics in models_with_cond:
            strict_rate = metrics.get('consistency_strict_rate', metrics['consistency_pass_rate'])
            lines.append(
                f"| {model_name} | {metrics['total_cases']} | "
                f"{metrics['success_rate']:.1%} | "
                f"{metrics['consistency_pass_rate']:.1%} | "
                f"{strict_rate:.1%} | "
                f"{metrics['first_attempt_success_rate']:.1%} | "
                f"{metrics['ground_truth_similarity']:.1%} |"
            )

        if aggregated_data.get(condition):
            agg = aggregated_data[condition]
            strict_rate = agg.get('consistency_strict_rate', agg.get('consistency_pass_rate', 0.0))
            lines.append(
                f"| **All Models** | {agg['total_cases']} | {agg['success_rate']:.1%} | "
                f"{agg['consistency_pass_rate']:.1%} | {strict_rate:.1%} | {agg['first_attempt_success_rate']:.1%} | "
                f"{agg['ground_truth_similarity']:.1%} |"
            )

        lines.append("")

    if aggregated_data:
        lines.extend([
            "---",
            "",
            "## Aggregate Metrics Across Models",
            "",
            "| Condition | Models | Total Cases | Success | Consistency | Strict | 1st Attempt | GT Similarity | Vuln Elimin. |",
            "|-----------|--------|-------------|---------|-------------|--------|-------------|---------------|--------------|",
        ])

        cond_labels = {
            'c1': 'C1 (Baseline)',
            'c2': 'C2 (Vague)',
            'c3': 'C3 (Pre-hoc)',
            'c4': 'C4 (Full)'
        }

        for condition in ['c1', 'c2', 'c3', 'c4']:
            if condition not in aggregated_data:
                continue
            agg = aggregated_data[condition]
            strict_rate = agg.get('consistency_strict_rate', agg['consistency_pass_rate'])
            lines.append(
                f"| {cond_labels.get(condition, condition.upper())} | {agg['model_count']} | "
                f"{agg['total_cases']} | {agg['success_rate']:.1%} | "
                f"{agg['consistency_pass_rate']:.1%} | {strict_rate:.1%} | {agg['first_attempt_success_rate']:.1%} | "
                f"{agg['ground_truth_similarity']:.1%} | {agg['vulnerability_elimination_rate']:.1%} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## Aggregate LLM Judge Scores",
            "",
            "| Condition | Accuracy | Completeness | Clarity | Causality |",
            "|-----------|----------|--------------|---------|-----------|",
        ])

        for condition in ['c1', 'c2', 'c3', 'c4']:
            if condition not in aggregated_data:
                continue
            agg = aggregated_data[condition]
            lines.append(
                f"| {cond_labels.get(condition, condition.upper())} | "
                f"{agg['avg_llm_accuracy']:.2f} | {agg['avg_llm_completeness']:.2f} | "
                f"{agg['avg_llm_clarity']:.2f} | {agg['avg_llm_causality']:.2f} |"
            )

        lines.append("")

    def _fmt_llm(value: Any) -> str:
        if isinstance(value, (int, float)):
            return f"{value:.2f}"
        return "—"

    # Detailed LLM judge quality per model and condition
    lines.extend([
        "---",
        "",
        "## LLM Judge Quality by Condition and Model",
        "",
    ])

    condition_headings = {
        'c1': 'C1 (Baseline)',
        'c2': 'C2 (Vague Hints)',
        'c3': 'C3 (Pre-hoc)',
        'c4': 'C4 (Full PatchScribe)'
    }

    for condition in ['c1', 'c2', 'c3', 'c4']:
        rows = []
        for model_name, condition_map in all_data.items():
            metrics = condition_map.get(condition)
            if not metrics:
                continue

            has_scores = any(key in metrics for key in (
                'avg_llm_accuracy',
                'avg_llm_completeness',
                'avg_llm_clarity',
                'avg_llm_causality',
            ))
            if not has_scores:
                continue

            rows.append(
                (
                    model_name,
                    _fmt_llm(metrics.get('avg_llm_accuracy')),
                    _fmt_llm(metrics.get('avg_llm_completeness')),
                    _fmt_llm(metrics.get('avg_llm_clarity')),
                    _fmt_llm(metrics.get('avg_llm_causality')),
                )
            )

        if not rows:
            continue

        lines.extend([
            f"### {condition_headings.get(condition, condition.upper())}",
            "",
            "| Model | Accuracy | Completeness | Clarity | Causality |",
            "|-------|----------|--------------|---------|-----------|",
        ])

        for model_name, acc, comp, clar, caus in rows:
            lines.append(f"| {model_name} | {acc} | {comp} | {clar} | {caus} |")

        lines.append("")

    # Calculate summary statistics: model averages and metric averages by condition
    # Collect all data first
    condition_data = {}
    for condition in ['c1', 'c2', 'c3', 'c4']:
        condition_data[condition] = {}
        for model_name, condition_map in all_data.items():
            metrics = condition_map.get(condition)
            if not metrics:
                continue
            
            acc = metrics.get('avg_llm_accuracy')
            comp = metrics.get('avg_llm_completeness')
            clar = metrics.get('avg_llm_clarity')
            caus = metrics.get('avg_llm_causality')
            
            if acc is not None or comp is not None or clar is not None or caus is not None:
                condition_data[condition][model_name] = {
                    'accuracy': acc if acc is not None else 0,
                    'completeness': comp if comp is not None else 0,
                    'clarity': clar if clar is not None else 0,
                    'causality': caus if caus is not None else 0,
                }
    
    # Calculate model averages by condition
    model_averages = {}
    for model_name in all_data.keys():
        model_averages[model_name] = {}
        for condition in ['c1', 'c2', 'c3', 'c4']:
            if model_name in condition_data[condition]:
                scores = condition_data[condition][model_name]
                values = [scores[k] for k in ['accuracy', 'completeness', 'clarity', 'causality'] if scores[k] > 0]
                if values:
                    model_averages[model_name][condition] = statistics.mean(values)
                else:
                    model_averages[model_name][condition] = 0
    
    # Calculate metric averages by condition
    metric_averages = {
        'accuracy': {},
        'completeness': {},
        'clarity': {},
        'causality': {}
    }
    for condition in ['c1', 'c2', 'c3', 'c4']:
        for metric in ['accuracy', 'completeness', 'clarity', 'causality']:
            values = []
            for model_name in condition_data[condition]:
                val = condition_data[condition][model_name][metric]
                if val > 0:
                    values.append(val)
            if values:
                metric_averages[metric][condition] = statistics.mean(values)
            else:
                metric_averages[metric][condition] = 0
    
    # Add summary statistics section
    lines.extend([
        "---",
        "",
        "## LLM Judge Quality Summary Statistics",
        "",
        "### Model Averages by Condition",
        "",
        "| Model | C1 Average | C2 Average | C3 Average | C4 Average |",
        "|-------|------------|------------|------------|------------|",
    ])
    
    # Add model averages rows
    for model_name in sorted(model_averages.keys()):
        c1_avg = model_averages[model_name].get('c1', 0)
        c2_avg = model_averages[model_name].get('c2', 0)
        c3_avg = model_averages[model_name].get('c3', 0)
        c4_avg = model_averages[model_name].get('c4', 0)
        lines.append(
            f"| {model_name} | {c1_avg:.2f} | {c2_avg:.2f} | {c3_avg:.2f} | {c4_avg:.2f} |"
        )
    
    # Calculate overall average for all models
    all_models_c1 = [v.get('c1', 0) for v in model_averages.values() if v.get('c1', 0) > 0]
    all_models_c2 = [v.get('c2', 0) for v in model_averages.values() if v.get('c2', 0) > 0]
    all_models_c3 = [v.get('c3', 0) for v in model_averages.values() if v.get('c3', 0) > 0]
    all_models_c4 = [v.get('c4', 0) for v in model_averages.values() if v.get('c4', 0) > 0]
    
    overall_c1 = statistics.mean(all_models_c1) if all_models_c1 else 0
    overall_c2 = statistics.mean(all_models_c2) if all_models_c2 else 0
    overall_c3 = statistics.mean(all_models_c3) if all_models_c3 else 0
    overall_c4 = statistics.mean(all_models_c4) if all_models_c4 else 0
    
    lines.append(
        f"| **All Models Average** | {overall_c1:.2f} | {overall_c2:.2f} | {overall_c3:.2f} | {overall_c4:.2f} |"
    )
    
    lines.extend([
        "",
        "### Metric Averages by Condition",
        "",
        "| Metric | C1 Average | C2 Average | C3 Average | C4 Average |",
        "|--------|------------|------------|------------|------------|",
    ])
    
    # Add metric averages rows
    metric_labels = {
        'accuracy': 'Accuracy',
        'completeness': 'Completeness',
        'clarity': 'Clarity',
        'causality': 'Causality'
    }
    
    for metric in ['accuracy', 'completeness', 'clarity', 'causality']:
        c1_avg = metric_averages[metric].get('c1', 0)
        c2_avg = metric_averages[metric].get('c2', 0)
        c3_avg = metric_averages[metric].get('c3', 0)
        c4_avg = metric_averages[metric].get('c4', 0)
        lines.append(
            f"| {metric_labels[metric]} | {c1_avg:.2f} | {c2_avg:.2f} | {c3_avg:.2f} | {c4_avg:.2f} |"
        )
    
    # Calculate overall average for all metrics
    all_metrics_c1 = [metric_averages[m].get('c1', 0) for m in ['accuracy', 'completeness', 'clarity', 'causality'] if metric_averages[m].get('c1', 0) > 0]
    all_metrics_c2 = [metric_averages[m].get('c2', 0) for m in ['accuracy', 'completeness', 'clarity', 'causality'] if metric_averages[m].get('c2', 0) > 0]
    all_metrics_c3 = [metric_averages[m].get('c3', 0) for m in ['accuracy', 'completeness', 'clarity', 'causality'] if metric_averages[m].get('c3', 0) > 0]
    all_metrics_c4 = [metric_averages[m].get('c4', 0) for m in ['accuracy', 'completeness', 'clarity', 'causality'] if metric_averages[m].get('c4', 0) > 0]
    
    overall_metrics_c1 = statistics.mean(all_metrics_c1) if all_metrics_c1 else 0
    overall_metrics_c2 = statistics.mean(all_metrics_c2) if all_metrics_c2 else 0
    overall_metrics_c3 = statistics.mean(all_metrics_c3) if all_metrics_c3 else 0
    overall_metrics_c4 = statistics.mean(all_metrics_c4) if all_metrics_c4 else 0
    
    lines.append(
        f"| **All Metrics Average** | {overall_metrics_c1:.2f} | {overall_metrics_c2:.2f} | {overall_metrics_c3:.2f} | {overall_metrics_c4:.2f} |"
    )
    
    lines.extend([
        "",
        "---",
        "",
        "## LLM Judge Quality Scores by Model (C4)",
        "",
        "| Model | Accuracy | Completeness | Clarity | Causality | Average |",
        "|-------|----------|--------------|---------|-----------|---------|",
    ])

    # LLM scores for C4
    c4_llm_scores = []
    for model_name, conditions in all_data.items():
        c4_metrics = conditions.get('c4', {})
        acc = c4_metrics.get('avg_llm_accuracy', 0)
        comp = c4_metrics.get('avg_llm_completeness', 0)
        clar = c4_metrics.get('avg_llm_clarity', 0)
        caus = c4_metrics.get('avg_llm_causality', 0)

        if acc > 0 or comp > 0 or clar > 0 or caus > 0:
            avg = statistics.mean([s for s in [acc, comp, clar, caus] if s > 0])
            c4_llm_scores.append((model_name, acc, comp, clar, caus, avg))

    # Sort by average score
    c4_llm_scores.sort(key=lambda x: x[5], reverse=True)

    for model_name, acc, comp, clar, caus, avg in c4_llm_scores:
        lines.append(
            f"| {model_name} | {acc:.2f} | {comp:.2f} | {clar:.2f} | {caus:.2f} | {avg:.2f} |"
        )

    if not c4_llm_scores:
        lines.append("| *No LLM judge scores available* | - | - | - | - | - |")

    # LLM Judge Success Breakdown section
    lines.extend([
        "",
        "---",
        "",
        "## LLM Judge Success Breakdown",
        "",
        "Shows how patches were classified by the LLM judge (SynEq/SemEq/Plausible).",
        "",
    ])

    condition_labels = {
        'c1': 'C1 (Baseline)',
        'c2': 'C2 (Vague Hints)',
        'c3': 'C3 (Pre-hoc)',
        'c4': 'C4 (Full PatchScribe)'
    }

    for condition in ['c1', 'c2', 'c3', 'c4']:
        models_with_cond = [(m, d[condition]) for m, d in all_data.items() if condition in d]
        if not models_with_cond:
            continue

        # Check if any model has judge data
        has_judge_data = any(
            m.get('syn_eq_rate', 0) + m.get('sem_eq_rate', 0) + m.get('plausible_rate', 0) > 0
            for _, m in models_with_cond
        )
        if not has_judge_data:
            continue

        lines.extend([
            f"### {condition_labels.get(condition, condition.upper())}",
            "",
            "| Model | SynEq | SemEq | Plausible | Failed |",
            "|-------|-------|-------|-----------|--------|",
        ])

        models_with_cond.sort(key=lambda x: (
            x[1].get('syn_eq_rate', 0) +
            x[1].get('sem_eq_rate', 0) +
            x[1].get('plausible_rate', 0)
        ), reverse=True)

        for model_name, metrics in models_with_cond:
            syn_eq = metrics.get('syn_eq_rate', 0.0)
            sem_eq = metrics.get('sem_eq_rate', 0.0)
            plausible = metrics.get('plausible_rate', 0.0)
            failed = 1.0 - (syn_eq + sem_eq + plausible)

            lines.append(
                f"| {model_name} | {syn_eq:.1%} | {sem_eq:.1%} | {plausible:.1%} | {failed:.1%} |"
            )

        if aggregated_data.get(condition):
            agg = aggregated_data[condition]
            syn_eq = agg.get('syn_eq_rate', 0.0)
            sem_eq = agg.get('sem_eq_rate', 0.0)
            plausible = agg.get('plausible_rate', 0.0)
            failed = 1.0 - (syn_eq + sem_eq + plausible)

            lines.append(
                f"| **All Models** | {syn_eq:.1%} | {sem_eq:.1%} | {plausible:.1%} | {failed:.1%} |"
            )

        lines.append("")

    lines.extend([
        "",
        "---",
        "",
        "## Key Insights",
        "",
    ])

    # Calculate insights
    if sorted_models:
        best_model = sorted_models[0]
        best_c4_rate = best_model[1].get('c4', {}).get('success_rate', 0)

        lines.append(f"- **Best Overall Model (C4):** {best_model[0]} ({best_c4_rate:.1%} success rate)")

        # Average improvement from C1 to C4
        improvements = []
        for model_name, conditions in all_data.items():
            c1_rate = conditions.get('c1', {}).get('success_rate', 0)
            c4_rate = conditions.get('c4', {}).get('success_rate', 0)
            if c1_rate > 0:
                improvement = (c4_rate - c1_rate) / c1_rate
                improvements.append(improvement)

        if improvements:
            avg_improvement = statistics.mean(improvements)
            lines.append(f"- **Average C1→C4 Improvement:** {avg_improvement:.1%}")

        # Count how many models have all conditions
        complete_models = sum(1 for m, d in all_data.items()
                             if all(f'c{i}' in d for i in range(1, 5)))
        lines.append(f"- **Models with Complete Data (C1-C4):** {complete_models}/{len(all_data)}")

        if aggregated_data.get('c4'):
            lines.append(f"- **Weighted C4 Success (All Models):** {aggregated_data['c4']['success_rate']:.1%}")

    lines.extend([
        "",
        "---",
        "",
        "## Condition Descriptions",
        "",
        "- **C1 (Baseline):** No explanation guidance - baseline LLM patch generation",
        "- **C2 (Vague Hints):** Generic vulnerability hints without formal specification",
        "- **C3 (Pre-hoc E_bug):** Formal causal bug explanation before patch generation",
        "- **C4 (Full PatchScribe):** Complete pipeline with E_bug + E_patch dual verification",
        "",
    ])

    output_path.write_text('\n'.join(lines))


def _print_unified_console(all_data: Dict[str, Dict[str, Dict]],
                           aggregated_data: Dict[str, Dict[str, Any]]):
    """Print unified summary to console"""

    print_header("UNIFIED SUMMARY - ALL MODELS & CONDITIONS")

    # Overall comparison table
    print("\n" + "=" * 100)
    print(f"{'Model':<30} {'C1 (Base)':<12} {'C2 (Vague)':<12} {'C3 (Pre)':<12} {'C4 (Full)':<12} {'Δ C1→C4':<10}")
    print("=" * 100)

    sorted_models = sorted(all_data.items(),
                          key=lambda x: x[1].get('c4', {}).get('success_rate', 0),
                          reverse=True)

    for model_name, conditions in sorted_models:
        c1 = conditions.get('c1', {}).get('success_rate', 0)
        c2 = conditions.get('c2', {}).get('success_rate', 0)
        c3 = conditions.get('c3', {}).get('success_rate', 0)
        c4 = conditions.get('c4', {}).get('success_rate', 0)
        delta = c4 - c1

        print(f"{model_name:<30} {c1:>10.1%}  {c2:>10.1%}  {c3:>10.1%}  {c4:>10.1%}  "
              f"{'+' if delta >= 0 else ''}{delta:>8.1%}")

    if aggregated_data:
        agg_c1 = aggregated_data.get('c1', {}).get('success_rate', 0)
        agg_c2 = aggregated_data.get('c2', {}).get('success_rate', 0)
        agg_c3 = aggregated_data.get('c3', {}).get('success_rate', 0)
        agg_c4 = aggregated_data.get('c4', {}).get('success_rate', 0)
        delta = agg_c4 - agg_c1
        print('-' * 100)
        print(f"{'All Models (weighted)':<30} {agg_c1:>10.1%}  {agg_c2:>10.1%}  {agg_c3:>10.1%}  "
              f"{agg_c4:>10.1%}  {'+' if delta >= 0 else ''}{delta:>8.1%}")

    print("=" * 100)

    # Detailed condition breakdown
    for condition in ['c1', 'c2', 'c3', 'c4']:
        cond_label = {
            'c1': 'C1 (Baseline)',
            'c2': 'C2 (Vague Hints)',
            'c3': 'C3 (Pre-hoc)',
            'c4': 'C4 (Full PatchScribe)'
        }.get(condition, condition.upper())

        models_with_cond = [(m, d[condition]) for m, d in all_data.items() if condition in d]
        if not models_with_cond:
            continue

        print(f"\n{'-' * 85}")
        print(f"{cond_label}")
        print(f"{'-' * 100}")
        print(f"{'Model':<30} {'Cases':<8} {'Success':<10} {'Consistency':<12} {'Strict':<10} {'1st Attempt':<12}")
        print(f"{'-' * 100}")

        models_with_cond.sort(key=lambda x: x[1].get('success_rate', 0), reverse=True)

        for model_name, metrics in models_with_cond:
            strict_rate = metrics.get('consistency_strict_rate', metrics['consistency_pass_rate'])
            print(f"{model_name:<30} {metrics['total_cases']:<8} "
                  f"{metrics['success_rate']:>8.1%}  "
                  f"{metrics['consistency_pass_rate']:>10.1%}  "
                  f"{strict_rate:>8.1%}  "
                  f"{metrics['first_attempt_success_rate']:>10.1%}")

        if aggregated_data.get(condition):
            agg = aggregated_data[condition]
            strict_rate = agg.get('consistency_strict_rate', agg['consistency_pass_rate'])
            print(f"{'All Models':<30} {agg['total_cases']:<8} "
                  f"{agg['success_rate']:>8.1%}  "
                  f"{agg['consistency_pass_rate']:>10.1%}  "
                  f"{strict_rate:>8.1%}  "
                  f"{agg['first_attempt_success_rate']:>10.1%}")

    # LLM Judge Success Breakdown
    print("\n" + "=" * 100)
    print("LLM JUDGE SUCCESS BREAKDOWN")
    print("=" * 100)

    for condition in ['c1', 'c2', 'c3', 'c4']:
        cond_label = {
            'c1': 'C1 (Baseline)',
            'c2': 'C2 (Vague Hints)',
            'c3': 'C3 (Pre-hoc)',
            'c4': 'C4 (Full PatchScribe)'
        }.get(condition, condition.upper())

        models_with_cond = [(m, d[condition]) for m, d in all_data.items() if condition in d]
        if not models_with_cond:
            continue

        # Check if any model has judge data
        has_judge_data = any(
            m.get('syn_eq_rate', 0) + m.get('sem_eq_rate', 0) + m.get('plausible_rate', 0) > 0
            for _, m in models_with_cond
        )
        if not has_judge_data:
            continue

        print(f"\n{'-' * 100}")
        print(f"{cond_label}")
        print(f"{'-' * 100}")
        print(f"{'Model':<30} {'SynEq':<10} {'SemEq':<10} {'Plausible':<12} {'Failed':<10}")
        print(f"{'-' * 100}")

        models_with_cond.sort(key=lambda x: (
            x[1].get('syn_eq_rate', 0) +
            x[1].get('sem_eq_rate', 0) +
            x[1].get('plausible_rate', 0)
        ), reverse=True)

        for model_name, metrics in models_with_cond:
            syn_eq = metrics.get('syn_eq_rate', 0.0)
            sem_eq = metrics.get('sem_eq_rate', 0.0)
            plausible = metrics.get('plausible_rate', 0.0)
            failed = 1.0 - (syn_eq + sem_eq + plausible)

            print(f"{model_name:<30} {syn_eq:>8.1%}  {sem_eq:>8.1%}  {plausible:>10.1%}  {failed:>8.1%}")

        if aggregated_data.get(condition):
            agg = aggregated_data[condition]
            syn_eq = agg.get('syn_eq_rate', 0.0)
            sem_eq = agg.get('sem_eq_rate', 0.0)
            plausible = agg.get('plausible_rate', 0.0)
            failed = 1.0 - (syn_eq + sem_eq + plausible)

            print(f"{'All Models':<30} {syn_eq:>8.1%}  {sem_eq:>8.1%}  {plausible:>10.1%}  {failed:>8.1%}")

    print("\n" + "=" * 100)


# ==================== MAIN ====================

def main():
    parser = argparse.ArgumentParser(
        description='PatchScribe Comprehensive Analysis Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:

1. Analyze single result file:
   python3 scripts/analyze.py results/local/qwen3-4b/c4_results.json

2. Analyze entire directory (C4 only by default):
   python3 scripts/analyze.py results/local

3. Analyze all conditions (C1-C4 ablation study):
   python3 scripts/analyze.py results/local --all-conditions

4. Merge distributed results and analyze:
   python3 scripts/analyze.py --merge results/server*

5. Compare multiple models:
   python3 scripts/analyze.py --compare results/model1 results/model2

6. Filter specific models:
   python3 scripts/analyze.py results/local --models qwen3-4b deepseek-r1-7b

7. Show unified summary of all models and conditions:
   python3 scripts/analyze.py --unified results/local

Output:
  - Comprehensive RQ1-RQ4 analysis (JSON)
  - Markdown summary report
  - Multi-model comparison (if applicable)
  - Console summary statistics

Note:
  - Default: Only C4 (full PatchScribe) is analyzed
  - Use --all-conditions to analyze C1-C4 for ablation study
        """
    )

    parser.add_argument(
        'input_paths',
        nargs='+',
        type=Path,
        help='Paths to analyze (directories or JSON files)'
    )

    parser.add_argument(
        '--merge',
        action='store_true',
        help='Merge distributed experiment results'
    )

    parser.add_argument(
        '--compare',
        action='store_true',
        help='Generate multi-model comparison report'
    )

    parser.add_argument(
        '-o', '--output',
        type=Path,
        help='Output directory (default: auto-determined from input)'
    )

    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='(Deprecated) Output is minimal by default'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed console output (RQ breakdowns, tables, etc.)'
    )

    parser.add_argument(
        '--run-judge',
        action='store_true',
        help='Run LLM judge evaluation before analysis'
    )
    parser.add_argument(
        '--judge-only',
        action='store_true',
        help='Only run the LLM judge without full analysis'
    )
    parser.add_argument(
        '--judge-batch-size',
        type=int,
        default=5,
        help='Batch size for LLM judge requests (default: 5)'
    )

    parser.add_argument(
        '--models',
        nargs='+',
        help='Filter models to analyze (e.g., --models qwen3-4b deepseek-r1-7b)'
    )

    parser.add_argument(
        '--all-conditions',
        action='store_true',
        help='Analyze all conditions (C1-C4). Default: only C4 (full PatchScribe)'
    )

    parser.add_argument(
        '--unified',
        action='store_true',
        help='Generate unified summary of all models and conditions'
    )

    args = parser.parse_args()

    if args.verbose and args.quiet:
        parser.error("Cannot use --quiet and --verbose together")

    verbose = args.verbose
    # Handle comma-separated model names as well as space-separated
    model_filter = None
    if args.models:
        model_filter = []
        for model in args.models:
            # Split by comma in case user provided comma-separated list
            model_filter.extend([m.strip() for m in model.split(',') if m.strip()])
        if not model_filter:
            model_filter = None

    def _print_analysis_saved(analyzer: RQAnalyzer) -> None:
        """Print minimal completion info when running in quiet mode."""
        if verbose:
            return
        json_path = analyzer.last_output_path
        md_path = analyzer.last_markdown_path
        if not json_path:
            return
        condition_label = analyzer.condition.upper() if analyzer.condition else 'N/A'
        print(f"✅ {analyzer.model} ({condition_label}) analysis saved")
        print(f"   JSON: {json_path}")
        if md_path:
            print(f"   Markdown: {md_path}")

    if args.judge_only and not args.run_judge:
        args.run_judge = True

    if args.judge_batch_size < 1:
        args.judge_batch_size = 1

    if verbose and model_filter:
        print(f"\n🔍 Model filter active: {', '.join(model_filter)}")

    if (args.merge or args.compare) and args.run_judge and verbose:
        print("⚠️  --run-judge is ignored in merge/compare mode")

    try:
        # Unified summary mode
        if args.unified:
            if len(args.input_paths) != 1 or not args.input_paths[0].is_dir():
                print("❌ --unified requires exactly one directory path")
                sys.exit(1)

            base_dir = args.input_paths[0]
            output_dir = args.output if args.output else base_dir / "unified"

            generate_unified_summary(base_dir, output_dir, verbose, model_filter)

        # Merge mode
        elif args.merge:
            server_dirs = [p for p in args.input_paths if p.is_dir()]

            if not server_dirs:
                print("❌ No server directories found")
                sys.exit(1)

            output_dir = args.output if args.output else Path('results/merged')

            merged_dir = merge_distributed_results(server_dirs, output_dir,
                                                  verbose, model_filter)

            # Auto-analyze merged results
            if verbose:
                print_header("Analyzing Merged Results")

            for model_dir in merged_dir.iterdir():
                if not model_dir.is_dir() or model_dir.name.startswith('.'):
                    continue

                if not should_include_model(model_dir.name, model_filter):
                    continue

                results_dir = resolve_model_results_dir(model_dir)
                c4_file = results_dir / "c4_merged_results.json"
                if c4_file.exists():
                    analyzer = RQAnalyzer(c4_file)
                    analyzer.generate_comprehensive_report(verbose=verbose)
                    _print_analysis_saved(analyzer)

            # Generate comparison report
            comparison_dir = args.output.parent / "comparison" if args.output else Path('results/comparison')
            generate_comparison_report([merged_dir], comparison_dir, verbose, model_filter)

        # Compare mode
        elif args.compare:
            output_dir = args.output if args.output else Path('results/comparison')
            generate_comparison_report(args.input_paths, output_dir, verbose, model_filter)

        # Analysis mode
        else:
            results_analyzed = 0
            judge_updates = 0

            for input_path in args.input_paths:
                # Direct JSON file
                if input_path.is_file() and input_path.suffix == '.json':
                    model_name = input_path.parent.name
                    if not should_include_model(model_name, model_filter):
                        if verbose and model_filter:
                            print(f"⏭️  Skipping {model_name} (filtered out)")
                        continue

                    if args.run_judge:
                        if verbose:
                            print(f"\n🤖 Running judge for {input_path}")
                        if run_llm_judge_on_file(input_path, batch_size=args.judge_batch_size,
                                                  verbose=verbose):
                            judge_updates += 1

                    if args.judge_only:
                        continue

                    analyzer = RQAnalyzer(input_path)
                    analyzer.generate_comprehensive_report(verbose=verbose)
                    _print_analysis_saved(analyzer)
                    results_analyzed += 1

                # Directory - find result files
                elif input_path.is_dir():
                    if args.all_conditions:
                        conditions = ['c1', 'c2', 'c3', 'c4']
                    else:
                        conditions = ['c4']

                    # Find all model directories
                    model_dirs = [d for d in input_path.iterdir()
                                 if d.is_dir() and not d.name.startswith('.')
                                 and d.name not in ('comparison', 'unified')]

                    if not model_dirs:
                        if verbose:
                            print(f"⚠️  No model directories found in {input_path}")
                        continue

                    models_analyzed = set()
                    result_files: List[Path] = []

                    # For each model, use only the most recent timestamp directory
                    for model_dir in model_dirs:
                        model_name = model_dir.name

                        if not should_include_model(model_name, model_filter):
                            if verbose and model_filter:
                                print(f"⏭️  Skipping {model_name} (filtered out)")
                            continue

                        # Resolve to most recent timestamp directory
                        results_dir = resolve_model_results_dir(model_dir)

                        # Find result files for requested conditions
                        for condition in conditions:
                            result_file = results_dir / f'{condition}_results.json'
                            if not result_file.exists():
                                result_file = results_dir / f'{condition}_merged_results.json'
                            if result_file.exists():
                                result_files.append(result_file)

                    if not result_files:
                        if verbose:
                            cond_str = "C1-C4" if args.all_conditions else "C4"
                            print(f"⚠️  No {cond_str} result files found in {input_path}")
                        continue

                    for result_file in sorted(result_files):
                        # Get model name - skip timestamp directories
                        parent_dir = result_file.parent
                        if looks_like_timestamp(parent_dir.name):
                            model_name = parent_dir.parent.name
                        else:
                            model_name = parent_dir.name

                        condition = result_file.stem.split('_')[0]

                        if args.run_judge:
                            if verbose:
                                print(f"\n🤖 Running judge for {model_name} - {condition.upper()}")
                            if run_llm_judge_on_file(result_file, batch_size=args.judge_batch_size,
                                                      verbose=verbose):
                                judge_updates += 1

                        if args.judge_only:
                            continue

                        if verbose:
                            print(f"\n📊 Analyzing {model_name} - {condition.upper()}")

                        analyzer = RQAnalyzer(result_file)
                        analyzer.generate_comprehensive_report(verbose=verbose)
                        _print_analysis_saved(analyzer)
                        results_analyzed += 1
                        models_analyzed.add(model_name)

                    if not args.judge_only and len(models_analyzed) > 1:
                        comparison_dir = input_path / "comparison"
                        generate_comparison_report([input_path], comparison_dir,
                                                  verbose, model_filter)

            if args.judge_only:
                if verbose:
                    print_header("Judge Evaluation Complete")
                    if judge_updates:
                        print(f"\n✅ Updated {judge_updates} file(s) with judge scores\n")
                    else:
                        print("\n⚠️  LLM judge did not update any files\n")
                else:
                    print(f"✅ LLM judge finished - updated {judge_updates} file(s)")
                sys.exit(0)

            if results_analyzed == 0:
                print("❌ No results found to analyze")
                sys.exit(1)

            if verbose:
                if args.run_judge:
                    print_header("Judge Evaluation Summary")
                    if judge_updates:
                        print(f"\n✅ Updated {judge_updates} file(s) with judge scores")
                    else:
                        print("\n⚠️  LLM judge did not update any files")
                    print("")
                print_header("Analysis Complete")
                print(f"\n✅ Analyzed {results_analyzed} result file(s)\n")
            else:
                if args.run_judge:
                    print(f"✅ Judge evaluation complete - updated {judge_updates} file(s)")
                print(f"✅ Analyzed {results_analyzed} result file(s)")

    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user\n")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Analysis failed: {e}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
