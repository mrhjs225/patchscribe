#!/usr/bin/env python3
"""
PatchScribe Comprehensive Analysis Script

Unified analysis tool for all Research Questions (RQ1-RQ4) based on the paper evaluation plan.
This script provides complete analysis for the PatchScribe paper evaluation, including:
- RQ1: Theory-Guided Generation Effectiveness
- RQ2: Dual Verification Effectiveness
- RQ3: Scalability and Performance
- RQ4: Explanation Quality and Developer Trust

Usage:
    # Analyze single result file
    python3 scripts/analyze.py results/local/qwen3-4b/c4_results.json

    # Analyze entire directory
    python3 scripts/analyze.py results/local

    # Merge distributed results and analyze
    python3 scripts/analyze.py --merge results/server*

    # Compare multiple models
    python3 scripts/analyze.py --compare results/local/model1 results/local/model2

    # Filter specific models
    python3 scripts/analyze.py results/local --models qwen3-4b deepseek-r1-7b
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


# ==================== DATA STRUCTURES ====================

@dataclass
class RQ1Result:
    """RQ1: Theory-Guided Generation Effectiveness

    Metrics:
    - Triple verification pass rate
    - Ground truth similarity (AST-based)
    - First-attempt success rate
    - Overall success rate
    - Vulnerability elimination rate
    """
    condition: str
    total_cases: int
    success_rate: float
    expected_success_rate: float
    triple_verification_rate: float
    ground_truth_similarity: float
    first_attempt_success_rate: float
    consistency_pass_rate: float
    verification_pass_rate: float
    vulnerability_elimination_rate: float

    # Additional detailed metrics
    ast_structural_similarity: float = 0.0
    ast_token_similarity: float = 0.0


@dataclass
class RQ2Result:
    """RQ2: Dual Verification Effectiveness

    Metrics:
    - Incomplete patches caught
    - Consistency violation breakdown
    - Verification agreement rate
    - Stage-wise precision/recall
    """
    verification_method: str
    incomplete_patches_caught: int
    total_patches: int
    detection_rate: float

    # Consistency checking breakdown
    consistency_violations: Dict[str, int]

    # Verification stage statistics
    verification_stage_stats: Dict[str, Dict[str, Any]]

    # Agreement metrics
    verification_agreement_rate: float = 0.0

    # Precision/recall (requires manual validation)
    precision: float = 0.0
    recall: float = 0.0


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
        if normalized_filter in normalized_model or normalized_model in normalized_filter:
            return True

    return False


def safe_mean(values: List[Optional[float]]) -> Optional[float]:
    """Calculate mean of non-None values"""
    filtered = [v for v in values if v is not None]
    return statistics.mean(filtered) if filtered else None


def safe_median(values: List[Optional[float]]) -> Optional[float]:
    """Calculate median of non-None values"""
    filtered = [v for v in values if v is not None]
    return statistics.median(filtered) if filtered else None


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

                result_files = list(search_dir.glob(f'{condition}_server*_results.json'))

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

    if verbose:
        print(f"\n✅ Merge complete: {output_dir}/")

    return output_dir


def recalculate_metrics(cases: List[Dict]) -> Dict:
    """Recalculate metrics from case list"""
    if not cases:
        return {}

    total = len(cases)
    successes = sum(1 for c in cases if c.get('actual_success', False))
    expected_successes = sum(1 for c in cases if c.get('expected_success', False))

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
    consistency_passes = sum(1 for c in cases
                            if c.get('consistency', {}).get('overall', False))
    consistency_count = sum(1 for c in cases if c.get('consistency') is not None)

    # Verification checks
    verification_passes = sum(1 for c in cases
                             if c.get('verification', {}).get('overall', False))
    verification_count = sum(1 for c in cases if c.get('verification') is not None)

    # Triple verification (all three stages pass)
    triple_verification_passes = 0
    for case in cases:
        verification = case.get('verification', {})
        if all(verification.get(stage, {}).get('success', False)
               for stage in ('symbolic', 'model_check', 'fuzzing')):
            triple_verification_passes += 1

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
        "expected_successes": float(expected_successes),
        "success_rate": successes / total if total else 0.0,
        "expected_success_rate": expected_successes / total if total else 0.0,
        "ground_truth_match_rate": ground_truth_matches / ground_truth_total if ground_truth_total else 0.0,
        "first_attempt_success_rate": first_attempt_successes / first_attempt_count if first_attempt_count else 0.0,
        "consistency_pass_rate": consistency_passes / consistency_count if consistency_count else 0.0,
        "verification_pass_rate": verification_passes / verification_count if verification_count else 0.0,
        "triple_verification_rate": triple_verification_passes / total if total else 0.0,
        "vulnerability_elimination_rate": vuln_eliminated / total if total else 0.0,
    }

    if ast_count > 0:
        metrics.update({
            "avg_ast_overall_similarity": ast_overall / ast_count,
            "avg_ast_structural_similarity": ast_structural / ast_count,
            "avg_ast_token_similarity": ast_token / ast_count,
        })

    return metrics


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
                expected_success_rate=0.0,
                triple_verification_rate=0.0,
                ground_truth_similarity=0.0,
                first_attempt_success_rate=0.0,
                consistency_pass_rate=0.0,
                verification_pass_rate=0.0,
                vulnerability_elimination_rate=0.0
            )

        # Use precomputed metrics if available
        result = RQ1Result(
            condition=self.condition,
            total_cases=total,
            success_rate=self.metrics.get('success_rate', 0.0),
            expected_success_rate=self.metrics.get('expected_success_rate', 0.0),
            triple_verification_rate=self.metrics.get('triple_verification_rate', 0.0),
            ground_truth_similarity=self.metrics.get('avg_ast_overall_similarity',
                                                     self.metrics.get('ground_truth_match_rate', 0.0)),
            first_attempt_success_rate=self.metrics.get('first_attempt_success_rate', 0.0),
            consistency_pass_rate=self.metrics.get('consistency_pass_rate', 0.0),
            verification_pass_rate=self.metrics.get('verification_pass_rate', 0.0),
            vulnerability_elimination_rate=self.metrics.get('vulnerability_elimination_rate', 0.0),
            ast_structural_similarity=self.metrics.get('avg_ast_structural_similarity', 0.0),
            ast_token_similarity=self.metrics.get('avg_ast_token_similarity', 0.0),
        )

        return result

    def analyze_rq2(self) -> RQ2Result:
        """
        RQ2: Dual Verification Effectiveness

        Research Question: How effective is the dual explanation approach
        (E_bug ↔ E_patch) with consistency checking at detecting incomplete patches?

        Metrics:
        1. Incomplete patches caught
        2. Consistency violation breakdown
        3. Verification agreement rate
        4. Stage-wise analysis
        """

        total = len(self.cases)

        # Consistency violation breakdown
        violation_counts = {
            'causal_coverage': 0,
            'intervention_validity': 0,
            'logical_consistency': 0,
            'completeness': 0
        }

        incomplete_caught = 0

        for case in self.cases:
            consistency = case.get('consistency', {})

            if consistency and not consistency.get('overall', True):
                incomplete_caught += 1

                # Count violation types
                for dimension in violation_counts.keys():
                    dim_result = consistency.get(dimension, {})
                    if isinstance(dim_result, dict):
                        if not dim_result.get('success', True):
                            violation_counts[dimension] += 1
                    elif dim_result is False:
                        violation_counts[dimension] += 1

        # Verification stage statistics
        stage_stats: Dict[str, Dict[str, Any]] = {
            stage: {'pass': 0, 'fail': 0, 'reasons': Counter()}
            for stage in ('symbolic', 'model_check', 'fuzzing')
        }

        for case in self.cases:
            verification = case.get('verification', {})

            for stage, stats in stage_stats.items():
                stage_result = verification.get(stage)
                if not stage_result:
                    continue

                if stage_result.get('success', False):
                    stats['pass'] += 1
                else:
                    stats['fail'] += 1
                    reason = self._categorize_failure(stage_result.get('details', ''))
                    stats['reasons'][reason] += 1

        # Calculate agreement rate (all three verification methods agree)
        agreement_count = 0
        for case in self.cases:
            verification = case.get('verification', {})
            consistency = case.get('consistency', {})

            if verification and consistency:
                symbolic_pass = verification.get('symbolic', {}).get('success', False)
                model_check_pass = verification.get('model_check', {}).get('success', False)
                consistency_pass = consistency.get('overall', False)

                # Agreement means all pass or all fail
                if (symbolic_pass == model_check_pass == consistency_pass):
                    agreement_count += 1

        verification_stage_stats = {
            stage: {
                'pass': stats['pass'],
                'fail': stats['fail'],
                'failure_reasons': dict(stats['reasons'])
            }
            for stage, stats in stage_stats.items()
        }

        result = RQ2Result(
            verification_method="Triple Verification (V4)",
            incomplete_patches_caught=incomplete_caught,
            total_patches=total,
            detection_rate=incomplete_caught / total if total else 0.0,
            consistency_violations=violation_counts,
            verification_stage_stats=verification_stage_stats,
            verification_agreement_rate=agreement_count / total if total else 0.0,
        )

        return result

    def _categorize_failure(self, details: str) -> str:
        """Categorize verification failure reason"""
        if not details:
            return 'unspecified'

        details_lower = details.lower()

        if 'compilation failed' in details_lower or 'compile error' in details_lower:
            return 'compile_error'
        if 'no guard' in details_lower or 'missing guard' in details_lower:
            return 'missing_causal_guard'
        if 'no fail-fast' in details_lower or 'missing fail-fast' in details_lower:
            return 'missing_fail_fast'
        if 'timeout' in details_lower:
            return 'timeout'
        if 'solver' in details_lower or 'unsat' in details_lower:
            return 'solver_failure'
        if 'path' in details_lower and 'not covered' in details_lower:
            return 'incomplete_coverage'

        return 'other'

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

        if verbose:
            print(f"\n✅ Analysis saved: {output_path}")

        # Generate markdown report
        md_path = output_path.with_suffix('.md')
        self._generate_markdown_report(report, md_path)

        if verbose:
            print(f"✅ Markdown report: {md_path}")

        return report

    def _print_rq1_results(self, rq1: RQ1Result):
        """Print RQ1 results"""
        print_section("RQ1: Theory-Guided Generation Effectiveness")
        print(f"\nCondition: {rq1.condition}")
        print(f"  Total cases: {rq1.total_cases}")
        print(f"  Success rate: {rq1.success_rate:.1%} (expected: {rq1.expected_success_rate:.1%})")
        print(f"  Triple verification rate: {rq1.triple_verification_rate:.1%}")
        print(f"  Ground truth similarity: {rq1.ground_truth_similarity:.1%}")
        print(f"  First attempt success: {rq1.first_attempt_success_rate:.1%}")
        print(f"  Consistency pass rate: {rq1.consistency_pass_rate:.1%}")
        print(f"  Verification pass rate: {rq1.verification_pass_rate:.1%}")
        print(f"  Vulnerability elimination: {rq1.vulnerability_elimination_rate:.1%}")

        if rq1.ast_structural_similarity > 0:
            print(f"\n  AST Similarity Details:")
            print(f"    Structural: {rq1.ast_structural_similarity:.1%}")
            print(f"    Token: {rq1.ast_token_similarity:.1%}")

    def _print_rq2_results(self, rq2: RQ2Result):
        """Print RQ2 results"""
        print_section("RQ2: Dual Verification Effectiveness")
        print(f"\nVerification Method: {rq2.verification_method}")
        print(f"  Incomplete patches caught: {rq2.incomplete_patches_caught}/{rq2.total_patches} ({rq2.detection_rate:.1%})")
        print(f"  Verification agreement rate: {rq2.verification_agreement_rate:.1%}")

        print(f"\n  Consistency Violation Breakdown:")
        for vtype, count in rq2.consistency_violations.items():
            if count > 0:
                print(f"    {vtype}: {count}")

        print(f"\n  Verification Stage Statistics:")
        for stage, stats in rq2.verification_stage_stats.items():
            total = stats['pass'] + stats['fail']
            pass_rate = stats['pass'] / total if total > 0 else 0.0
            print(f"    {stage}: {stats['pass']} pass / {stats['fail']} fail ({pass_rate:.1%})")

            if stats['failure_reasons']:
                reasons = ', '.join(f"{r}: {c}" for r, c in
                                  Counter(stats['failure_reasons']).most_common(3))
                print(f"      Top failures: {reasons}")

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
            "## RQ1: Theory-Guided Generation Effectiveness",
            "",
            "**Research Question:** Does pre-hoc formal bug specification (E_bug) lead to more accurate patches?",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Success Rate | {rq1.success_rate:.1%} |",
            f"| Expected Success Rate | {rq1.expected_success_rate:.1%} |",
            f"| Triple Verification Rate | {rq1.triple_verification_rate:.1%} |",
            f"| Ground Truth Similarity | {rq1.ground_truth_similarity:.1%} |",
            f"| First Attempt Success | {rq1.first_attempt_success_rate:.1%} |",
            f"| Consistency Pass Rate | {rq1.consistency_pass_rate:.1%} |",
            f"| Verification Pass Rate | {rq1.verification_pass_rate:.1%} |",
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

        lines.extend([
            "---",
            "",
            "## RQ2: Dual Verification Effectiveness",
            "",
            "**Research Question:** How effective is dual verification at detecting incomplete patches?",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Verification Method | {rq2.verification_method} |",
            f"| Incomplete Patches Caught | {rq2.incomplete_patches_caught}/{rq2.total_patches} ({rq2.detection_rate:.1%}) |",
            f"| Verification Agreement Rate | {rq2.verification_agreement_rate:.1%} |",
            "",
            "### Consistency Violation Breakdown",
            "",
        ])

        for vtype, count in rq2.consistency_violations.items():
            lines.append(f"- **{vtype}**: {count}")

        lines.extend([
            "",
            "### Verification Stage Statistics",
            "",
        ])

        for stage, stats in rq2.verification_stage_stats.items():
            total = stats['pass'] + stats['fail']
            pass_rate = stats['pass'] / total if total > 0 else 0.0
            lines.append(f"**{stage}**: {stats['pass']} pass / {stats['fail']} fail ({pass_rate:.1%})")

            if stats['failure_reasons']:
                lines.append("")
                for reason, count in Counter(stats['failure_reasons']).most_common():
                    lines.append(f"  - {reason}: {count}")
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

                if rq3.avg_phase1_time is not None:
                    lines.extend([
                        f"| Phase 1 (Formalization) | {rq3.avg_phase1_time:.2f}s |",
                        f"| Phase 2 (Generation) | {rq3.avg_phase2_time:.2f}s |",
                        f"| Phase 3 (Verification) | {rq3.avg_phase3_time:.2f}s |",
                    ])

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

            # Apply model filter
            if not should_include_model(model_name, model_filter):
                continue

            # Find C4 results (full PatchScribe)
            c4_file = model_dir / "c4_merged_results.json"
            if not c4_file.exists():
                c4_file = model_dir / "c4_results.json"
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
                    'verification_pass_rate': metrics.get('verification_pass_rate', 0),
                    'triple_verification_rate': metrics.get('triple_verification_rate', 0),
                    'first_attempt_success_rate': metrics.get('first_attempt_success_rate', 0),
                    'ground_truth_similarity': metrics.get('avg_ast_overall_similarity',
                                                          metrics.get('ground_truth_match_rate', 0)),
                    'total_cases': int(metrics.get('total_cases', 0)),
                }
            }

            # Collect other condition results (C1-C3)
            for condition in ['c1', 'c2', 'c3']:
                cond_file = model_dir / f"{condition}_merged_results.json"
                if not cond_file.exists():
                    cond_file = model_dir / f"{condition}_results.json"
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
        "| Model | Success Rate | Triple Verification | Consistency | First Attempt | GT Similarity | Cases |",
        "|-------|--------------|---------------------|-------------|---------------|---------------|-------|",
    ]

    # Sort by success rate
    sorted_models = sorted(all_results.items(),
                          key=lambda x: x[1]['metrics']['success_rate'],
                          reverse=True)

    for model_name, data in sorted_models:
        m = data['metrics']
        md_lines.append(
            f"| {model_name} | {m['success_rate']:.1%} | {m['triple_verification_rate']:.1%} | "
            f"{m['consistency_pass_rate']:.1%} | {m['first_attempt_success_rate']:.1%} | "
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
    best_first_attempt = max(all_results.items(),
                            key=lambda x: x[1]['metrics']['first_attempt_success_rate'])

    md_lines.extend([
        "",
        "---",
        "",
        "## Key Findings",
        "",
        f"- **Best Overall Model**: {best_model[0]} ({best_model[1]['metrics']['success_rate']:.1%} success rate)",
        f"- **Highest Consistency**: {best_consistency[0]} ({best_consistency[1]['metrics']['consistency_pass_rate']:.1%})",
        f"- **Best First Attempt**: {best_first_attempt[0]} ({best_first_attempt[1]['metrics']['first_attempt_success_rate']:.1%})",
        "",
    ])

    # Expected outcomes analysis (from paper)
    if has_conditions and len(sorted_models) > 0:
        avg_c1 = statistics.mean([d.get('c1_success_rate', 0) for d in all_results.values() if d.get('c1_success_rate', 0) > 0])
        avg_c3 = statistics.mean([d.get('c3_success_rate', 0) for d in all_results.values() if d.get('c3_success_rate', 0) > 0])
        avg_c4 = statistics.mean([d['metrics']['success_rate'] for d in all_results.values()])

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
        print(f"\n✅ Comparison report saved:")
        print(f"   JSON: {json_file}")
        print(f"   Markdown: {md_file}")

        # Console summary
        print("\n" + "=" * 80)
        print("MODEL PERFORMANCE SUMMARY")
        print("=" * 80)
        print(f"{'Model':<30} {'Success':<12} {'Triple Ver.':<12} {'Consistency':<12}")
        print("-" * 80)

        for model_name, data in sorted_models:
            m = data['metrics']
            print(f"{model_name:<30} {m['success_rate']:>10.1%}  "
                  f"{m['triple_verification_rate']:>10.1%}  "
                  f"{m['consistency_pass_rate']:>10.1%}")

        print("=" * 80)


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
        help='Minimal output mode'
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

    args = parser.parse_args()

    verbose = not args.quiet
    model_filter = args.models

    if verbose and model_filter:
        print(f"\n🔍 Model filter active: {', '.join(model_filter)}")

    try:
        # Merge mode
        if args.merge:
            server_dirs = [p for p in args.input_paths if p.is_dir()]

            if not server_dirs:
                print("❌ No server directories found")
                sys.exit(1)

            output_dir = args.output if args.output else Path('results/merged')

            merged_dir = merge_distributed_results(server_dirs, output_dir,
                                                  verbose, model_filter)

            # Auto-analyze merged results
            print_header("Analyzing Merged Results")

            for model_dir in merged_dir.iterdir():
                if not model_dir.is_dir() or model_dir.name.startswith('.'):
                    continue

                if not should_include_model(model_dir.name, model_filter):
                    continue

                c4_file = model_dir / "c4_merged_results.json"
                if c4_file.exists():
                    analyzer = RQAnalyzer(c4_file)
                    analyzer.generate_comprehensive_report(verbose=verbose)

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

            for input_path in args.input_paths:
                # Direct JSON file
                if input_path.is_file() and input_path.suffix == '.json':
                    model_name = input_path.parent.name
                    if should_include_model(model_name, model_filter):
                        analyzer = RQAnalyzer(input_path)
                        analyzer.generate_comprehensive_report(verbose=verbose)
                        results_analyzed += 1
                    elif verbose and model_filter:
                        print(f"⏭️  Skipping {model_name} (filtered out)")

                # Directory - find result files
                elif input_path.is_dir():
                    # Determine which conditions to analyze
                    if args.all_conditions:
                        conditions = ['c1', 'c2', 'c3', 'c4']
                    else:
                        conditions = ['c4']  # Only full PatchScribe by default

                    # Find result files
                    result_files = []
                    for condition in conditions:
                        result_files.extend(input_path.glob(f"**/{condition}_*results.json"))

                    if not result_files:
                        if verbose:
                            cond_str = "C1-C4" if args.all_conditions else "C4"
                            print(f"⚠️  No {cond_str} result files found in {input_path}")
                        continue

                    # Group by model and analyze
                    models_analyzed = set()
                    for result_file in sorted(result_files):
                        model_name = result_file.parent.name

                        # Apply model filter
                        if not should_include_model(model_name, model_filter):
                            if verbose and model_filter and model_name not in models_analyzed:
                                print(f"⏭️  Skipping {model_name} (filtered out)")
                            continue

                        if verbose:
                            condition = result_file.stem.split('_')[0]
                            print(f"\n📊 Analyzing {model_name} - {condition.upper()}")

                        analyzer = RQAnalyzer(result_file)
                        analyzer.generate_comprehensive_report(verbose=verbose)
                        results_analyzed += 1
                        models_analyzed.add(model_name)

                    # Auto-generate comparison if multiple models analyzed
                    if len(models_analyzed) > 1:
                        comparison_dir = input_path / "comparison"
                        generate_comparison_report([input_path], comparison_dir,
                                                  verbose, model_filter)

            if results_analyzed == 0:
                print("❌ No results found to analyze")
                sys.exit(1)

            if verbose:
                print_header("Analysis Complete")
                print(f"\n✅ Analyzed {results_analyzed} result file(s)\n")

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
