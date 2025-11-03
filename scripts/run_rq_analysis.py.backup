#!/usr/bin/env python3
"""
RQ Analysis Script for PatchScribe
Analyzes results from evaluation runs and produces comprehensive RQ-specific reports.
"""
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
import statistics

# Add patchscribe to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from patchscribe.performance import categorize_complexity, measure_code_complexity


@dataclass
class RQ1Result:
    """Results for RQ1: Theory-Guided Generation Effectiveness"""
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
    
    def as_dict(self) -> Dict:
        return {
            'condition': self.condition,
            'total_cases': self.total_cases,
            'success_rate': self.success_rate,
            'expected_success_rate': self.expected_success_rate,
            'triple_verification_rate': self.triple_verification_rate,
            'ground_truth_similarity': self.ground_truth_similarity,
            'first_attempt_success_rate': self.first_attempt_success_rate,
            'consistency_pass_rate': self.consistency_pass_rate,
            'verification_pass_rate': self.verification_pass_rate,
            'vulnerability_elimination_rate': self.vulnerability_elimination_rate
        }


@dataclass
class RQ2Result:
    """Results for RQ2: Dual Verification Effectiveness"""
    verification_method: str
    incomplete_patches_caught: int
    precision: float
    recall: float
    consistency_violations: Dict[str, int]
    verification_stage_stats: Dict[str, Dict[str, Any]]
    
    def as_dict(self) -> Dict:
        return {
            'verification_method': self.verification_method,
            'incomplete_patches_caught': self.incomplete_patches_caught,
            'precision': self.precision,
            'recall': self.recall,
            'consistency_violations': self.consistency_violations,
            'verification_stage_stats': self.verification_stage_stats
        }


@dataclass
class RQ3Result:
    """Results for RQ3: Scalability and Performance"""
    complexity_level: str
    case_count: int
    avg_iterations: float
    avg_phase1_time: Optional[float] = None
    avg_phase2_time: Optional[float] = None
    avg_phase3_time: Optional[float] = None
    avg_total_time: Optional[float] = None
    peak_memory_mb: Optional[float] = None
    avg_loc: Optional[float] = None
    
    def as_dict(self) -> Dict:
        return {
            'complexity_level': self.complexity_level,
            'avg_phase1_time': self.avg_phase1_time,
            'avg_phase2_time': self.avg_phase2_time,
            'avg_phase3_time': self.avg_phase3_time,
            'avg_total_time': self.avg_total_time,
            'avg_iterations': self.avg_iterations,
            'peak_memory_mb': self.peak_memory_mb,
            'case_count': self.case_count,
            'avg_loc': self.avg_loc
        }


@dataclass
class RQ4Result:
    """Results for RQ4: Explanation Quality"""
    explanation_type: str
    checklist_coverage: float
    avg_accuracy_score: float
    avg_clarity_score: float
    avg_causality_score: float
    missing_item_frequency: Dict[str, int]
    
    def as_dict(self) -> Dict:
        return {
            'explanation_type': self.explanation_type,
            'checklist_coverage': self.checklist_coverage,
            'avg_accuracy_score': self.avg_accuracy_score,
            'avg_clarity_score': self.avg_clarity_score,
            'avg_causality_score': self.avg_causality_score,
            'missing_item_frequency': self.missing_item_frequency
        }


class RQAnalyzer:
    """Analyzer for Research Questions"""
    
    def __init__(self, results_path: Path):
        self.results_path = results_path
        with open(results_path, 'r') as f:
            self.data = json.load(f)
        self.cases = self.data.get('cases', [])
        self.metrics = self.data.get('metrics', {})
        
        stem = self.results_path.stem
        if stem.endswith('_results'):
            stem = stem[:-len('_results')]
        self.condition_key = stem
        self.condition_label = self._resolve_condition_label(stem)
        
        self.dataset_dirs = [
            d for d in (self.results_path.parents[2] / 'datasets').glob('*')
            if d.is_dir()
        ] if len(self.results_path.parents) >= 3 and (self.results_path.parents[2] / 'datasets').exists() else [
            d for d in Path('datasets').glob('*') if d.is_dir()
        ]
        self._case_source_cache: Dict[str, Optional[Path]] = {}
    
    @staticmethod
    def _resolve_condition_label(condition_key: str) -> str:
        """Return a human-readable label for the condition key."""
        mapping = {
            'baseline_c1': 'C1 Baseline (post-hoc, no formal guidance)',
            'vague_hints_c2': 'C2 Vague Hints (informal prompts)',
            'prehoc_c3': 'C3 Pre-hoc Guidance (formal spec, no verification)',
            'full_patchscribe_c4': 'C4 Full PatchScribe (formal spec + triple verification)',
        }
        return mapping.get(condition_key, condition_key or 'Unknown')
    
    @staticmethod
    def _is_triple_verification_pass(case: Dict[str, Any]) -> bool:
        """Determine whether triple verification succeeded for the case."""
        verification = case.get('verification', {})
        return all(
            verification.get(stage, {}).get('success', False)
            for stage in ('symbolic', 'model_check', 'fuzzing')
        )
    
    @staticmethod
    def _categorize_stage_failure(details: Optional[str]) -> str:
        """Categorize a verification failure message into a coarse bucket."""
        if not details:
            return 'unspecified'
        
        details_lower = details.lower()
        if 'compilation failed' in details_lower or 'expected' in details_lower and 'error' in details_lower:
            return 'compile_error'
        if 'no guard' in details_lower:
            return 'missing_causal_guard'
        if 'no fail-fast' in details_lower:
            return 'missing_fail_fast'
        if 'timeout' in details_lower:
            return 'timeout'
        if 'solver' in details_lower or 'unsat' in details_lower:
            return 'solver_failure'
        return 'other'
    
    def _find_case_source(self, case_id: str) -> Optional[Path]:
        """Locate the source file for a case across known dataset directories."""
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
        """Measure LOC and complexity category for a case if source is available."""
        case_id = case.get('case_id')
        if not case_id:
            return None
        
        source_path = self._find_case_source(case_id)
        if not source_path:
            return None
        
        if source_path.is_dir():
            # Prefer vulnerable file if present, fall back to first source file
            candidates = [
                source_path / name for name in ('vul.c', 'vul.cpp', 'vulnerable.c', 'buggy.c')
            ]
            candidates += sorted(source_path.glob('*.c')) + sorted(source_path.glob('*.cpp'))
            code_path = next((cand for cand in candidates if cand.exists()), None)
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
    
    def analyze_rq1(self) -> List[RQ1Result]:
        """
        RQ1: Theory-Guided Generation Effectiveness
        
        Compares different conditions:
        - C1 (baseline): Raw LLM with no formal guidance
        - C2 (vague hints): Informal prompts
        - C3 (pre-hoc): E_bug specification without verification
        - C4 (full PatchScribe): E_bug + triple verification
        """
        print("\n" + "="*80)
        print("RQ1: Theory-Guided Generation Effectiveness")
        print("="*80)
        
        total_cases = len(self.cases)
        if total_cases == 0:
            print("No cases found in results file.")
            return []
        
        success_count = sum(1 for case in self.cases if case.get('actual_success', False))
        expected_success_count = sum(1 for case in self.cases if case.get('expected_success', False))
        triple_pass_count = sum(1 for case in self.cases if self._is_triple_verification_pass(case))
        consistency_pass_count = sum(
            1 for case in self.cases
            if case.get('consistency', {}).get('overall', False)
        )
        verification_pass_count = sum(
            1 for case in self.cases
            if case.get('verification', {}).get('overall', False)
        )
        ground_truth_matches = sum(
            1 for case in self.cases
            if case.get('patch', {}).get('matches_ground_truth', False)
        )
        first_attempt_successes = sum(
            1 for case in self.cases
            if case.get('first_attempt_success', False)
        )
        vulnerability_eliminated = sum(
            1 for case in self.cases
            if case.get('effect', {}).get('vulnerability_removed', False)
        )
        
        result = RQ1Result(
            condition=self.condition_label,
            total_cases=total_cases,
            success_rate=success_count / total_cases,
            expected_success_rate=expected_success_count / total_cases,
            triple_verification_rate=triple_pass_count / total_cases,
            ground_truth_similarity=ground_truth_matches / total_cases,
            first_attempt_success_rate=first_attempt_successes / total_cases,
            consistency_pass_rate=consistency_pass_count / total_cases,
            verification_pass_rate=verification_pass_count / total_cases,
            vulnerability_elimination_rate=vulnerability_eliminated / total_cases
        )
        
        print(f"\nCondition: {result.condition}")
        print(f"  Total cases: {result.total_cases}")
        print(f"  Success rate: {result.success_rate:.1%} (expected {result.expected_success_rate:.1%})")
        print(f"  Triple verification rate: {result.triple_verification_rate:.1%}")
        print(f"  Consistency pass rate: {result.consistency_pass_rate:.1%}")
        print(f"  Verification (all stages) pass rate: {result.verification_pass_rate:.1%}")
        print(f"  Ground truth match rate: {result.ground_truth_similarity:.1%}")
        print(f"  First attempt success rate: {result.first_attempt_success_rate:.1%}")
        print(f"  Vulnerability elimination rate: {result.vulnerability_elimination_rate:.1%}")
        
        return [result]
    
    def analyze_rq2(self) -> List[RQ2Result]:
        """
        RQ2: Dual Verification Effectiveness
        
        Measures effectiveness of different verification methods:
        - V1: Exploit-only testing
        - V2: Symbolic execution only
        - V3: Consistency checking only
        - V4: Triple verification (consistency + symbolic + completeness)
        """
        print("\n" + "="*80)
        print("RQ2: Dual Verification Effectiveness")
        print("="*80)
        
        total_cases = len(self.cases)
        if total_cases == 0:
            print("No cases found for RQ2 analysis.")
            return []
        
        violation_pass_fail = {
            'causal_coverage': {'pass': 0, 'fail': 0},
            'intervention_validity': {'pass': 0, 'fail': 0},
            'logical_consistency': {'pass': 0, 'fail': 0},
            'completeness': {'pass': 0, 'fail': 0}
        }
        stage_stats: Dict[str, Dict[str, Any]] = {
            stage: {'pass': 0, 'fail': 0, 'reasons': Counter()}
            for stage in ('symbolic', 'model_check', 'fuzzing')
        }
        incomplete_patches = []
        
        for case in self.cases:
            consistency = case.get('consistency', {})
            verification = case.get('verification', {})
            
            if consistency and not consistency.get('overall', True):
                incomplete_patches.append(case)
            
            for dimension, counts in violation_pass_fail.items():
                outcome = consistency.get(dimension, {})
                if outcome.get('success', False):
                    counts['pass'] += 1
                elif outcome:
                    counts['fail'] += 1
            
            for stage, stats in stage_stats.items():
                stage_result = verification.get(stage)
                if not stage_result:
                    continue
                
                if stage_result.get('success', False):
                    stats['pass'] += 1
                else:
                    stats['fail'] += 1
                    reason = self._categorize_stage_failure(stage_result.get('details'))
                    stats['reasons'][reason] += 1
        
        incomplete_caught = len(incomplete_patches)
        
        print(f"\nIncomplete patches flagged by consistency checker: "
              f"{incomplete_caught}/{total_cases} ({incomplete_caught/total_cases:.1%})")
        print("\nConsistency sub-check outcomes:")
        for dimension, counts in violation_pass_fail.items():
            print(f"  {dimension}: {counts['fail']} fail / {counts['pass']} pass")
        
        print("\nVerification stage outcomes:")
        for stage, stats in stage_stats.items():
            total_stage = stats['pass'] + stats['fail']
            pass_rate = stats['pass'] / total_stage if total_stage else 0.0
            print(f"  {stage}: {stats['pass']} pass / {stats['fail']} fail "
                  f"({pass_rate:.1%} success)")
            if stats['reasons']:
                reason_summary = ', '.join(
                    f"{reason}: {count}" for reason, count in stats['reasons'].most_common()
                )
                print(f"    Failure reasons: {reason_summary}")
        
        consistency_violation_counts = {
            dimension: counts['fail']
            for dimension, counts in violation_pass_fail.items()
        }
        
        result = RQ2Result(
            verification_method="Triple Verification (V4)",
            incomplete_patches_caught=incomplete_caught,
            precision=0.0,  # Would be calculated from manual review
            recall=0.0,     # Would be calculated from manual review
            consistency_violations=consistency_violation_counts,
            verification_stage_stats={
                stage: {
                    'pass': stats['pass'],
                    'fail': stats['fail'],
                    'failure_reasons': dict(stats['reasons'])
                }
                for stage, stats in stage_stats.items()
            }
        )
        
        print(f"\nTriple verification effectiveness:")
        print(f"  Method: {result.verification_method}")
        print(f"  Patches caught: {result.incomplete_patches_caught}")
        print(f"  Note: Precision/Recall require manual validation of incomplete patches")
        
        return [result]
    
    def analyze_rq3(self) -> List[RQ3Result]:
        """
        RQ3: Scalability and Performance
        
        Measures time overhead by complexity:
        - Simple: <50 LoC
        - Medium: 50-100 LoC
        - Complex: >100 LoC
        """
        print("\n" + "="*80)
        print("RQ3: Scalability and Performance")
        print("="*80)
        
        if not self.cases:
            print("No cases available for RQ3 analysis.")
            return []
        
        complexity_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        unknown_cases = 0
        
        for case in self.cases:
            perf = case.get('performance') or {}
            complexity_info = perf.get('code_complexity')
            if not complexity_info:
                complexity_info = self._extract_complexity_metrics(case)
            iteration_count = perf.get('iteration_count')
            if iteration_count is None:
                iteration_count = len(case.get('iterations', []))
            phase_breakdown = perf.get('phase_breakdown', {}) if perf else {}
            
            record = {
                'iteration_count': iteration_count,
                'phase1_time': phase_breakdown.get('phase1_formalization'),
                'phase2_time': phase_breakdown.get('phase2_generation'),
                'phase3_time': phase_breakdown.get('phase3_verification'),
                'total_time': perf.get('total_time_seconds') if perf else None,
                'peak_memory': perf.get('peak_memory_mb') if perf else None,
                'phase_memory': perf.get('phase_memory_mb') if perf else None,
                'loc': None
            }
            
            if complexity_info:
                record['loc'] = complexity_info.get('lines_of_code') or complexity_info.get('loc')
                bucket = (
                    complexity_info.get('complexity_bucket')
                    or complexity_info.get('bucket')
                    or complexity_info.get('category')
                    or 'unknown'
                )
            else:
                bucket = 'unknown'

            if bucket == 'unknown' and record['loc'] is not None:
                bucket = categorize_complexity(int(record['loc']))
            
            complexity_groups[bucket].append(record)
            if bucket == 'unknown':
                unknown_cases += 1
        
        results: List[RQ3Result] = []
        for complexity, entries in sorted(complexity_groups.items()):
            if not entries:
                continue
            
            def safe_mean(values: List[Optional[float]]) -> Optional[float]:
                filtered = [v for v in values if v is not None]
                return statistics.mean(filtered) if filtered else None
            
            avg_iterations = safe_mean([entry['iteration_count'] for entry in entries]) or 0.0
            avg_phase1 = safe_mean([entry['phase1_time'] for entry in entries])
            avg_phase2 = safe_mean([entry['phase2_time'] for entry in entries])
            avg_phase3 = safe_mean([entry['phase3_time'] for entry in entries])
            avg_total = safe_mean([entry['total_time'] for entry in entries])
            avg_memory = safe_mean([entry['peak_memory'] for entry in entries])
            avg_loc = safe_mean([entry['loc'] for entry in entries])
            
            result = RQ3Result(
                complexity_level=complexity,
                case_count=len(entries),
                avg_iterations=avg_iterations,
                avg_phase1_time=avg_phase1,
                avg_phase2_time=avg_phase2,
                avg_phase3_time=avg_phase3,
                avg_total_time=avg_total,
                peak_memory_mb=avg_memory,
                avg_loc=avg_loc
            )
            results.append(result)
            
            print(f"\nComplexity bucket: {complexity}")
            print(f"  Cases: {result.case_count}")
            print(f"  Avg iterations: {result.avg_iterations:.1f}")
            if result.avg_loc is not None:
                print(f"  Avg LOC: {result.avg_loc:.1f}")
            if result.avg_total_time is not None:
                print(f"  Avg total time: {result.avg_total_time:.2f}s")
            else:
                print("  Avg total time: N/A (performance metrics not captured)")
            
        if unknown_cases:
            print(f"\n⚠️  Source files not found for {unknown_cases} case(s); "
                  "classified under 'unknown' complexity.")
        
        return results
    
    def analyze_rq4(self) -> List[RQ4Result]:
        """
        RQ4: Explanation Quality and Developer Trust
        
        Measures quality of explanations:
        - Checklist-based coverage
        - Expert quality scores (accuracy, clarity, causality)
        """
        print("\n" + "="*80)
        print("RQ4: Explanation Quality and Developer Trust")
        print("="*80)
        
        # Analyze explanation metrics
        checklist_coverages = []
        accuracy_scores = []
        clarity_scores = []
        causality_scores = []
        missing_counter: Counter[str] = Counter()
        
        for case in self.cases:
            metrics = case.get('explanation_metrics', {})
            
            coverage = metrics.get('checklist_coverage')
            if coverage is not None:
                checklist_coverages.append(coverage)
            
            llm_scores = metrics.get('llm_scores', {})
            if llm_scores:
                if 'accuracy' in llm_scores:
                    accuracy_scores.append(llm_scores['accuracy'])
                if 'clarity' in llm_scores:
                    clarity_scores.append(llm_scores['clarity'])
                if 'causality' in llm_scores:
                    causality_scores.append(llm_scores['causality'])
            
            missing_items = metrics.get('missing_items')
            if missing_items:
                missing_counter.update(missing_items)
        
        result = RQ4Result(
            explanation_type="Dual Explanations (E_bug + E_patch)",
            checklist_coverage=statistics.mean(checklist_coverages) if checklist_coverages else 0,
            avg_accuracy_score=statistics.mean(accuracy_scores) if accuracy_scores else 0,
            avg_clarity_score=statistics.mean(clarity_scores) if clarity_scores else 0,
            avg_causality_score=statistics.mean(causality_scores) if causality_scores else 0,
            missing_item_frequency=dict(missing_counter)
        )
        
        print(f"\nExplanation type: {result.explanation_type}")
        print(f"  Avg checklist coverage: {result.checklist_coverage:.1%}")
        if result.avg_accuracy_score > 0:
            print(f"  Avg accuracy score: {result.avg_accuracy_score:.2f}/5")
            print(f"  Avg clarity score: {result.avg_clarity_score:.2f}/5")
            print(f"  Avg causality score: {result.avg_causality_score:.2f}/5")
        else:
            print(f"  Note: LLM quality scores not available (requires manual evaluation)")
        if result.missing_item_frequency:
            missing_summary = ', '.join(
                f"{item}: {count}" for item, count in Counter(result.missing_item_frequency).most_common()
            )
            print(f"  Frequent missing checklist items: {missing_summary}")
        
        return [result]
    
    def generate_comprehensive_report(self, output_path: Path):
        """Generate comprehensive RQ analysis report"""
        print("\n" + "="*80)
        print("GENERATING COMPREHENSIVE RQ ANALYSIS REPORT")
        print("="*80)
        
        rq1_results = self.analyze_rq1()
        rq2_results = self.analyze_rq2()
        rq3_results = self.analyze_rq3()
        rq4_results = self.analyze_rq4()
        
        # Compile full report
        report = {
            'rq1_theory_guided_generation': [r.as_dict() for r in rq1_results],
            'rq2_dual_verification': [r.as_dict() for r in rq2_results],
            'rq3_scalability_performance': [r.as_dict() for r in rq3_results],
            'rq4_explanation_quality': [r.as_dict() for r in rq4_results],
            'overall_metrics': self.metrics
        }
        
        # Save report
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n✅ Comprehensive RQ analysis saved to: {output_path}")
        
        # Generate markdown summary
        md_path = output_path.with_suffix('.md')
        self._generate_markdown_report(report, md_path)
        print(f"✅ Markdown summary saved to: {md_path}")
        
        return report
    
    def _generate_markdown_report(self, report: Dict, output_path: Path):
        """Generate human-readable markdown report"""
        lines = [
            "# PatchScribe RQ Analysis Report",
            "",
            f"Generated from: {self.results_path.name}",
            f"Total cases analyzed: {len(self.cases)}",
            "",
            "## RQ1: Theory-Guided Generation Effectiveness",
            "",
            "**Research Question**: Does pre-hoc formal bug specification (E_bug) lead to more accurate patches?",
            ""
        ]
        
        for result in report['rq1_theory_guided_generation']:
            lines.extend([
                f"### Condition: {result['condition']}",
                f"- Total cases: {result['total_cases']}",
                f"- Success rate: {result['success_rate']:.1%}",
                f"- Expected success rate: {result['expected_success_rate']:.1%}",
                f"- Triple verification rate: {result['triple_verification_rate']:.1%}",
                f"- Consistency pass rate: {result['consistency_pass_rate']:.1%}",
                f"- Verification success rate: {result['verification_pass_rate']:.1%}",
                f"- Ground truth match rate: {result['ground_truth_similarity']:.1%}",
                f"- First attempt success rate: {result['first_attempt_success_rate']:.1%}",
                f"- Vulnerability elimination rate: {result['vulnerability_elimination_rate']:.1%}",
                ""
            ])
        
        lines.extend([
            "## RQ2: Dual Verification Effectiveness",
            "",
            "**Research Question**: How effective is consistency checking at detecting incomplete patches?",
            ""
        ])
        
        for result in report['rq2_dual_verification']:
            lines.extend([
                f"### {result['verification_method']}",
                f"- Incomplete patches caught: {result['incomplete_patches_caught']}",
                "",
                "**Consistency violation breakdown:**",
            ])
            for vtype, count in result['consistency_violations'].items():
                lines.append(f"- {vtype}: {count} cases")
            stage_stats = result.get('verification_stage_stats', {})
            if stage_stats:
                lines.append("")
                lines.append("**Verification stage outcomes:**")
                for stage, stats in stage_stats.items():
                    lines.append(f"- {stage}: {stats['pass']} pass / {stats['fail']} fail")
                    reasons = stats.get('failure_reasons', {})
                    if reasons:
                        reason_summary = ', '.join(
                            f"{reason} ({count})"
                            for reason, count in Counter(reasons).most_common()
                        )
                        lines.append(f"  - Failure reasons: {reason_summary}")
            lines.append("")
        
        lines.extend([
            "## RQ3: Scalability and Performance",
            "",
            "**Research Question**: What is the time overhead of the three-phase workflow?",
            ""
        ])
        
        for result in report['rq3_scalability_performance']:
            entries = [
                f"### Complexity: {result['complexity_level']}",
                f"- Cases: {result['case_count']}",
                f"- Avg Iterations: {result['avg_iterations']:.1f}",
            ]
            if result.get('avg_loc') is not None:
                entries.append(f"- Avg LOC: {result['avg_loc']:.1f}")
            for label, key, unit in [
                ("Avg Phase 1 (Formalization)", 'avg_phase1_time', 's'),
                ("Avg Phase 2 (Generation)", 'avg_phase2_time', 's'),
                ("Avg Phase 3 (Verification)", 'avg_phase3_time', 's'),
                ("**Avg Total Time**", 'avg_total_time', 's'),
                ("Peak Memory", 'peak_memory_mb', 'MB')
            ]:
                value = result.get(key)
                if value is None:
                    entries.append(f"- {label}: N/A")
                else:
                    entries.append(f"- {label}: {value:.2f}{unit}")
            entries.append("")
            lines.extend(entries)
        
        lines.extend([
            "## RQ4: Explanation Quality",
            "",
            "**Research Question**: Do dual explanations provide useful insights to developers?",
            ""
        ])
        
        for result in report['rq4_explanation_quality']:
            lines.extend([
                f"### {result['explanation_type']}",
                f"- Checklist coverage: {result['checklist_coverage']:.1%}",
            ])
            if result['avg_accuracy_score'] > 0:
                lines.extend([
                    f"- Accuracy score: {result['avg_accuracy_score']:.2f}/5",
                    f"- Clarity score: {result['avg_clarity_score']:.2f}/5",
                    f"- Causality score: {result['avg_causality_score']:.2f}/5",
                ])
            missing_items = result.get('missing_item_frequency', {})
            if missing_items:
                missing_summary = ', '.join(
                    f"{item} ({count})"
                    for item, count in Counter(missing_items).most_common()
                )
                lines.append(f"- Frequent missing checklist items: {missing_summary}")
            lines.append("")
        
        lines.extend([
            "## Overall Metrics",
            ""
        ])
        
        for key, value in report['overall_metrics'].items():
            if isinstance(value, float):
                lines.append(f"- {key}: {value:.4f}")
            else:
                lines.append(f"- {key}: {value}")
        
        # Write to file
        output_path.write_text('\n'.join(lines))


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze PatchScribe evaluation results for RQ analysis')
    parser.add_argument('results_file', type=Path, help='Path to evaluation results JSON file')
    parser.add_argument('-o', '--output', type=Path, default=None, 
                       help='Output path for RQ analysis report (default: results/rq_analysis.json)')
    
    args = parser.parse_args()
    
    if not args.results_file.exists():
        print(f"❌ Error: Results file not found: {args.results_file}")
        sys.exit(1)
    
    output_path = args.output or Path('results') / 'rq_analysis.json'
    
    analyzer = RQAnalyzer(args.results_file)
    report = analyzer.generate_comprehensive_report(output_path)
    
    print("\n" + "="*80)
    print("✅ RQ ANALYSIS COMPLETE")
    print("="*80)


if __name__ == '__main__':
    main()
