#!/usr/bin/env python3
"""
RQ Analysis Script for PatchScribe
Analyzes results from evaluation runs and produces comprehensive RQ-specific reports.
"""
import json
import sys
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass
import statistics

# Add patchscribe to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@dataclass
class RQ1Result:
    """Results for RQ1: Theory-Guided Generation Effectiveness"""
    condition: str
    triple_verification_rate: float
    ground_truth_similarity: float
    first_attempt_success_rate: float
    total_cases: int
    
    def as_dict(self) -> Dict:
        return {
            'condition': self.condition,
            'triple_verification_rate': self.triple_verification_rate,
            'ground_truth_similarity': self.ground_truth_similarity,
            'first_attempt_success_rate': self.first_attempt_success_rate,
            'total_cases': self.total_cases
        }


@dataclass
class RQ2Result:
    """Results for RQ2: Dual Verification Effectiveness"""
    verification_method: str
    incomplete_patches_caught: int
    precision: float
    recall: float
    consistency_violations: Dict[str, int]
    
    def as_dict(self) -> Dict:
        return {
            'verification_method': self.verification_method,
            'incomplete_patches_caught': self.incomplete_patches_caught,
            'precision': self.precision,
            'recall': self.recall,
            'consistency_violations': self.consistency_violations
        }


@dataclass
class RQ3Result:
    """Results for RQ3: Scalability and Performance"""
    complexity_level: str
    avg_phase1_time: float
    avg_phase2_time: float
    avg_phase3_time: float
    avg_total_time: float
    avg_iterations: float
    peak_memory_mb: float
    case_count: int
    
    def as_dict(self) -> Dict:
        return {
            'complexity_level': self.complexity_level,
            'avg_phase1_time': self.avg_phase1_time,
            'avg_phase2_time': self.avg_phase2_time,
            'avg_phase3_time': self.avg_phase3_time,
            'avg_total_time': self.avg_total_time,
            'avg_iterations': self.avg_iterations,
            'peak_memory_mb': self.peak_memory_mb,
            'case_count': self.case_count
        }


@dataclass
class RQ4Result:
    """Results for RQ4: Explanation Quality"""
    explanation_type: str
    checklist_coverage: float
    avg_accuracy_score: float
    avg_clarity_score: float
    avg_causality_score: float
    
    def as_dict(self) -> Dict:
        return {
            'explanation_type': self.explanation_type,
            'checklist_coverage': self.checklist_coverage,
            'avg_accuracy_score': self.avg_accuracy_score,
            'avg_clarity_score': self.avg_clarity_score,
            'avg_causality_score': self.avg_causality_score
        }


class RQAnalyzer:
    """Analyzer for Research Questions"""
    
    def __init__(self, results_path: Path):
        self.results_path = results_path
        with open(results_path, 'r') as f:
            self.data = json.load(f)
        self.cases = self.data.get('cases', [])
        self.metrics = self.data.get('metrics', {})
    
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
        
        # Group cases by strategy/condition
        conditions = {}
        for case in self.cases:
            # Infer condition from case metadata or iterations
            # For now, we'll use a simplified approach
            strategy = case.get('strategy', 'unknown')
            if strategy not in conditions:
                conditions[strategy] = []
            conditions[strategy].append(case)
        
        results = []
        for condition_name, condition_cases in conditions.items():
            if not condition_cases:
                continue
            
            # Calculate metrics
            triple_verif_count = sum(
                1 for c in condition_cases 
                if c.get('actual_success', False) 
                and c.get('consistency', {}).get('overall', False)
            )
            triple_verif_rate = triple_verif_count / len(condition_cases) if condition_cases else 0.0
            
            ground_truth_matches = sum(
                1 for c in condition_cases
                if c.get('patch', {}).get('matches_ground_truth', False)
            )
            gt_similarity = ground_truth_matches / len(condition_cases) if condition_cases else 0.0
            
            first_attempt_successes = sum(
                1 for c in condition_cases
                if c.get('first_attempt_success', False)
            )
            first_attempt_rate = first_attempt_successes / len(condition_cases) if condition_cases else 0.0
            
            result = RQ1Result(
                condition=condition_name,
                triple_verification_rate=triple_verif_rate,
                ground_truth_similarity=gt_similarity,
                first_attempt_success_rate=first_attempt_rate,
                total_cases=len(condition_cases)
            )
            results.append(result)
            
            print(f"\nCondition: {condition_name}")
            print(f"  Total cases: {result.total_cases}")
            print(f"  Triple verification rate: {result.triple_verification_rate:.1%}")
            print(f"  Ground truth similarity: {result.ground_truth_similarity:.1%}")
            print(f"  First attempt success rate: {result.first_attempt_success_rate:.1%}")
        
        # Calculate improvement
        if len(results) > 1:
            baseline_rate = min(r.triple_verification_rate for r in results)
            best_rate = max(r.triple_verification_rate for r in results)
            improvement = ((best_rate - baseline_rate) / baseline_rate * 100) if baseline_rate > 0 else 0
            print(f"\n  Improvement over baseline: {improvement:.1f}%")
        
        return results
    
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
        
        # Analyze consistency violations
        violation_types = {
            'causal_coverage': 0,
            'intervention_validity': 0,
            'logical_consistency': 0,
            'completeness': 0
        }
        
        incomplete_patches = []
        for case in self.cases:
            consistency = case.get('consistency')
            if consistency and not consistency.get('overall', True):
                incomplete_patches.append(case)
                
                # Count violation types
                if not consistency.get('causal_coverage', {}).get('success', True):
                    violation_types['causal_coverage'] += 1
                if not consistency.get('intervention_validity', {}).get('success', True):
                    violation_types['intervention_validity'] += 1
                if not consistency.get('logical_consistency', {}).get('success', True):
                    violation_types['logical_consistency'] += 1
                if not consistency.get('completeness', {}).get('success', True):
                    violation_types['completeness'] += 1
        
        # Calculate metrics
        total_cases = len(self.cases)
        incomplete_caught = len(incomplete_patches)
        
        # For precision/recall, we need ground truth about incomplete patches
        # In real evaluation, this would come from manual review or variant exploits
        # For now, we'll report what we caught
        
        print(f"\nIncomplete patches detected: {incomplete_caught}/{total_cases} ({incomplete_caught/total_cases:.1%})")
        print(f"\nConsistency violation breakdown:")
        for vtype, count in violation_types.items():
            print(f"  {vtype}: {count} cases")
        
        # Create result for triple verification
        result = RQ2Result(
            verification_method="Triple Verification (V4)",
            incomplete_patches_caught=incomplete_caught,
            precision=0.0,  # Would be calculated from manual review
            recall=0.0,     # Would be calculated from manual review
            consistency_violations=violation_types
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
        
        # Group cases by complexity
        complexity_groups = {
            'simple': [],
            'medium': [],
            'complex': []
        }
        
        for case in self.cases:
            # Try to infer complexity from case data
            # This would typically come from code analysis
            case_id = case.get('case_id', '')
            
            # For now, categorize based on available performance data
            perf = case.get('performance')
            if not perf:
                continue
            
            # Estimate complexity from total time (rough heuristic)
            total_time = perf.get('total_time_seconds', 0)
            if total_time < 120:  # < 2 min
                complexity_groups['simple'].append(case)
            elif total_time < 180:  # 2-3 min
                complexity_groups['medium'].append(case)
            else:
                complexity_groups['complex'].append(case)
        
        results = []
        for complexity, cases in complexity_groups.items():
            if not cases:
                continue
            
            # Extract performance metrics
            phase1_times = []
            phase2_times = []
            phase3_times = []
            total_times = []
            iterations = []
            memory_values = []
            
            for case in cases:
                perf = case.get('performance', {})
                if not perf:
                    continue
                
                phase_breakdown = perf.get('phase_breakdown', {})
                phase1_times.append(phase_breakdown.get('phase1_formalization', 0))
                phase2_times.append(phase_breakdown.get('phase2_generation', 0))
                phase3_times.append(phase_breakdown.get('phase3_verification', 0))
                total_times.append(perf.get('total_time_seconds', 0))
                iterations.append(perf.get('iteration_count', 0))
                
                mem = perf.get('peak_memory_mb')
                if mem:
                    memory_values.append(mem)
            
            # Calculate averages
            result = RQ3Result(
                complexity_level=complexity,
                avg_phase1_time=statistics.mean(phase1_times) if phase1_times else 0,
                avg_phase2_time=statistics.mean(phase2_times) if phase2_times else 0,
                avg_phase3_time=statistics.mean(phase3_times) if phase3_times else 0,
                avg_total_time=statistics.mean(total_times) if total_times else 0,
                avg_iterations=statistics.mean(iterations) if iterations else 0,
                peak_memory_mb=statistics.mean(memory_values) if memory_values else 0,
                case_count=len(cases)
            )
            results.append(result)
            
            print(f"\nComplexity: {complexity}")
            print(f"  Cases: {result.case_count}")
            print(f"  Avg Phase 1 (Formalization): {result.avg_phase1_time:.2f}s")
            print(f"  Avg Phase 2 (Generation): {result.avg_phase2_time:.2f}s")
            print(f"  Avg Phase 3 (Verification): {result.avg_phase3_time:.2f}s")
            print(f"  Avg Total Time: {result.avg_total_time:.2f}s")
            print(f"  Avg Iterations: {result.avg_iterations:.1f}")
            if result.peak_memory_mb > 0:
                print(f"  Peak Memory: {result.peak_memory_mb:.2f} MB")
        
        # Overall statistics
        if results:
            all_total_times = [r.avg_total_time for r in results]
            overall_avg = statistics.mean(all_total_times)
            print(f"\nOverall average time: {overall_avg:.2f}s ({overall_avg/60:.2f} min)")
        
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
        
        result = RQ4Result(
            explanation_type="Dual Explanations (E_bug + E_patch)",
            checklist_coverage=statistics.mean(checklist_coverages) if checklist_coverages else 0,
            avg_accuracy_score=statistics.mean(accuracy_scores) if accuracy_scores else 0,
            avg_clarity_score=statistics.mean(clarity_scores) if clarity_scores else 0,
            avg_causality_score=statistics.mean(causality_scores) if causality_scores else 0
        )
        
        print(f"\nExplanation type: {result.explanation_type}")
        print(f"  Avg checklist coverage: {result.checklist_coverage:.1%}")
        if result.avg_accuracy_score > 0:
            print(f"  Avg accuracy score: {result.avg_accuracy_score:.2f}/5")
            print(f"  Avg clarity score: {result.avg_clarity_score:.2f}/5")
            print(f"  Avg causality score: {result.avg_causality_score:.2f}/5")
        else:
            print(f"  Note: LLM quality scores not available (requires manual evaluation)")
        
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
                f"- Triple verification rate: {result['triple_verification_rate']:.1%}",
                f"- Ground truth similarity: {result['ground_truth_similarity']:.1%}",
                f"- First attempt success rate: {result['first_attempt_success_rate']:.1%}",
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
            lines.append("")
        
        lines.extend([
            "## RQ3: Scalability and Performance",
            "",
            "**Research Question**: What is the time overhead of the three-phase workflow?",
            ""
        ])
        
        for result in report['rq3_scalability_performance']:
            lines.extend([
                f"### Complexity: {result['complexity_level']}",
                f"- Cases: {result['case_count']}",
                f"- Avg Phase 1 (Formalization): {result['avg_phase1_time']:.2f}s",
                f"- Avg Phase 2 (Generation): {result['avg_phase2_time']:.2f}s",
                f"- Avg Phase 3 (Verification): {result['avg_phase3_time']:.2f}s",
                f"- **Avg Total Time**: {result['avg_total_time']:.2f}s",
                f"- Avg Iterations: {result['avg_iterations']:.1f}",
                f"- Peak Memory: {result['peak_memory_mb']:.2f} MB",
                ""
            ])
        
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
