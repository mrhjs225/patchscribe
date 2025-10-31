#!/usr/bin/env python3
"""
Main evaluation runner for PatchScribe RQ experiments.
Runs full evaluation pipeline and generates RQ-specific analysis.
"""
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

# Add patchscribe to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from patchscribe.evaluation import Evaluator
from patchscribe.pipeline import PatchScribePipeline
from patchscribe.dataset import load_cases


def load_evaluation_cases(dataset_path: Path) -> List[Dict[str, Any]]:
    """Load evaluation cases from dataset"""
    print(f"📂 Loading dataset from: {dataset_path}")
    
    # Check if it's a dataset name
    dataset_name = str(dataset_path)
    if dataset_name in ['poc', 'zeroday']:
        print(f"Using built-in {dataset_name} dataset")
        cases = load_cases(dataset=dataset_name)
        print(f"✅ Loaded {len(cases)} test cases")
        return cases
    
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")
    
    # Try to load as JSON
    if dataset_path.suffix == '.json':
        with open(dataset_path, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                cases = data
            elif isinstance(data, dict) and 'cases' in data:
                cases = data['cases']
            else:
                raise ValueError("Invalid dataset format")
    # Try to load from directory (zeroday_repair format)
    elif dataset_path.is_dir():
        # Check if it's the zeroday_repair directory
        if (dataset_path / "datasets" / "zeroday_repair").exists():
            cases = load_cases(dataset='zeroday')
        else:
            raise ValueError(f"Unknown directory structure: {dataset_path}")
    else:
        raise ValueError(f"Unknown dataset format: {dataset_path}")
    
    print(f"✅ Loaded {len(cases)} test cases")
    return cases


def run_baseline_evaluation(cases: List[Dict], output_dir: Path, config: Dict):
    """Run baseline evaluation (C1: post-hoc, no formal guidance)"""
    print("\n" + "="*80)
    print("RQ1 - Condition C1: Baseline (post-hoc, no formal guidance)")
    print("="*80)

    pipeline = PatchScribePipeline(
        strategy="only_natural",  # No formal guidance
        explain_mode="llm",
        enable_consistency_check=False,  # No verification
        enable_performance_profiling=False
    )

    max_workers = config.get('max_workers', None)
    evaluator = Evaluator(pipeline=pipeline, max_workers=max_workers)
    report = evaluator.run(cases)
    
    # Save results
    output_path = output_dir / 'baseline_c1_results.json'
    with open(output_path, 'w') as f:
        json.dump(report.as_dict(), f, indent=2)
    
    print(f"✅ Baseline results saved to: {output_path}")
    print(f"   Success rate: {report.metrics.get('success_rate', 0):.1%}")
    
    return report


def run_vague_hints_evaluation(cases: List[Dict], output_dir: Path, config: Dict):
    """Run vague hints evaluation (C2: informal prompts)"""
    print("\n" + "="*80)
    print("RQ1 - Condition C2: Vague Hints (informal prompts)")
    print("="*80)

    pipeline = PatchScribePipeline(
        strategy="natural",  # Natural language hints but not formal
        explain_mode="llm",
        enable_consistency_check=False,
        enable_performance_profiling=False
    )

    max_workers = config.get('max_workers', None)
    evaluator = Evaluator(pipeline=pipeline, max_workers=max_workers)
    report = evaluator.run(cases)
    
    output_path = output_dir / 'vague_hints_c2_results.json'
    with open(output_path, 'w') as f:
        json.dump(report.as_dict(), f, indent=2)
    
    print(f"✅ Vague hints results saved to: {output_path}")
    print(f"   Success rate: {report.metrics.get('success_rate', 0):.1%}")
    
    return report


def run_prehoc_guidance_evaluation(cases: List[Dict], output_dir: Path, config: Dict):
    """Run pre-hoc guidance evaluation (C3: E_bug without verification)"""
    print("\n" + "="*80)
    print("RQ1 - Condition C3: Pre-hoc Guidance (E_bug without verification)")
    print("="*80)

    pipeline = PatchScribePipeline(
        strategy="formal",  # Formal E_bug guidance
        explain_mode="both",
        enable_consistency_check=False,  # No verification yet
        enable_performance_profiling=False
    )

    max_workers = config.get('max_workers', None)
    evaluator = Evaluator(pipeline=pipeline, max_workers=max_workers)
    report = evaluator.run(cases)
    
    output_path = output_dir / 'prehoc_c3_results.json'
    with open(output_path, 'w') as f:
        json.dump(report.as_dict(), f, indent=2)
    
    print(f"✅ Pre-hoc guidance results saved to: {output_path}")
    print(f"   Success rate: {report.metrics.get('success_rate', 0):.1%}")
    
    return report


def run_full_patchscribe_evaluation(cases: List[Dict], output_dir: Path, config: Dict):
    """Run full PatchScribe evaluation (C4: E_bug + triple verification)"""
    print("\n" + "="*80)
    print("RQ1 - Condition C4: Full PatchScribe (E_bug + triple verification)")
    print("="*80)

    pipeline = PatchScribePipeline(
        strategy="formal",
        explain_mode="both",
        enable_consistency_check=True,  # Enable consistency checking
        enable_performance_profiling=True  # Enable for RQ3
    )

    max_workers = config.get('max_workers', None)
    evaluator = Evaluator(pipeline=pipeline, max_workers=max_workers)
    report = evaluator.run(cases)
    
    output_path = output_dir / 'full_patchscribe_c4_results.json'
    with open(output_path, 'w') as f:
        json.dump(report.as_dict(), f, indent=2)
    
    print(f"✅ Full PatchScribe results saved to: {output_path}")
    print(f"   Success rate: {report.metrics.get('success_rate', 0):.1%}")
    print(f"   Consistency pass rate: {report.metrics.get('consistency_pass_rate', 0):.1%}")
    print(f"   Triple verification rate: {report.metrics.get('triple_verification_pass_rate', 0):.1%}")
    
    return report


def run_rq_analysis(results_dir: Path, output_dir: Path):
    """Run RQ-specific analysis on all results"""
    print("\n" + "="*80)
    print("RUNNING RQ ANALYSIS")
    print("="*80)
    
    # Import the RQ analysis script
    from scripts.run_rq_analysis import RQAnalyzer
    
    # Analyze each condition
    all_analyses = {}
    
    for results_file in results_dir.glob('*_results.json'):
        print(f"\n📊 Analyzing: {results_file.name}")
        analyzer = RQAnalyzer(results_file)
        
        condition_name = results_file.stem.replace('_results', '')
        analysis_output = output_dir / f'rq_analysis_{condition_name}.json'
        
        report = analyzer.generate_comprehensive_report(analysis_output)
        all_analyses[condition_name] = report
    
    # Generate comparative analysis
    comparative_path = output_dir / 'rq_comparative_analysis.json'
    with open(comparative_path, 'w') as f:
        json.dump(all_analyses, f, indent=2)
    
    print(f"\n✅ Comparative analysis saved to: {comparative_path}")
    
    return all_analyses


def generate_final_report(all_results: Dict, output_dir: Path):
    """Generate final comprehensive report"""
    print("\n" + "="*80)
    print("GENERATING FINAL REPORT")
    print("="*80)
    
    report_lines = [
        "# PatchScribe Evaluation Report",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Executive Summary",
        "",
    ]
    
    # Extract key metrics from each condition
    conditions = ['baseline_c1', 'vague_hints_c2', 'prehoc_c3', 'full_patchscribe_c4']
    
    report_lines.append("### RQ1: Theory-Guided Generation Effectiveness")
    report_lines.append("")
    report_lines.append("| Condition | Success Rate | First Attempt | Ground Truth |")
    report_lines.append("|-----------|--------------|---------------|--------------|")
    
    for cond in conditions:
        if cond in all_results:
            metrics = all_results[cond].metrics
            report_lines.append(
                f"| {cond} | "
                f"{metrics.get('success_rate', 0):.1%} | "
                f"{metrics.get('first_attempt_success_rate', 0):.1%} | "
                f"{metrics.get('ground_truth_match_rate', 0):.1%} |"
            )
    
    report_lines.extend([
        "",
        "### RQ2: Dual Verification Effectiveness",
        ""
    ])
    
    if 'full_patchscribe_c4' in all_results:
        c4_metrics = all_results['full_patchscribe_c4'].metrics
        report_lines.extend([
            f"- Consistency pass rate: {c4_metrics.get('consistency_pass_rate', 0):.1%}",
            f"- Triple verification rate: {c4_metrics.get('triple_verification_pass_rate', 0):.1%}",
            f"- Vulnerability elimination rate: {c4_metrics.get('vulnerability_elimination_rate', 0):.1%}",
            ""
        ])
    
    report_lines.extend([
        "### RQ3: Scalability and Performance",
        "",
        "See detailed performance breakdown in RQ3 analysis files.",
        "",
        "### RQ4: Explanation Quality",
        ""
    ])
    
    if 'full_patchscribe_c4' in all_results:
        c4_metrics = all_results['full_patchscribe_c4'].metrics
        report_lines.extend([
            f"- Avg explanation checklist coverage: {c4_metrics.get('avg_explanation_checklist', 0):.1%}",
        ])
        
        if 'avg_llm_accuracy' in c4_metrics:
            report_lines.extend([
                f"- Avg LLM accuracy: {c4_metrics.get('avg_llm_accuracy', 0):.2f}/5",
                f"- Avg LLM clarity: {c4_metrics.get('avg_llm_clarity', 0):.2f}/5",
                f"- Avg LLM causality: {c4_metrics.get('avg_llm_causality', 0):.2f}/5",
            ])
    
    report_lines.extend([
        "",
        "## Detailed Results",
        "",
        "See individual result files:",
    ])
    
    for cond in conditions:
        if cond in all_results:
            report_lines.append(f"- `{cond}_results.json`")
    
    report_lines.extend([
        "",
        "## RQ Analysis Reports",
        "",
        "Detailed RQ-specific analysis available in:",
        "- `rq_comparative_analysis.json`",
        "- Individual RQ analysis files for each condition",
    ])
    
    # Write report
    report_path = output_dir / 'EVALUATION_REPORT.md'
    report_path.write_text('\n'.join(report_lines))
    
    print(f"✅ Final report saved to: {report_path}")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run comprehensive PatchScribe RQ evaluation')
    parser.add_argument('dataset', type=Path, help='Path to evaluation dataset')
    parser.add_argument('-o', '--output', type=Path, default=Path('results/evaluation'),
                       help='Output directory for results (default: results/evaluation)')
    parser.add_argument('--conditions', nargs='+', 
                       choices=['c1', 'c2', 'c3', 'c4', 'all'],
                       default=['all'],
                       help='Which conditions to run (default: all)')
    parser.add_argument('--limit', type=int,
                       help='Limit number of cases to evaluate (useful for testing)')
    parser.add_argument('--skip-analysis', action='store_true',
                       help='Skip RQ analysis step')
    parser.add_argument('--llm-provider', type=str, default='ollama',
                       help='LLM provider (default: ollama)')
    parser.add_argument('--llm-model', type=str, default='llama3.2:1b',
                       help='LLM model name (default: llama3.2:1b)')
    parser.add_argument('--llm-endpoint', type=str,
                       help='LLM endpoint URL (default: provider-specific)')
    parser.add_argument('--max-workers', type=int, default=None,
                       help='Maximum parallel workers for case evaluation (default: CPU count)')

    args = parser.parse_args()
    
    # Set LLM environment variables from command line args
    import os
    os.environ['PATCHSCRIBE_LLM_PROVIDER'] = args.llm_provider
    os.environ['PATCHSCRIBE_LLM_MODEL'] = args.llm_model
    if args.llm_endpoint:
        os.environ['PATCHSCRIBE_LLM_ENDPOINT'] = args.llm_endpoint
    
    # Create output directory
    output_dir = args.output
    output_dir.mkdir(parents=True, exist_ok=True)
    
    results_dir = output_dir / 'raw_results'
    results_dir.mkdir(exist_ok=True)
    
    analysis_dir = output_dir / 'rq_analysis'
    analysis_dir.mkdir(exist_ok=True)
    
    print("="*80)
    print("PATCHSCRIBE RQ EVALUATION")
    print("="*80)
    print(f"Dataset: {args.dataset}")
    print(f"Output: {output_dir}")
    print(f"Conditions: {args.conditions}")
    print(f"LLM Provider: {args.llm_provider}")
    print(f"LLM Model: {args.llm_model}")
    if args.llm_endpoint:
        print(f"LLM Endpoint: {args.llm_endpoint}")
    print("="*80)
    
    # Load dataset
    try:
        cases = load_evaluation_cases(args.dataset)
        
        # Apply limit if specified
        if args.limit and args.limit > 0:
            original_count = len(cases)
            cases = cases[:args.limit]
            print(f"⚠️  Limited dataset from {original_count} to {len(cases)} cases")
    except Exception as e:
        print(f"❌ Error loading dataset: {e}")
        sys.exit(1)
    
    # Configuration
    config = {
        'llm_model': 'gpt-4',
        'max_iterations': 3,
        'timeout': 300,
        'max_workers': args.max_workers
    }
    
    # Run evaluations
    all_results = {}
    conditions_to_run = args.conditions
    if 'all' in conditions_to_run:
        conditions_to_run = ['c1', 'c2', 'c3', 'c4']
    
    try:
        if 'c1' in conditions_to_run:
            report_c1 = run_baseline_evaluation(cases, results_dir, config)
            all_results['baseline_c1'] = report_c1
        
        if 'c2' in conditions_to_run:
            report_c2 = run_vague_hints_evaluation(cases, results_dir, config)
            all_results['vague_hints_c2'] = report_c2
        
        if 'c3' in conditions_to_run:
            report_c3 = run_prehoc_guidance_evaluation(cases, results_dir, config)
            all_results['prehoc_c3'] = report_c3
        
        if 'c4' in conditions_to_run:
            report_c4 = run_full_patchscribe_evaluation(cases, results_dir, config)
            all_results['full_patchscribe_c4'] = report_c4
        
        # Run RQ analysis
        if not args.skip_analysis and all_results:
            run_rq_analysis(results_dir, analysis_dir)
        
        # Generate final report
        generate_final_report(all_results, output_dir)
        
        print("\n" + "="*80)
        print("✅ EVALUATION COMPLETE")
        print("="*80)
        print(f"Results directory: {output_dir}")
        print(f"  - Raw results: {results_dir}")
        print(f"  - RQ analysis: {analysis_dir}")
        print(f"  - Final report: {output_dir / 'EVALUATION_REPORT.md'}")
        
    except Exception as e:
        print(f"\n❌ Error during evaluation: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
