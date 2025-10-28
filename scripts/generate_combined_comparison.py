#!/usr/bin/env python3
"""
Generate a combined comparison report from multiple model evaluation results.
This can combine results from different servers or evaluation runs.
"""
import json
import sys
from pathlib import Path
from datetime import datetime
import argparse


def collect_results(base_dirs: list[Path]) -> dict:
    """Collect results from multiple base directories"""
    
    all_results = {}
    
    for base_dir in base_dirs:
        print(f"Scanning directory: {base_dir}")
        
        if not base_dir.exists():
            print(f"  ⚠️  Directory not found, skipping")
            continue
        
        # Find all model result directories
        for model_dir in base_dir.iterdir():
            if not model_dir.is_dir():
                continue
            
            # Look for C4 results (full PatchScribe)
            c4_results = model_dir / "raw_results" / "full_patchscribe_c4_results.json"
            if not c4_results.exists():
                continue
            
            # Extract model name from directory
            model_name = model_dir.name.rsplit('_', 2)[0]
            
            print(f"  ✅ Found results for: {model_name}")
            
            # Load results
            with open(c4_results, 'r') as f:
                data = json.load(f)
                metrics = data.get('metrics', {})
                
                all_results[model_name] = {
                    "source_directory": str(model_dir),
                    "metrics": {
                        "success_rate": metrics.get('success_rate', 0),
                        "consistency_pass_rate": metrics.get('consistency_pass_rate', 0),
                        "triple_verification_pass_rate": metrics.get('triple_verification_pass_rate', 0),
                        "first_attempt_success_rate": metrics.get('first_attempt_success_rate', 0),
                        "total_cases": metrics.get('total_cases', 0),
                        "successful_cases": metrics.get('successful_cases', 0),
                    }
                }
            
            # Also check for other conditions if available
            for condition in ['baseline_c1', 'vague_hints_c2', 'prehoc_c3']:
                condition_file = model_dir / "raw_results" / f"{condition}_results.json"
                if condition_file.exists():
                    with open(condition_file, 'r') as f:
                        data = json.load(f)
                        cond_metrics = data.get('metrics', {})
                        all_results[model_name][f"{condition}_success_rate"] = cond_metrics.get('success_rate', 0)
    
    return all_results


def generate_comparison_report(results: dict, output_dir: Path):
    """Generate comprehensive comparison report"""
    
    # Create comparison data structure
    comparison = {
        "generated_at": datetime.now().isoformat(),
        "total_models": len(results),
        "models": results
    }
    
    # Save JSON report
    json_file = output_dir / "combined_comparison.json"
    with open(json_file, 'w') as f:
        json.dump(comparison, f, indent=2)
    
    print(f"\n✅ JSON report saved to: {json_file}")
    
    # Generate Markdown report
    md_lines = [
        "# PatchScribe Multi-Model Comparison Report",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"Total models evaluated: {len(results)}",
        "",
        "## Overall Performance Comparison",
        "",
        "### C4 (Full PatchScribe) Results",
        "",
        "| Model | Success Rate | Consistency Pass | Triple Verification | First Attempt | Total Cases |",
        "|-------|--------------|------------------|---------------------|---------------|-------------|",
    ]
    
    # Sort by success rate
    sorted_models = sorted(
        results.items(),
        key=lambda x: x[1]['metrics']['success_rate'],
        reverse=True
    )
    
    for model_name, data in sorted_models:
        metrics = data['metrics']
        md_lines.append(
            f"| {model_name} | "
            f"{metrics['success_rate']:.1%} | "
            f"{metrics['consistency_pass_rate']:.1%} | "
            f"{metrics['triple_verification_pass_rate']:.1%} | "
            f"{metrics['first_attempt_success_rate']:.1%} | "
            f"{metrics['total_cases']} |"
        )
    
    # Add condition comparison if available
    has_conditions = any(
        any(key.endswith('_success_rate') for key in data.keys() if key != 'metrics')
        for data in results.values()
    )
    
    if has_conditions:
        md_lines.extend([
            "",
            "## RQ1: Condition Comparison",
            "",
            "| Model | C1 (Baseline) | C2 (Vague) | C3 (Pre-hoc) | C4 (Full) |",
            "|-------|---------------|------------|--------------|-----------|",
        ])
        
        for model_name, data in sorted_models:
            c1 = data.get('baseline_c1_success_rate', 0)
            c2 = data.get('vague_hints_c2_success_rate', 0)
            c3 = data.get('prehoc_c3_success_rate', 0)
            c4 = data['metrics']['success_rate']
            
            if c1 > 0 or c2 > 0 or c3 > 0:  # Only show if we have condition data
                md_lines.append(
                    f"| {model_name} | "
                    f"{c1:.1%} | "
                    f"{c2:.1%} | "
                    f"{c3:.1%} | "
                    f"{c4:.1%} |"
                )
    
    md_lines.extend([
        "",
        "## Key Findings",
        "",
        f"- **Best performing model**: {sorted_models[0][0]} ({sorted_models[0][1]['metrics']['success_rate']:.1%} success rate)",
        f"- **Highest consistency**: {max(results.items(), key=lambda x: x[1]['metrics']['consistency_pass_rate'])[0]}",
        f"- **Best first attempt**: {max(results.items(), key=lambda x: x[1]['metrics']['first_attempt_success_rate'])[0]}",
        "",
        "## Source Directories",
        "",
    ])
    
    for model_name, data in sorted_models:
        md_lines.append(f"- **{model_name}**: `{data['source_directory']}`")
    
    md_lines.append("")
    
    # Save Markdown report
    md_file = output_dir / "combined_comparison.md"
    with open(md_file, 'w') as f:
        f.write('\n'.join(md_lines))
    
    print(f"✅ Markdown report saved to: {md_file}")
    
    # Print console summary
    print("\n" + "=" * 80)
    print("MODEL PERFORMANCE SUMMARY")
    print("=" * 80)
    print(f"{'Model':<25} {'Success':<12} {'Consistency':<15} {'Triple Verif':<15}")
    print("-" * 80)
    
    for model_name, data in sorted_models:
        metrics = data['metrics']
        print(f"{model_name:<25} "
              f"{metrics['success_rate']:>10.1%}  "
              f"{metrics['consistency_pass_rate']:>12.1%}  "
              f"{metrics['triple_verification_pass_rate']:>13.1%}")
    
    print("=" * 80)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Generate combined comparison report from multiple evaluation results'
    )
    parser.add_argument(
        'directories',
        nargs='+',
        type=Path,
        help='Result directories to combine (can be from different servers)'
    )
    parser.add_argument(
        '-o', '--output',
        type=Path,
        default=Path('results/combined_comparison'),
        help='Output directory for combined report (default: results/combined_comparison)'
    )
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("PATCHSCRIBE COMBINED COMPARISON REPORT")
    print("=" * 80)
    print(f"Input directories: {len(args.directories)}")
    for d in args.directories:
        print(f"  - {d}")
    print(f"Output directory: {args.output}")
    print("=" * 80)
    print()
    
    # Collect results
    results = collect_results(args.directories)
    
    if not results:
        print("❌ No results found in the specified directories")
        sys.exit(1)
    
    print(f"\n✅ Collected results from {len(results)} models")
    
    # Create output directory
    args.output.mkdir(parents=True, exist_ok=True)
    
    # Generate report
    generate_comparison_report(results, args.output)
    
    print("\n" + "=" * 80)
    print("COMBINED REPORT GENERATION COMPLETE")
    print("=" * 80)
    print(f"Results: {args.output}")
    print()


if __name__ == '__main__':
    main()
