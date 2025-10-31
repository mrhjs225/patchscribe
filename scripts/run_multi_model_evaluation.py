#!/usr/bin/env python3
"""
Multi-model evaluation runner for PatchScribe.
Runs full RQ evaluation with multiple LLM models in parallel.
"""
import subprocess
import sys
from pathlib import Path
from datetime import datetime
import json
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing as mp

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None


# Models to test (modify as needed)
DEFAULT_MODELS = [
    "llama3.2:1b",
]


def run_evaluation_for_model(
    dataset: str,
    model: str,
    provider: str,
    output_base: Path,
    conditions: list = None,
    endpoint: str = None,
    limit: int = None
) -> bool:
    """Run evaluation for a single model"""
    
    # Create model-specific output directory
    model_safe = model.replace(':', '_').replace('/', '_')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = output_base / f"{model_safe}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print("=" * 80)
    print(f"Starting evaluation with model: {model}")
    print("=" * 80)
    print(f"Output directory: {output_dir}")
    print()
    
    # Build command
    cmd = [
        sys.executable,
        "scripts/run_full_evaluation.py",
        dataset,
        "--llm-provider", provider,
        "--llm-model", model,
        "-o", str(output_dir)
    ]
    
    if conditions:
        cmd.extend(["--conditions"] + conditions)
    
    if endpoint:
        cmd.extend(["--llm-endpoint", endpoint])
    
    if limit:
        cmd.extend(["--limit", str(limit)])
    
    # Run evaluation
    log_file = output_dir / "evaluation.log"
    
    try:
        with open(log_file, 'w') as f:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Stream output to both console and log file
            for line in process.stdout:
                print(line, end='')
                f.write(line)
            
            process.wait()
            
        if process.returncode == 0:
            print(f"\n✅ Evaluation with {model} completed successfully")
            print(f"   Results: {output_dir}")
            return True
        else:
            print(f"\n❌ Evaluation with {model} failed (exit code: {process.returncode})")
            print(f"   Check log: {log_file}")
            return False
            
    except Exception as e:
        print(f"\n❌ Error running evaluation with {model}: {e}")
        return False


def generate_comparison_report(output_base: Path, models: list):
    """Generate a comparison report across all models"""
    
    print("\n" + "=" * 80)
    print("GENERATING COMPARISON REPORT")
    print("=" * 80)
    
    comparison = {
        "timestamp": datetime.now().isoformat(),
        "models": {},
    }
    
    # Collect results from each model
    for model_dir in output_base.iterdir():
        if not model_dir.is_dir():
            continue
        
        report_path = model_dir / "EVALUATION_REPORT.md"
        if not report_path.exists():
            continue
        
        # Extract model name from directory
        model_name = model_dir.name.rsplit('_', 2)[0]
        
        # Try to load key metrics
        c4_results = model_dir / "raw_results" / "full_patchscribe_c4_results.json"
        if c4_results.exists():
            with open(c4_results, 'r') as f:
                data = json.load(f)
                metrics = data.get('metrics', {})
                comparison["models"][model_name] = {
                    "directory": str(model_dir),
                    "success_rate": metrics.get('success_rate', 0),
                    "consistency_pass_rate": metrics.get('consistency_pass_rate', 0),
                    "triple_verification_rate": metrics.get('triple_verification_pass_rate', 0),
                    "total_cases": metrics.get('total_cases', 0),
                }
    
    # Save comparison
    comparison_file = output_base / "model_comparison.json"
    with open(comparison_file, 'w') as f:
        json.dump(comparison, f, indent=2)
    
    print(f"✅ Comparison saved to: {comparison_file}")
    
    # Print summary table
    print("\n" + "=" * 80)
    print("MODEL COMPARISON SUMMARY")
    print("=" * 80)
    print(f"{'Model':<25} {'Success':<12} {'Consistency':<15} {'Triple Verif':<15}")
    print("-" * 80)
    
    for model_name, metrics in comparison["models"].items():
        print(f"{model_name:<25} "
              f"{metrics['success_rate']:>10.1%}  "
              f"{metrics['consistency_pass_rate']:>12.1%}  "
              f"{metrics['triple_verification_rate']:>13.1%}")
    
    print("=" * 80)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Run PatchScribe RQ evaluation with multiple LLM models'
    )
    parser.add_argument(
        'dataset',
        nargs='?',
        default='zeroday',
        help='Dataset name (poc/zeroday) or path to JSON file (default: zeroday)'
    )
    parser.add_argument(
        '-o', '--output',
        type=Path,
        default=Path('results/multi_model_evaluation'),
        help='Base output directory (default: results/multi_model_evaluation)'
    )
    parser.add_argument(
        '--models',
        nargs='+',
        default=DEFAULT_MODELS,
        help=f'Models to evaluate (default: {" ".join(DEFAULT_MODELS)})'
    )
    parser.add_argument(
        '--provider',
        type=str,
        default='ollama',
        help='LLM provider (default: ollama)'
    )
    parser.add_argument(
        '--endpoint',
        type=str,
        help='LLM endpoint URL (optional)'
    )
    parser.add_argument(
        '--conditions',
        nargs='+',
        choices=['c1', 'c2', 'c3', 'c4', 'all'],
        help='Which conditions to run (default: all)'
    )
    parser.add_argument(
        '--limit',
        type=int,
        help='Limit number of cases to evaluate (useful for testing)'
    )
    parser.add_argument(
        '--skip-comparison',
        action='store_true',
        help='Skip final comparison report'
    )
    parser.add_argument(
        '--parallel',
        action='store_true',
        help='Run models in parallel (default: sequential)'
    )
    parser.add_argument(
        '--max-parallel-models',
        type=int,
        default=min(4, mp.cpu_count() // 4),
        help=f'Maximum number of models to run in parallel (default: {min(4, mp.cpu_count() // 4)})'
    )

    args = parser.parse_args()
    if args.provider.lower() == 'ollama' and args.parallel:
        print("Warning: Ollama provider detected; disabling parallel model execution to avoid concurrent Ollama requests.")
        args.parallel = False
    
    print("=" * 80)
    print("PATCHSCRIBE MULTI-MODEL EVALUATION")
    print("=" * 80)
    print(f"Dataset: {args.dataset}")
    print(f"Base output: {args.output}")
    print(f"Provider: {args.provider}")
    print(f"Models: {', '.join(args.models)}")
    if args.conditions:
        print(f"Conditions: {', '.join(args.conditions)}")
    if args.limit:
        print(f"Case limit: {args.limit}")
    if args.parallel:
        print(f"Parallel execution: YES (max {args.max_parallel_models} concurrent models)")
    else:
        print(f"Parallel execution: NO (sequential)")
    print("=" * 80)
    print()

    # Create base output directory
    args.output.mkdir(parents=True, exist_ok=True)

    # Run evaluation for each model
    results = {}

    if args.parallel:
        # Parallel execution
        print(f"Running {len(args.models)} models in parallel (max {args.max_parallel_models} concurrent)...\n")

        # 진행 상황 표시 설정
        if tqdm is not None:
            progress_bar = tqdm(
                total=len(args.models),
                desc="Model evaluation",
                unit="model"
            )
        else:
            progress_bar = None

        with ProcessPoolExecutor(max_workers=args.max_parallel_models) as executor:
            # Submit all model evaluations
            future_to_model = {
                executor.submit(
                    run_evaluation_for_model,
                    args.dataset,
                    model,
                    args.provider,
                    args.output,
                    args.conditions,
                    args.endpoint,
                    args.limit
                ): model
                for model in args.models
            }

            # Collect results as they complete
            for future in as_completed(future_to_model):
                model = future_to_model[future]
                try:
                    success = future.result()
                    results[model] = success
                    if progress_bar is not None:
                        progress_bar.update(1)
                        success_count = sum(1 for s in results.values() if s)
                        progress_bar.set_postfix({"success": f"{success_count}/{len(results)}"})
                    else:
                        print(f"\n{'✅' if success else '❌'} Model {model} completed\n")
                except Exception as e:
                    results[model] = False
                    if progress_bar is not None:
                        progress_bar.update(1)
                    else:
                        print(f"\n❌ Model {model} failed with exception: {e}\n")

        if progress_bar is not None:
            progress_bar.close()
    else:
        # Sequential execution
        for model in args.models:
            success = run_evaluation_for_model(
                dataset=args.dataset,
                model=model,
                provider=args.provider,
                output_base=args.output,
                conditions=args.conditions,
                endpoint=args.endpoint,
                limit=args.limit
            )
            results[model] = success

            print("\nWaiting 5 seconds before next model...")
            import time
            time.sleep(5)
    
    # Generate comparison report
    if not args.skip_comparison:
        generate_comparison_report(args.output, args.models)
    
    # Final summary
    print("\n" + "=" * 80)
    print("ALL EVALUATIONS COMPLETE")
    print("=" * 80)
    
    successful = sum(1 for s in results.values() if s)
    total = len(results)
    
    print(f"Successful: {successful}/{total}")
    print(f"Results directory: {args.output}")
    print()
    
    for model, success in results.items():
        status = "✅" if success else "❌"
        print(f"  {status} {model}")
    
    print()
    print("To view individual reports:")
    print(f"  ls -la {args.output}/*/EVALUATION_REPORT.md")
    print()
    
    # Exit with error if any evaluation failed
    if not all(results.values()):
        sys.exit(1)


if __name__ == '__main__':
    main()
