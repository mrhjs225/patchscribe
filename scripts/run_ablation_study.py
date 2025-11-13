#!/usr/bin/env python3
"""
Ablation Study Framework for PatchScribe

This script runs comprehensive ablation studies to evaluate the contribution
of each component as described in the paper (Section 5.3).

Paper presents 3 ablation types:
1. Condition Ablation (C1-C4, Table 4): Guidance strategies
2. Component Ablation (A1-A5, Table 9): Individual components
3. Design Ablation (D1-D3, Tables 10-12): Design parameters

Usage:
    # Run all ablations
    python scripts/run_ablation_study.py --dataset zeroday --output results/ablation/

    # Run specific ablation type
    python scripts/run_ablation_study.py --ablation-type condition --dataset zeroday

    # Run in parallel
    python scripts/run_ablation_study.py --parallel --n-jobs 4
"""
from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Any, Optional
import numpy as np
import pandas as pd
from tqdm import tqdm

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from patchscribe.pipeline import PatchScribePipeline
from patchscribe.pcg_builder import PCGBuilderConfig


@dataclass
class AblationConfig:
    """Configuration for an ablation experiment."""
    name: str
    description: str
    config_overrides: Dict[str, Any]


@dataclass
class AblationResult:
    """Result from one ablation experiment."""
    config_name: str
    case_id: str
    success: bool
    patch_generated: bool
    consistency_passed: bool
    iteration_count: int
    execution_time_seconds: float
    error_message: Optional[str] = None


class ConditionAblation:
    """
    Condition Ablation (C1-C4, Table 4)

    Tests different levels of guidance:
    - C1: No guidance (baseline)
    - C2: Vague hints
    - C3: Pre-hoc guidance (E_bug) without consistency
    - C4: Full PatchScribe with consistency
    """

    @staticmethod
    def get_configurations() -> List[AblationConfig]:
        return [
            AblationConfig(
                name="C1_no_guidance",
                description="No guidance - baseline LLM patching",
                config_overrides={
                    "strategy": "c1",
                    "use_ebug": False,
                    "use_consistency_checking": False,
                    "use_iterative_refinement": False,
                }
            ),
            AblationConfig(
                name="C2_vague_hints",
                description="Vague hints only",
                config_overrides={
                    "strategy": "c2",
                    "use_ebug": False,
                    "use_consistency_checking": False,
                    "use_iterative_refinement": False,
                }
            ),
            AblationConfig(
                name="C3_ebug_no_checking",
                description="Pre-hoc guidance (E_bug) without consistency checking",
                config_overrides={
                    "strategy": "c3",
                    "use_ebug": True,
                    "use_consistency_checking": False,
                    "use_iterative_refinement": False,
                }
            ),
            AblationConfig(
                name="C4_full_patchscribe",
                description="Full PatchScribe with consistency checking",
                config_overrides={
                    "strategy": "c4",
                    "use_ebug": True,
                    "use_consistency_checking": True,
                    "use_iterative_refinement": True,
                }
            ),
        ]


class ComponentAblation:
    """
    Component Ablation (A1-A5, Table 9)

    Tests contribution of each component:
    - A1: Baseline (no PCG/SCM/checking)
    - A2: PCG-only (informal descriptions)
    - A3: PCG+SCM (E_bug) without checking
    - A4: PCG+Checking (no SCM reasoning)
    - A5: Full system
    """

    @staticmethod
    def get_configurations() -> List[AblationConfig]:
        return [
            AblationConfig(
                name="A1_baseline",
                description="Baseline - no PCG, SCM, or checking",
                config_overrides={
                    "use_pcg": False,
                    "use_scm": False,
                    "use_consistency_checking": False,
                }
            ),
            AblationConfig(
                name="A2_pcg_only",
                description="PCG only with informal descriptions",
                config_overrides={
                    "use_pcg": True,
                    "use_scm": False,
                    "use_consistency_checking": False,
                }
            ),
            AblationConfig(
                name="A3_pcg_scm",
                description="PCG + SCM (E_bug) without checking",
                config_overrides={
                    "use_pcg": True,
                    "use_scm": True,
                    "use_consistency_checking": False,
                }
            ),
            AblationConfig(
                name="A4_pcg_checking",
                description="PCG + Checking without SCM reasoning",
                config_overrides={
                    "use_pcg": True,
                    "use_scm": False,
                    "use_consistency_checking": True,
                }
            ),
            AblationConfig(
                name="A5_full_system",
                description="Full system - PCG + SCM + Checking",
                config_overrides={
                    "use_pcg": True,
                    "use_scm": True,
                    "use_consistency_checking": True,
                }
            ),
        ]


class DesignAblation:
    """
    Design Ablation (D1-D3, Tables 10-12)

    Tests design choices:
    - D1: Backward slice depth (1/3/5/∞)
    - D2: Prompt style (natural/formal/hybrid)
    - D3: Intervention style (prohibitive/constructive)
    """

    @staticmethod
    def get_slice_depth_configurations() -> List[AblationConfig]:
        """D1: Backward slice depth variations."""
        return [
            AblationConfig(
                name="D1_depth_1",
                description="Backward slice depth = 1",
                config_overrides={"slice_depth": 1}
            ),
            AblationConfig(
                name="D1_depth_3",
                description="Backward slice depth = 3",
                config_overrides={"slice_depth": 3}
            ),
            AblationConfig(
                name="D1_depth_5",
                description="Backward slice depth = 5",
                config_overrides={"slice_depth": 5}
            ),
            AblationConfig(
                name="D1_depth_inf",
                description="Backward slice depth = unlimited",
                config_overrides={"slice_depth": None}
            ),
        ]

    @staticmethod
    def get_prompt_style_configurations() -> List[AblationConfig]:
        """D2: Prompt style variations."""
        return [
            AblationConfig(
                name="D2_natural",
                description="Natural language prompts",
                config_overrides={"prompt_style": "natural"}
            ),
            AblationConfig(
                name="D2_formal",
                description="Formal specification prompts",
                config_overrides={"prompt_style": "formal"}
            ),
            AblationConfig(
                name="D2_hybrid",
                description="Hybrid natural + formal prompts",
                config_overrides={"prompt_style": "hybrid"}
            ),
        ]

    @staticmethod
    def get_intervention_style_configurations() -> List[AblationConfig]:
        """D3: Intervention style variations."""
        return [
            AblationConfig(
                name="D3_prohibitive",
                description="Prohibitive interventions (what not to do)",
                config_overrides={"intervention_style": "prohibitive"}
            ),
            AblationConfig(
                name="D3_constructive",
                description="Constructive interventions (what to do)",
                config_overrides={"intervention_style": "constructive"}
            ),
        ]

    @staticmethod
    def get_all_configurations() -> List[AblationConfig]:
        """Get all design ablation configurations."""
        configs = []
        configs.extend(DesignAblation.get_slice_depth_configurations())
        configs.extend(DesignAblation.get_prompt_style_configurations())
        configs.extend(DesignAblation.get_intervention_style_configurations())
        return configs


def run_single_case(
    case: Dict[str, Any],
    config: AblationConfig,
    base_config: Dict[str, Any]
) -> AblationResult:
    """
    Run a single test case with a specific ablation configuration.

    Args:
        case: Test case data
        config: Ablation configuration
        base_config: Base pipeline configuration

    Returns:
        AblationResult with execution details
    """
    import time

    try:
        # Merge base config with ablation overrides
        merged_config = {**base_config, **config.config_overrides}

        # Create pipeline with ablation config
        pipeline = PatchScribePipeline(
            program=case['source'],
            vuln_info={
                'location': case['vuln_line'],
                'cwe_id': case.get('cwe_id', 'unknown'),
                'signature': case.get('signature', ''),
            },
            config=merged_config
        )

        # Run pipeline
        start_time = time.time()
        result = pipeline.run()
        execution_time = time.time() - start_time

        return AblationResult(
            config_name=config.name,
            case_id=case['id'],
            success=result.get('success', False),
            patch_generated=result.get('patch') is not None,
            consistency_passed=result.get('consistency_result', {}).get('decision') == 'PASS',
            iteration_count=result.get('iteration_count', 0),
            execution_time_seconds=execution_time,
        )

    except Exception as e:
        return AblationResult(
            config_name=config.name,
            case_id=case['id'],
            success=False,
            patch_generated=False,
            consistency_passed=False,
            iteration_count=0,
            execution_time_seconds=0.0,
            error_message=str(e)
        )


def run_ablation_study(
    configs: List[AblationConfig],
    cases: List[Dict[str, Any]],
    base_config: Dict[str, Any],
    parallel: bool = False,
    n_jobs: int = 4
) -> List[AblationResult]:
    """
    Run ablation study across all configurations and cases.

    Args:
        configs: List of ablation configurations
        cases: List of test cases
        base_config: Base pipeline configuration
        parallel: Whether to run in parallel
        n_jobs: Number of parallel jobs

    Returns:
        List of ablation results
    """
    total_experiments = len(configs) * len(cases)
    print(f"\nRunning ablation study: {len(configs)} configs × {len(cases)} cases = {total_experiments} experiments")

    results = []

    if parallel:
        print(f"Running in parallel with {n_jobs} workers...")

        with ProcessPoolExecutor(max_workers=n_jobs) as executor:
            futures = []
            for config in configs:
                for case in cases:
                    future = executor.submit(run_single_case, case, config, base_config)
                    futures.append(future)

            for future in tqdm(as_completed(futures), total=total_experiments, desc="Processing"):
                result = future.result()
                results.append(result)

    else:
        print("Running sequentially...")

        for config in configs:
            print(f"\n--- Configuration: {config.name} ---")
            for case in tqdm(cases, desc=f"{config.name}"):
                result = run_single_case(case, config, base_config)
                results.append(result)

    return results


def analyze_results(results: List[AblationResult]) -> pd.DataFrame:
    """
    Analyze ablation results and compute statistics.

    Args:
        results: List of ablation results

    Returns:
        DataFrame with aggregated statistics
    """
    df = pd.DataFrame([asdict(r) for r in results])

    # Group by configuration
    grouped = df.groupby('config_name').agg({
        'success': ['mean', 'sum', 'count'],
        'patch_generated': 'mean',
        'consistency_passed': 'mean',
        'iteration_count': ['mean', 'std'],
        'execution_time_seconds': ['mean', 'std']
    }).round(3)

    # Flatten column names
    grouped.columns = ['_'.join(col).strip() for col in grouped.columns.values]

    return grouped


def save_results(
    results: List[AblationResult],
    analysis: pd.DataFrame,
    output_dir: Path,
    ablation_type: str
):
    """Save ablation study results."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save raw results
    results_path = output_dir / f"{ablation_type}_results.json"
    with open(results_path, 'w') as f:
        json.dump([asdict(r) for r in results], f, indent=2)
    print(f"✅ Raw results saved to: {results_path}")

    # Save analysis
    analysis_path = output_dir / f"{ablation_type}_analysis.csv"
    analysis.to_csv(analysis_path)
    print(f"✅ Analysis saved to: {analysis_path}")

    # Save summary
    summary_path = output_dir / f"{ablation_type}_summary.txt"
    with open(summary_path, 'w') as f:
        f.write(f"Ablation Study: {ablation_type}\n")
        f.write("=" * 80 + "\n\n")
        f.write(str(analysis))
        f.write("\n\n")
    print(f"✅ Summary saved to: {summary_path}")


def load_dataset(dataset_name: str, data_dir: Path) -> List[Dict[str, Any]]:
    """Load test dataset."""
    dataset_path = data_dir / f"{dataset_name}.json"

    if not dataset_path.exists():
        print(f"⚠️  Dataset not found: {dataset_path}")
        print("Using sample dataset for demonstration...")
        return [
            {
                'id': f'sample_{i}',
                'source': f'// Sample code {i}',
                'vuln_line': 10,
                'cwe_id': 'CWE-125',
                'signature': 'array[i]'
            }
            for i in range(3)
        ]

    with open(dataset_path) as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(
        description="Run ablation studies for PatchScribe"
    )
    parser.add_argument(
        '--ablation-type',
        type=str,
        choices=['condition', 'component', 'design', 'all'],
        default='all',
        help='Type of ablation study to run'
    )
    parser.add_argument(
        '--dataset',
        type=str,
        default='test_3cases',
        help='Dataset name to use'
    )
    parser.add_argument(
        '--data-dir',
        type=Path,
        default=Path('datasets'),
        help='Directory containing datasets'
    )
    parser.add_argument(
        '--output',
        type=Path,
        default=Path('results/ablation'),
        help='Output directory for results'
    )
    parser.add_argument(
        '--parallel',
        action='store_true',
        help='Run experiments in parallel'
    )
    parser.add_argument(
        '--n-jobs',
        type=int,
        default=4,
        help='Number of parallel jobs'
    )

    args = parser.parse_args()

    print("=" * 80)
    print("PatchScribe Ablation Study Framework")
    print("=" * 80)

    # Load dataset
    print(f"\nLoading dataset: {args.dataset}")
    cases = load_dataset(args.dataset, args.data_dir)
    print(f"Loaded {len(cases)} test cases")

    # Base configuration
    base_config = {
        'max_iterations': 3,
        'temperature': 0.7,
    }

    # Run ablation studies
    ablation_types = {
        'condition': ConditionAblation.get_configurations(),
        'component': ComponentAblation.get_configurations(),
        'design': DesignAblation.get_all_configurations(),
    }

    if args.ablation_type == 'all':
        types_to_run = ablation_types.keys()
    else:
        types_to_run = [args.ablation_type]

    for ablation_type in types_to_run:
        print(f"\n{'=' * 80}")
        print(f"Running {ablation_type.upper()} ablation study")
        print(f"{'=' * 80}")

        configs = ablation_types[ablation_type]
        print(f"Configurations: {[c.name for c in configs]}")

        # Run experiments
        results = run_ablation_study(
            configs=configs,
            cases=cases,
            base_config=base_config,
            parallel=args.parallel,
            n_jobs=args.n_jobs
        )

        # Analyze results
        analysis = analyze_results(results)
        print("\n" + "=" * 80)
        print("RESULTS SUMMARY")
        print("=" * 80)
        print(analysis)

        # Save results
        save_results(results, analysis, args.output, ablation_type)

    print("\n" + "=" * 80)
    print("Ablation study complete!")
    print("=" * 80)
    print(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()
