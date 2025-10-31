#!/usr/bin/env python3
"""
결과 병합 스크립트
여러 서버의 실험 결과를 하나로 병합
"""
import json
import sys
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).parent.parent))


def merge_results(server_dirs: List[Path], output_dir: Path):
    """모든 서버 결과를 병합"""

    print("="*80)
    print("MERGING RESULTS FROM ALL SERVERS")
    print("="*80)

    output_dir.mkdir(parents=True, exist_ok=True)

    # 각 조건별로 병합
    for condition in ['c1', 'c2', 'c3', 'c4']:
        print(f"\nMerging condition: {condition}")

        merged_cases = []

        for server_dir in server_dirs:
            result_files = list(server_dir.glob(f'{condition}_server*_results.json'))

            for result_file in result_files:
                if not result_file.exists():
                    continue

                print(f"  Reading: {result_file.name}")
                with open(result_file, 'r') as f:
                    data = json.load(f)

                cases = data.get('cases', [])
                merged_cases.extend(cases)
                print(f"    Added {len(cases)} cases")

        if not merged_cases:
            print(f"  ⚠️  No results found for {condition}")
            continue

        # 메트릭 재계산
        metrics = _recalculate_metrics(merged_cases)

        # 저장
        output_file = output_dir / f'{condition}_merged_results.json'
        merged_result = {
            'cases': merged_cases,
            'metrics': metrics
        }

        with open(output_file, 'w') as f:
            json.dump(merged_result, f, indent=2)

        print(f"  ✅ {condition}: {len(merged_cases)} cases, "
              f"success rate: {metrics.get('success_rate', 0):.1%}")

    # 불완전 패치 병합
    print("\nMerging incomplete patches...")
    merged_incomplete = {}

    for server_dir in server_dirs:
        incomplete_files = list(server_dir.glob('incomplete_patches_server*.json'))

        for incomplete_file in incomplete_files:
            if not incomplete_file.exists():
                continue

            print(f"  Reading: {incomplete_file.name}")
            with open(incomplete_file, 'r') as f:
                data = json.load(f)

            for case_id, patches in data.items():
                if case_id not in merged_incomplete:
                    merged_incomplete[case_id] = []
                merged_incomplete[case_id].extend(patches)

    if merged_incomplete:
        output_file = output_dir / 'incomplete_patches_merged.json'
        with open(output_file, 'w') as f:
            json.dump(merged_incomplete, f, indent=2)

        total_patches = sum(len(p) for p in merged_incomplete.values())
        print(f"  ✅ Incomplete patches: {len(merged_incomplete)} cases, "
              f"{total_patches} patches")

    print("\n" + "="*80)
    print("✅ MERGE COMPLETE")
    print("="*80)
    print(f"\nResults saved to: {output_dir}/")
    print("\nNext steps:")
    print("  # Run RQ analysis")
    print(f"  python3 scripts/run_rq_analysis.py {output_dir}/c4_merged_results.json")


def _recalculate_metrics(cases: List[Dict]) -> Dict:
    """메트릭 재계산"""
    if not cases:
        return {}

    total = len(cases)
    successes = sum(1 for c in cases if c.get('actual_success', False))

    ground_truth_matches = 0
    ground_truth_total = 0
    for case in cases:
        patch_summary = case.get('patch', {})
        matches = patch_summary.get('matches_ground_truth')
        if matches is not None:
            ground_truth_total += 1
            if matches:
                ground_truth_matches += 1

    first_attempt_successes = sum(
        1 for c in cases if c.get('first_attempt_success', False)
    )
    first_attempt_count = sum(
        1 for c in cases if c.get('first_attempt_success') is not None
    )

    consistency_passes = sum(
        1 for c in cases
        if c.get('consistency', {}).get('overall', False)
    )
    consistency_count = sum(
        1 for c in cases if c.get('consistency') is not None
    )

    # AST similarity
    ast_count = 0
    ast_overall = 0.0
    ast_structural = 0.0
    ast_token = 0.0

    for case in cases:
        if case.get('ast_similarity'):
            ast_count += 1
            ast_overall += case['ast_similarity'].get('overall_similarity', 0.0)
            ast_structural += case['ast_similarity'].get('structural_similarity', 0.0)
            ast_token += case['ast_similarity'].get('token_similarity', 0.0)

    metrics = {
        "total_cases": float(total),
        "success_rate": successes / total if total else 0.0,
        "ground_truth_match_rate": ground_truth_matches / ground_truth_total if ground_truth_total else 0.0,
        "first_attempt_success_rate": first_attempt_successes / first_attempt_count if first_attempt_count else 0.0,
        "consistency_pass_rate": consistency_passes / consistency_count if consistency_count else 0.0,
    }

    if ast_count > 0:
        metrics.update({
            "avg_ast_overall_similarity": ast_overall / ast_count,
            "avg_ast_structural_similarity": ast_structural / ast_count,
            "avg_ast_token_similarity": ast_token / ast_count,
        })

    return metrics


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Merge results from distributed servers')
    parser.add_argument('--results-dir', type=Path, default=Path('results'),
                       help='Base results directory (default: results)')
    parser.add_argument('--output', type=Path, default=Path('results/merged'),
                       help='Output directory for merged results')

    args = parser.parse_args()

    # results/server* 디렉토리 찾기
    server_dirs = sorted(args.results_dir.glob('server*'))

    if not server_dirs:
        print(f"❌ No server directories found in {args.results_dir}/")
        print("\nExpected structure:")
        print("  results/")
        print("    server0/")
        print("    server1/")
        print("    server2/")
        print("    ...")
        sys.exit(1)

    print(f"Found {len(server_dirs)} server directories:")
    for d in server_dirs:
        print(f"  - {d.name}")
    print()

    merge_results(server_dirs, args.output)


if __name__ == '__main__':
    main()
