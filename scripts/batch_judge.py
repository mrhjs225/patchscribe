#!/usr/bin/env python3
"""
배치 모드로 GPT Judge 평가를 수행하는 유틸리티

기존 실험 결과 파일을 읽어서 설명이 있지만 LLM 점수가 없는 케이스를
찾아 배치로 평가를 진행합니다.

사용 예시:
    # 단일 결과 파일 평가
    python3 scripts/batch_judge.py results/local/llama3.2:3b/c4_results.json

    # 디렉토리 내 모든 결과 파일 평가
    python3 scripts/batch_judge.py results/local/llama3.2:3b/

    # 배치 크기 조정 (동시 요청 수)
    python3 scripts/batch_judge.py results/local/ --batch-size 10

    # Dry run (평가할 케이스만 확인)
    python3 scripts/batch_judge.py results/local/ --dry-run
"""
import json
import sys
from pathlib import Path
from typing import List, Dict, Tuple
import argparse

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from patchscribe.llm import LLMClient
from patchscribe.explanation_quality import ExplanationEvaluator


def find_cases_needing_evaluation(result_file: Path) -> List[Tuple[str, Dict]]:
    """Find cases that have explanations but no LLM scores"""
    try:
        with open(result_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading {result_file}: {e}")
        return []

    cases = data.get('cases', [])
    needs_eval = []

    for case in cases:
        case_id = case.get('case_id', 'unknown')
        explanation_metrics = case.get('explanation_metrics', {})
        explanations = case.get('explanations', {})

        # Check if has explanation but no LLM scores
        has_explanation = bool(
            explanations.get('natural_llm') or
            explanations.get('natural_template')
        )
        has_llm_scores = bool(explanation_metrics.get('llm_scores'))

        if has_explanation and not has_llm_scores:
            needs_eval.append((case_id, case))

    return needs_eval


def build_evaluation_prompts(cases: List[Tuple[str, Dict]]) -> List[Tuple[str, str]]:
    """Build evaluation prompts for each case

    Returns:
        List of (case_id, prompt) tuples
    """
    evaluator = ExplanationEvaluator()
    prompts = []

    for case_id, case in cases:
        explanations = case.get('explanations', {})
        text = explanations.get('natural_llm') or explanations.get('natural_template', '')

        if not text.strip():
            continue

        # Build prompt using the same format as ExplanationEvaluator
        prompt = evaluator._build_judge_prompt(text, case)
        prompts.append((case_id, prompt))

    return prompts


def batch_evaluate(
    result_file: Path,
    batch_size: int = 5,
    dry_run: bool = False,
    verbose: bool = True
) -> int:
    """Evaluate a single result file with batch processing

    Returns:
        Number of cases updated
    """
    if verbose:
        print(f"\n📄 Processing: {result_file}")

    # Find cases needing evaluation
    cases_to_eval = find_cases_needing_evaluation(result_file)

    if not cases_to_eval:
        if verbose:
            print(f"   ✓ No cases need evaluation")
        return 0

    if verbose:
        print(f"   Found {len(cases_to_eval)} cases needing evaluation")

    if dry_run:
        for case_id, _ in cases_to_eval:
            print(f"      - {case_id}")
        return 0

    # Build prompts
    if verbose:
        print(f"   Building evaluation prompts...")

    prompts_data = build_evaluation_prompts(cases_to_eval)

    if not prompts_data:
        if verbose:
            print(f"   ⚠️  No valid prompts to evaluate")
        return 0

    # Batch evaluate
    if verbose:
        print(f"   Evaluating {len(prompts_data)} cases (batch_size={batch_size})...")

    case_ids = [case_id for case_id, _ in prompts_data]
    prompts = [prompt for _, prompt in prompts_data]

    try:
        responses = LLMClient.batch_score_explanations(prompts, max_workers=batch_size)
    except Exception as e:
        print(f"   ❌ Batch evaluation failed: {e}")
        return 0

    # Parse responses and update results
    if verbose:
        print(f"   Parsing responses and updating results...")

    evaluator = ExplanationEvaluator()
    updates = 0

    # Load original data
    with open(result_file, 'r') as f:
        data = json.load(f)

    # Update cases with new scores
    for case_id, response in zip(case_ids, responses):
        if response is None:
            continue

        # Parse the response
        try:
            scores = evaluator._parse_llm_scores(response)
            if not scores:
                continue

            # Find and update the case
            for case in data.get('cases', []):
                if case.get('case_id') == case_id:
                    if 'explanation_metrics' not in case:
                        case['explanation_metrics'] = {}
                    case['explanation_metrics']['llm_scores'] = scores
                    case['explanation_metrics']['llm_raw_response'] = response
                    updates += 1
                    break

        except Exception as e:
            if verbose:
                print(f"      ⚠️  Failed to parse response for {case_id}: {e}")
            continue

    if updates > 0:
        # Save updated results
        backup_file = result_file.with_suffix('.json.backup')
        if verbose:
            print(f"   Backing up to: {backup_file.name}")

        # Create backup
        result_file.rename(backup_file)

        # Save updated file
        with open(result_file, 'w') as f:
            json.dump(data, f, indent=2)

        # Recalculate metrics if needed
        if 'metrics' in data:
            from patchscribe.evaluation import Evaluator, CaseEvaluation

            # Rebuild case evaluations from dict
            cases = []
            for case_dict in data['cases']:
                # Simple conversion - just extract needed fields
                cases.append(CaseEvaluation(
                    case_id=case_dict.get('case_id', ''),
                    expected_success=case_dict.get('expected_success', False),
                    actual_success=case_dict.get('actual_success', False),
                    verification=case_dict.get('verification', {}),
                    patch_summary=case_dict.get('patch', {}),
                    effect=case_dict.get('effect', {}),
                    iterations=case_dict.get('iterations', []),
                    explanations=case_dict.get('explanations', {}),
                    explanation_metrics=case_dict.get('explanation_metrics', {}),
                    consistency=case_dict.get('consistency'),
                    first_attempt_success=case_dict.get('first_attempt_success'),
                    performance=case_dict.get('performance'),
                    patch_quality=case_dict.get('patch_quality'),
                    ast_similarity=case_dict.get('ast_similarity'),
                    success_judgment=case_dict.get('success_judgment'),
                ))

            # Recalculate metrics
            evaluator_obj = Evaluator()
            new_metrics = evaluator_obj._compute_metrics(cases)
            data['metrics'] = new_metrics

            # Save again with updated metrics
            with open(result_file, 'w') as f:
                json.dump(data, f, indent=2)

        if verbose:
            print(f"   ✅ Updated {updates} cases")

    return updates


def main():
    parser = argparse.ArgumentParser(
        description='배치 모드로 GPT Judge 평가 수행',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:

1. 단일 결과 파일 평가:
   python3 scripts/batch_judge.py results/local/llama3.2:3b/c4_results.json

2. 디렉토리 내 모든 결과 파일 평가:
   python3 scripts/batch_judge.py results/local/llama3.2:3b/

3. 배치 크기 조정 (동시 요청 10개):
   python3 scripts/batch_judge.py results/local/ --batch-size 10

4. Dry run (평가할 케이스만 확인):
   python3 scripts/batch_judge.py results/local/ --dry-run
        """
    )

    parser.add_argument(
        'path',
        type=Path,
        help='결과 파일 또는 디렉토리 경로'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        default=5,
        help='동시 요청 수 (기본값: 5)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='실제 평가 없이 평가할 케이스만 확인'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='최소 출력 모드'
    )

    args = parser.parse_args()

    # Validate path
    if not args.path.exists():
        print(f"❌ Path not found: {args.path}")
        sys.exit(1)

    # Find result files
    if args.path.is_file():
        result_files = [args.path]
    else:
        result_files = list(args.path.rglob("*_results.json"))

        if not result_files:
            print(f"❌ No result files found in {args.path}")
            sys.exit(1)

    if not args.quiet:
        print(f"\n{'=' * 70}")
        print(f"  Batch Judge Evaluation")
        print(f"{'=' * 70}")
        print(f"\nFound {len(result_files)} result file(s)")
        print(f"Batch size: {args.batch_size}")
        if args.dry_run:
            print("Mode: DRY RUN (no actual evaluation)")
        print()

    # Process each file
    total_updated = 0
    for result_file in result_files:
        try:
            updated = batch_evaluate(
                result_file,
                batch_size=args.batch_size,
                dry_run=args.dry_run,
                verbose=not args.quiet
            )
            total_updated += updated
        except Exception as e:
            print(f"❌ Error processing {result_file}: {e}")
            import traceback
            traceback.print_exc()
            continue

    # Summary
    if not args.quiet:
        print(f"\n{'=' * 70}")
        print(f"  Summary")
        print(f"{'=' * 70}")
        print(f"Files processed: {len(result_files)}")
        if not args.dry_run:
            print(f"Total cases updated: {total_updated}")
        print()


if __name__ == '__main__':
    main()
