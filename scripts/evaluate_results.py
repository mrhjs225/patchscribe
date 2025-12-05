#!/usr/bin/env python3
"""
Post-hoc evaluation script for PatchScribe results.

This script loads saved experiment results (patches + explanations) and applies
LLM judge evaluation using gpt-5-mini:
1. Success judgment (SynEq/SemEq/Plausible)
2. Explanation quality scoring

Usage:
    # Evaluate all results in a directory
    python scripts/evaluate_results.py results/experiment

    # Specify output directory
    python scripts/evaluate_results.py results/experiment --output results/evaluated
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

try:
    from tqdm import tqdm
except ImportError:
    # Fallback if tqdm is not installed
    def tqdm(iterable, **kwargs):
        return iterable

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from patchscribe.llm import LLMClient, LLMConfig
from patchscribe.success_judge import PatchSuccessJudge
from patchscribe.evaluation.manual_rubric import (
    InterRaterReliability,
    load_manual_evaluations_from_csv,
    manual_evaluation_to_dict,
)


class ResultEvaluator:
    """Evaluates saved experiment results with LLM judges."""

    def __init__(
        self,
        *,
        batch_size: int = 5,
        manual_eval_files: Optional[List[Path]] = None,
    ):
        """
        Args:
            batch_size: Batch size for parallel evaluation
        """
        self.batch_size = batch_size
        self.manual_eval_files = [Path(p) for p in manual_eval_files] if manual_eval_files else []

        # Initialize success judge with gpt-5-mini only
        self.success_judge = PatchSuccessJudge()
        self.manual_evaluations = self._load_manual_evaluations()
        self.manual_eval_index = self._index_manual_evaluations()

        print(f"[OK] Initialized evaluator with judge: gpt-5-mini")
        print(f"   Voting method: single judge")

    def evaluate_file(
        self,
        input_file: Path,
        output_file: Path,
        *,
        skip_success: bool = False,
        skip_explanation: bool = False,
    ) -> None:
        """
        Evaluate a single result file.

        Args:
            input_file: Path to experiment result JSON
            output_file: Path to save evaluated result JSON
            skip_success: Skip success judgment evaluation
            skip_explanation: Skip explanation quality evaluation
        """
        print(f"\n{'='*80}")
        print(f"[DIR] Loading: {input_file}")

        # Load experiment results
        with open(input_file, 'r') as f:
            data = json.load(f)

        cases = data.get('cases', [])
        if not cases:
            print(f"  [WARN]  No cases found in {input_file}")
            return

        print(f"  [ANALYZE] Found {len(cases)} cases")

        # Evaluate success judgments
        if not skip_success:
            print(f"\n[SEARCH] Evaluating success judgments...")
            self._evaluate_success_batch(cases)

        # Evaluate explanation quality
        if not skip_explanation:
            print(f"\n[EVAL] Evaluating explanation quality...")
            self._evaluate_explanations_batch(cases)

        # Recalculate metrics
        print(f"\n[ANALYZE] Recalculating metrics...")
        data['metrics'] = self._compute_metrics(cases)

        # Add evaluation metadata
        data['evaluation_metadata'] = {
            'input_file': str(input_file),
            'evaluation_timestamp': datetime.now().isoformat(),
            'judge': 'gpt-5-mini',
            'voting_method': 'single',
            'success_evaluated': not skip_success,
            'explanation_evaluated': not skip_explanation,
        }

        self._inject_manual_reviews(cases, data)

        # Save evaluated results
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"\n[OK] Saved evaluated results to: {output_file}")
        print(f"   Success rate: {data['metrics'].get('success_rate', 0):.1%}")
        print(f"   Cases evaluated: {len(cases)}")

    def _evaluate_success_batch(self, cases: List[Dict]) -> None:
        """Evaluate success judgments for all cases in parallel."""
        evaluated_count = 0
        skipped_count = 0

        # Prepare evaluation tasks
        eval_tasks = []
        for idx, case in enumerate(cases):
            # Skip if already has success judgment from experiment
            if case.get('success_judgment'):
                skipped_count += 1
                continue

            # Extract required data
            iterations = case.get('iterations', [])
            if not iterations:
                continue

            first_iter = iterations[0]
            original_code = first_iter.get('original_code', '')
            patched_code = first_iter.get('patched_code', '')
            ground_truth = case.get('ground_truth')
            vulnerability_sig = first_iter.get('vulnerability_signature', '')

            # Get description hint from explanations
            explanations = case.get('explanations', {})
            description_hint = (
                explanations.get('natural_llm', '')
                or explanations.get('natural_template', '')
                or explanations.get('formal_summary', '')
                or None
            )

            if not original_code or not patched_code:
                continue

            eval_tasks.append((idx, case, original_code, patched_code, ground_truth, vulnerability_sig, description_hint))

        if not eval_tasks:
            if skipped_count > 0:
                print(f"  [SKIP]  Skipped: {skipped_count} cases (already evaluated)")
            return

        # Evaluate in parallel using ThreadPoolExecutor
        def evaluate_single(task):
            idx, case, original_code, patched_code, ground_truth, vulnerability_sig, description_hint = task
            try:
                verdict = self.success_judge.evaluate(
                    original_code=original_code,
                    patched_code=patched_code,
                    ground_truth=ground_truth,
                    vulnerability_signature=vulnerability_sig,
                    description=description_hint,
                )
                return idx, case, verdict, None
            except Exception as e:
                return idx, case, None, e

        # Use ThreadPoolExecutor for parallel evaluation
        with ThreadPoolExecutor(max_workers=self.batch_size) as executor:
            futures = [executor.submit(evaluate_single, task) for task in eval_tasks]

            # Process results with progress bar
            for future in tqdm(as_completed(futures), total=len(futures), desc="  Evaluating success", unit="case"):
                idx, case, verdict, error = future.result()

                if error:
                    print(f"  [WARN]  Error evaluating case {idx}: {error}")
                    continue

                if verdict:
                    # Update case
                    case['success_judgment'] = verdict.as_dict()
                    case['actual_success'] = verdict.is_success
                    evaluated_count += 1

        print(f"  [OK] Evaluated: {evaluated_count} cases")
        if skipped_count > 0:
            print(f"  [SKIP]  Skipped: {skipped_count} cases (already evaluated)")

    def _evaluate_explanations_batch(self, cases: List[Dict]) -> None:
        """Evaluate explanation quality for all cases."""
        # Build prompts for all cases with explanations
        prompts = []
        valid_indices = []

        for idx, case in enumerate(cases):
            explanations = case.get('explanations', {})
            ebug = explanations.get('E_bug')
            epatch = explanations.get('E_patch')

            # Skip if no explanations
            if not ebug or not epatch:
                continue

            # Extract text
            ebug_text = ebug.get('text', '') if isinstance(ebug, dict) else str(ebug)
            epatch_text = epatch.get('text', '') if isinstance(epatch, dict) else str(epatch)

            if not ebug_text or not epatch_text:
                continue

            # Get case data
            iterations = case.get('iterations', [])
            if not iterations:
                continue

            first_iter = iterations[0]
            original_code = first_iter.get('original_code', '')
            patched_code = first_iter.get('patched_code', '')
            vulnerability_sig = first_iter.get('vulnerability_signature', '')

            if not original_code or not patched_code:
                continue

            # Build judge prompt
            prompt = LLMClient.build_explanation_judge_prompt(
                ebug_text=ebug_text,
                epatch_text=epatch_text,
                vulnerability_signature=vulnerability_sig,
                original_code=original_code,
                patched_code=patched_code,
            )

            prompts.append(prompt)
            valid_indices.append(idx)

        if not prompts:
            print(f"  [WARN]  No valid explanations to evaluate")
            return

        print(f"  [EVAL] Evaluating {len(prompts)} explanations with gpt-5-mini...")

        # Single judge evaluation with gpt-5-mini
        scores = LLMClient.batch_score_explanations(prompts, max_workers=self.batch_size, judge_model='gpt')

        # Parse scores and update cases
        success_count = 0
        for idx, score_text in zip(valid_indices, scores):
            if not score_text:
                continue

            try:
                score_data = json.loads(score_text)

                # Update explanation_metrics
                case = cases[idx]
                if 'explanation_metrics' not in case:
                    case['explanation_metrics'] = {}
                if 'llm_scores' not in case['explanation_metrics']:
                    case['explanation_metrics']['llm_scores'] = {}

                # Support both old and new field names
                has_new_format = any(k in score_data for k in [
                    'vulnerability_understanding',
                    'patch_understanding',
                    'causal_connection',
                    'actionability'
                ])

                if has_new_format:
                    case['explanation_metrics']['llm_scores'].update({
                        'vulnerability_understanding': float(score_data.get('vulnerability_understanding', 0)),
                        'patch_understanding': float(score_data.get('patch_understanding', 0)),
                        'causal_connection': float(score_data.get('causal_connection', 0)),
                        'actionability': float(score_data.get('actionability', 0)),
                        'reasoning': score_data.get('reasoning', ''),
                    })
                else:
                    case['explanation_metrics']['llm_scores'].update({
                        'accuracy': float(score_data.get('accuracy', 0)),
                        'completeness': float(score_data.get('completeness', 0)),
                        'clarity': float(score_data.get('clarity', 0)),
                        'causality': float(score_data.get('causality', 0)),
                        'reasoning': score_data.get('reasoning', ''),
                    })

                success_count += 1
            except (json.JSONDecodeError, ValueError, KeyError) as e:
                print(f"  [WARN]  Failed to parse judge response for case {case.get('case_id', idx)}: {e}")
                continue

        print(f"  [OK] Successfully evaluated {success_count}/{len(prompts)} explanations")

    def _load_manual_evaluations(self) -> List:
        """Load manual rubric rows from provided CSV files."""
        evaluations = []
        for path in self.manual_eval_files:
            if not path.exists():
                print(f"[WARN] Manual evaluation file not found: {path}")
                continue
            try:
                loaded = load_manual_evaluations_from_csv(path)
                evaluations.extend(loaded)
                print(f"[OK] Loaded {len(loaded)} manual reviews from {path.name}")
            except Exception as exc:
                print(f"[WARN] Failed to load manual evaluations from {path}: {exc}")
        return evaluations

    def _index_manual_evaluations(self) -> Dict[str, List]:
        """Group manual evaluations by case ID for quick lookup."""
        index: Dict[str, List] = {}
        for evaluation in self.manual_evaluations:
            index.setdefault(evaluation.case_id, []).append(evaluation)
        return index

    def _inject_manual_reviews(self, cases: List[Dict], data: Dict[str, object]) -> None:
        """Attach manual evaluations to matching cases and record summary stats."""
        if not self.manual_eval_index:
            return

        attached_cases = 0
        overall_scores: List[float] = []

        for case in cases:
            case_id = case.get('case_id') or case.get('id') or case.get('filename')
            if not case_id:
                continue
            reviews = self.manual_eval_index.get(case_id)
            if not reviews:
                continue
            case['manual_reviews'] = [manual_evaluation_to_dict(review) for review in reviews]
            attached_cases += 1
            overall_scores.extend(review.overall_score for review in reviews)

        summary: Dict[str, object] = {
            'cases_with_manual_reviews': attached_cases,
            'total_manual_reviews': len(self.manual_evaluations),
        }
        if overall_scores:
            summary['mean_overall_score'] = sum(overall_scores) / len(overall_scores)
        if len(self.manual_evaluations) >= 2:
            summary['cohens_kappa'] = InterRaterReliability.calculate_all_kappas(self.manual_evaluations)

        data['manual_evaluation_summary'] = summary

    @staticmethod
    def _find_latest_results(input_path: Path) -> List[Path]:
        """
        Find the latest result files for each model in the input directory.

        For a directory structure like:
            results/local_extractfix/
            ├── gpt-5-mini/
            │   ├── 20251109-120000/
            │   └── 20251109-235959/  ← latest
            ├── claude-haiku-4-5/
            │   └── 20251109-234530/  ← latest
            └── gemini-2.5-flash/
                └── 20251109-222224/  ← latest

        This returns only files from the latest timestamp directory for each model.

        Args:
            input_path: Root directory containing model subdirectories

        Returns:
            List of result file paths from latest runs only
        """
        result_files = []

        # Check if this looks like a top-level results directory
        # (contains model subdirectories like gpt-5-mini, claude-haiku-4-5, etc.)
        potential_model_dirs = [d for d in input_path.iterdir() if d.is_dir()]

        # If no subdirectories, or if subdirectories look like timestamp dirs,
        # fall back to recursive search
        if not potential_model_dirs:
            return list(input_path.rglob('*_results.json'))

        # Check if first-level subdirs look like timestamp directories (YYYYMMDD-HHMMSS pattern)
        # If so, we're already in a model directory, so just search recursively
        first_subdir_name = potential_model_dirs[0].name
        if '-' in first_subdir_name and first_subdir_name[0].isdigit():
            # Already in a model or timestamp directory
            return list(input_path.rglob('*_results.json'))

        # Otherwise, assume we're at the top level with model subdirectories
        for model_dir in potential_model_dirs:
            # Find all timestamp directories within this model directory
            timestamp_dirs = [d for d in model_dir.iterdir() if d.is_dir()]

            if not timestamp_dirs:
                continue

            # Sort timestamp directories by name (YYYYMMDD-HHMMSS format sorts correctly)
            # Latest timestamp will be last, so iterate in reverse to find latest with results
            timestamp_dirs.sort(reverse=True)

            # Find the latest directory that actually has result files
            latest_dir = None
            for dir_candidate in timestamp_dirs:
                result_files_in_dir = list(dir_candidate.glob('*_results.json'))
                if result_files_in_dir:
                    latest_dir = dir_candidate
                    break

            # Skip this model if no results found in any timestamp directory
            if not latest_dir:
                print(f"  [WARN]  {model_dir.name}: no result files found in any timestamp directory")
                continue

            # Collect all *_results.json files from the latest directory
            latest_results = list(latest_dir.glob('*_results.json'))
            result_files.extend(latest_results)

            if latest_results:
                print(f"  [NOTE] {model_dir.name}: using latest run {latest_dir.name} ({len(latest_results)} files)")

        return result_files

    @staticmethod
    def _compute_metrics(cases: List[Dict]) -> Dict[str, float]:
        """Compute evaluation metrics from cases."""
        total = len(cases)
        if total == 0:
            return {}

        # Success metrics
        successes = sum(1 for c in cases if c.get('actual_success', False))

        # Explanation metrics
        llm_totals = {
            'vulnerability_understanding': 0.0,
            'patch_understanding': 0.0,
            'causal_connection': 0.0,
            'actionability': 0.0,
        }
        llm_count = 0

        for case in cases:
            exp_metrics = case.get('explanation_metrics', {})
            llm_scores = exp_metrics.get('llm_scores', {})

            if llm_scores:
                for key in llm_totals:
                    if key in llm_scores:
                        llm_totals[key] += float(llm_scores[key])
                        llm_count = max(llm_count, 1)

        metrics = {
            'total_cases': float(total),
            'success_rate': successes / total if total > 0 else 0.0,
        }

        if llm_count > 0:
            for key, total_score in llm_totals.items():
                metrics[f'avg_{key}'] = total_score / llm_count

        return metrics


def main():
    parser = argparse.ArgumentParser(
        description='Post-hoc evaluation of PatchScribe experiment results with gpt-5-mini',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:

1. Evaluate all results in a directory:
   python scripts/evaluate_results.py results/local

2. Specify output directory:
   python scripts/evaluate_results.py results/local --output results/evaluated

3. Increase concurrency for faster evaluation:
   python scripts/evaluate_results.py results/local --concurrency 20
        """
    )

    parser.add_argument(
        'input_path',
        type=Path,
        help='Input directory or result JSON file (will auto-discover *_results.json files)'
    )
    parser.add_argument(
        '--output',
        type=Path,
        help='Output directory (default: input_path with _evaluated suffix)'
    )
    parser.add_argument(
        '--concurrency',
        type=int,
        default=5,
        help='Number of parallel judge requests (default: 5). Higher values = faster but more API load'
    )
    parser.add_argument(
        '--manual-evals',
        nargs='+',
        type=Path,
        help='One or more CSV files containing manual rubric evaluations to merge'
    )

    args = parser.parse_args()

    # Auto-discover input files
    input_path = args.input_path
    input_files = []

    if input_path.is_file():
        # Single file specified
        input_files.append(input_path)
        print(f"[LIST] Evaluating single file: {input_path.name}")
    elif input_path.is_dir():
        # Directory specified - find latest results for each model
        print(f"[SEARCH] Searching for latest results in: {input_path}")
        input_files = ResultEvaluator._find_latest_results(input_path)

        if input_files:
            print(f"[LIST] Found {len(input_files)} result files from latest runs")
    else:
        print(f"[ERROR] Input path not found: {input_path}")
        sys.exit(1)

    if not input_files:
        print(f"[ERROR] No *_results.json files found in: {input_path}")
        sys.exit(1)

    # Determine output directory
    if args.output:
        output_dir = args.output
    else:
        # Default: add _evaluated suffix to the input directory name
        # Example: results/local -> results/local_evaluated
        #          results/local_extractfix -> results/local_extractfix_evaluated
        if input_path.is_file():
            # For single file: parent_dir_evaluated
            parent_dir = input_path.parent
            output_dir = parent_dir.parent / f"{parent_dir.name}_evaluated"
        else:
            # For directory: dirname_evaluated
            output_dir = input_path.parent / f"{input_path.name}_evaluated"

    print(f"[DIR] Output directory: {output_dir}")
    print(f"   Input structure will be preserved under output directory")

    # Initialize evaluator (use only gpt-5-mini)
    evaluator = ResultEvaluator(
        batch_size=args.concurrency,
        manual_eval_files=args.manual_evals,
    )

    # Process files in parallel
    def process_single_file(input_file: Path):
        try:
            # Generate output filename
            # Example: c4_results.json -> c4_evaluated.json
            output_name = input_file.stem.replace('_results', '_evaluated') + '.json'

            # Preserve directory structure relative to input_path
            if input_path.is_dir():
                relative_path = input_file.relative_to(input_path)
                output_file = output_dir / relative_path.parent / output_name
            else:
                output_file = output_dir / output_name

            # Evaluate
            evaluator.evaluate_file(
                input_file,
                output_file,
                skip_success=False,
                skip_explanation=False,
            )
            return input_file, None
        except Exception as e:
            import traceback
            return input_file, (e, traceback.format_exc())

    # Determine max workers for file-level parallelization
    # Use min of: number of files, concurrency setting, or reasonable max (e.g., 4)
    max_file_workers = min(len(input_files), 4)

    print(f"[FAST] Processing {len(input_files)} files with {max_file_workers} parallel workers")

    # Process all files in parallel
    with ThreadPoolExecutor(max_workers=max_file_workers) as executor:
        futures = [executor.submit(process_single_file, f) for f in input_files]

        for future in tqdm(as_completed(futures), total=len(futures), desc="Processing files", unit="file"):
            input_file, error = future.result()
            if error:
                exc, trace = error
                print(f"[ERROR] Error processing {input_file}: {exc}")
                print(trace)

    print(f"\n{'='*80}")
    print(f"[OK] Evaluation complete! Results saved to: {output_dir}")


if __name__ == '__main__':
    main()
