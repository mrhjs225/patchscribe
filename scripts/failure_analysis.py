#!/usr/bin/env python3
"""
Failure Analysis Tool for PatchScribe

Systematically categorizes and analyzes failure cases to identify
patterns and inform future improvements.

Usage:
    python scripts/failure_analysis.py --input results/final_*/unified --output results/failure_report.md
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List
from collections import defaultdict, Counter


def load_results(unified_dir: Path) -> List[Dict]:
    """Load all results from unified directory"""
    all_results = []

    for result_file in unified_dir.glob("*_results.json"):
        with open(result_file, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                all_results.extend(data)
            elif isinstance(data, dict) and 'results' in data:
                all_results.extend(data['results'])

    return all_results


def categorize_failure(result: Dict) -> str:
    """Categorize failure reason"""
    if result.get('actual_success', False):
        return 'success'

    patch = result.get('patch', {})

    # Check patch generation issues
    if not patch:
        return 'no_patch_object'

    method = patch.get('method', '')
    if method == 'noop':
        return 'noop_method'

    diff = patch.get('diff', '')
    if not diff or not diff.strip():
        return 'empty_diff'

    patched_code = patch.get('patched_code', '')
    if not patched_code or not patched_code.strip():
        return 'empty_patched_code'

    # Check consistency issues (C4 only)
    consistency = result.get('consistency', {})
    if consistency and not consistency.get('accepted', True):
        # Detailed consistency failure reasons
        if not consistency.get('causal_coverage', {}).get('success', True):
            return 'consistency_causal_coverage'
        if not consistency.get('intervention_validity', {}).get('success', True):
            return 'consistency_intervention_validity'
        return 'consistency_failure'

    # Check semantic equivalence
    if not result.get('matches_ground_truth', False):
        return 'semantic_mismatch'

    # Default: unknown failure
    return 'unknown_failure'


def main():
    parser = argparse.ArgumentParser(description="Failure analysis for PatchScribe")
    parser.add_argument('--input', type=str, required=True,
                        help='Path to unified results directory')
    parser.add_argument('--output', type=str, required=True,
                        help='Output markdown file for failure report')

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input path {input_path} does not exist")
        sys.exit(1)

    # Load results
    print(f"Loading results from {input_path}...")
    results = load_results(input_path)

    if not results:
        print("Error: No results found")
        sys.exit(1)

    # Categorize failures
    failures_by_reason = defaultdict(list)
    failures_by_cwe = defaultdict(list)
    failures_by_condition = defaultdict(list)

    total_cases = len(results)
    success_count = sum(1 for r in results if r.get('actual_success', False))
    failure_count = total_cases - success_count

    for result in results:
        reason = categorize_failure(result)

        if reason != 'success':
            failures_by_reason[reason].append(result)

            cwe = result.get('cwe', 'Unknown')
            failures_by_cwe[cwe].append(result)

            condition = result.get('condition', 'unknown')
            failures_by_condition[condition].append(result)

    # Write report
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("# Failure Analysis Report - PatchScribe\n\n")
        f.write("## Overview\n\n")
        f.write(f"- **Total cases**: {total_cases}\n")
        f.write(f"- **Successful**: {success_count} ({success_count/total_cases*100:.1f}%)\n")
        f.write(f"- **Failed**: {failure_count} ({failure_count/total_cases*100:.1f}%)\n\n")

        # Failure reasons
        f.write("## Failure Reasons\n\n")
        f.write("| Reason | Count | Percentage |\n")
        f.write("|--------|-------|------------|\n")

        for reason, cases in sorted(failures_by_reason.items(),
                                    key=lambda x: -len(x[1])):
            count = len(cases)
            pct = count / failure_count * 100 if failure_count > 0 else 0
            f.write(f"| {reason} | {count} | {pct:.1f}% |\n")

        f.write("\n")

        # Detailed failure descriptions
        f.write("## Failure Category Descriptions\n\n")

        category_descriptions = {
            'noop_method': "패치 생성 시도 없음 (method='noop'). LLM이 패치를 생성하지 않았음.",
            'empty_diff': "코드 변경 없음 (diff가 비어있음). 패치가 아무것도 수정하지 않았음.",
            'empty_patched_code': "패치된 코드가 비어있음. 코드 추출 실패 가능성.",
            'consistency_causal_coverage': "일관성 검사 실패: 인과 경로 커버리지 부족.",
            'consistency_intervention_validity': "일관성 검사 실패: intervention 유효성 문제.",
            'consistency_failure': "일관성 검사 실패 (일반).",
            'semantic_mismatch': "의미적 동등성 실패. 패치가 생성되었으나 ground truth와 다름.",
            'no_patch_object': "패치 객체 자체가 없음. 시스템 오류 가능성.",
            'unknown_failure': "분류되지 않은 실패 유형."
        }

        for reason in sorted(failures_by_reason.keys()):
            desc = category_descriptions.get(reason, "설명 없음")
            count = len(failures_by_reason[reason])
            f.write(f"### {reason}\n\n")
            f.write(f"- **설명**: {desc}\n")
            f.write(f"- **발생 횟수**: {count}\n\n")

        # CWE distribution of failures
        f.write("## Failures by CWE Type\n\n")
        f.write("| CWE | Failures | Success Rate |\n")
        f.write("|-----|----------|-------------|\n")

        # Count total per CWE
        total_by_cwe = defaultdict(int)
        for result in results:
            cwe = result.get('cwe', 'Unknown')
            total_by_cwe[cwe] += 1

        for cwe in sorted(failures_by_cwe.keys(),
                         key=lambda x: -len(failures_by_cwe[x])):
            fail_count = len(failures_by_cwe[cwe])
            total = total_by_cwe[cwe]
            success_rate = (total - fail_count) / total * 100 if total > 0 else 0

            f.write(f"| {cwe} | {fail_count}/{total} | {success_rate:.1f}% |\n")

        f.write("\n")

        # Condition-specific failures
        f.write("## Failures by Condition\n\n")
        f.write("| Condition | Failures | Total | Failure Rate |\n")
        f.write("|-----------|----------|-------|-------------|\n")

        # Count total per condition
        total_by_condition = defaultdict(int)
        for result in results:
            condition = result.get('condition', 'unknown')
            total_by_condition[condition] += 1

        for condition in sorted(failures_by_condition.keys()):
            fail_count = len(failures_by_condition[condition])
            total = total_by_condition[condition]
            fail_rate = fail_count / total * 100 if total > 0 else 0

            f.write(f"| {condition} | {fail_count} | {total} | {fail_rate:.1f}% |\n")

        f.write("\n")

        # Recommendations
        f.write("## Recommendations\n\n")

        if 'noop_method' in failures_by_reason and len(failures_by_reason['noop_method']) > failure_count * 0.2:
            f.write("- **High noop rate**: LLM이 패치를 생성하지 않는 경우가 많음. ")
            f.write("프롬프트를 더 명확하게 하거나, 예제를 추가할 필요가 있음.\n\n")

        if 'semantic_mismatch' in failures_by_reason and len(failures_by_reason['semantic_mismatch']) > failure_count * 0.3:
            f.write("- **High semantic mismatch**: 패치가 생성되지만 정확하지 않음. ")
            f.write("명세의 정확성을 높이거나, 검증 로직을 강화할 필요가 있음.\n\n")

        if any('consistency' in reason for reason in failures_by_reason.keys()):
            consistency_failures = sum(len(cases) for reason, cases in failures_by_reason.items()
                                     if 'consistency' in reason)
            if consistency_failures > failure_count * 0.1:
                f.write("- **Consistency check failures**: 일관성 검사가 너무 엄격할 수 있음. ")
                f.write("검사 기준을 재검토하거나, 명세 생성 단계를 개선할 필요가 있음.\n\n")

        # Top failing CWEs
        if failures_by_cwe:
            top_failing_cwes = sorted(failures_by_cwe.items(),
                                     key=lambda x: -len(x[1]))[:3]
            f.write("- **Most problematic CWE types**:\n")
            for cwe, cases in top_failing_cwes:
                count = len(cases)
                total = total_by_cwe[cwe]
                f.write(f"  - {cwe}: {count}/{total} failures ")
                f.write(f"({count/total*100:.1f}% failure rate)\n")

    print(f"\nFailure analysis complete. Report saved to: {output_path}")


if __name__ == "__main__":
    main()
