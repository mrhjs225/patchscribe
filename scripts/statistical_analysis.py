#!/usr/bin/env python3
"""
Statistical Analysis Tool for PatchScribe Experiments

This script performs rigorous statistical tests on experimental results
to establish significance of performance differences across conditions.

Usage:
    python scripts/statistical_analysis.py --input results/final_*/unified --output results/statistics.txt
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List
from collections import defaultdict

import numpy as np
from scipy.stats import ttest_rel, wilcoxon, friedmanchisquare
from scipy import stats

try:
    from statsmodels.stats.power import TTestIndPower
    POWER_ANALYSIS_AVAILABLE = True
except ImportError:
    POWER_ANALYSIS_AVAILABLE = False


def load_unified_results(unified_dir: Path) -> Dict[str, List[Dict]]:
    """Load unified results organized by condition"""
    results_by_condition = defaultdict(list)

    # Look for condition-specific result files
    for cond_file in unified_dir.glob("*_results.json"):
        # Extract condition from filename (e.g., "c1_results.json" -> "c1")
        condition = cond_file.stem.split('_')[0]

        with open(cond_file, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                results_by_condition[condition] = data
            elif isinstance(data, dict) and 'results' in data:
                results_by_condition[condition] = data['results']

    return dict(results_by_condition)


def extract_scores(results: List[Dict], metric: str) -> List[float]:
    """Extract scores for a specific metric from results"""
    scores = []

    for result in results:
        # Try different possible locations for scores
        if 'explanation_metrics' in result and result['explanation_metrics']:
            exp_metrics = result['explanation_metrics']
            if 'llm_scores' in exp_metrics and exp_metrics['llm_scores']:
                if metric in exp_metrics['llm_scores']:
                    scores.append(float(exp_metrics['llm_scores'][metric]))

        # Also check top-level
        if metric in result:
            scores.append(float(result[metric]))

    return scores


def extract_success_rate(results: List[Dict]) -> float:
    """Calculate success rate from results"""
    if not results:
        return 0.0

    success_count = sum(1 for r in results if r.get('actual_success', False))
    return success_count / len(results)


def paired_ttest(c1_scores: List[float], c4_scores: List[float]) -> tuple:
    """Perform paired t-test"""
    if len(c1_scores) != len(c4_scores):
        raise ValueError("Score lists must have equal length for paired test")

    t_stat, p_value = ttest_rel(c1_scores, c4_scores)

    # Calculate Cohen's d (effect size)
    diff = np.array(c4_scores) - np.array(c1_scores)
    cohens_d = np.mean(diff) / np.std(diff, ddof=1)

    return t_stat, p_value, cohens_d


def wilcoxon_test(c1_scores: List[float], c4_scores: List[float]) -> tuple:
    """Perform Wilcoxon signed-rank test (non-parametric alternative to t-test)"""
    if len(c1_scores) != len(c4_scores):
        raise ValueError("Score lists must have equal length for paired test")

    # Wilcoxon test
    w_stat, p_value = wilcoxon(c1_scores, c4_scores)

    # Effect size (r = Z / sqrt(N))
    z_score = stats.norm.ppf(1 - p_value / 2)  # Convert p to z
    r = abs(z_score) / np.sqrt(len(c1_scores))

    return w_stat, p_value, r


def friedman_test(scores_by_condition: Dict[str, List[float]]) -> tuple:
    """Perform Friedman test (non-parametric repeated measures ANOVA)"""
    conditions = sorted(scores_by_condition.keys())

    # All conditions must have same number of samples
    n_samples = len(scores_by_condition[conditions[0]])
    for cond in conditions:
        if len(scores_by_condition[cond]) != n_samples:
            raise ValueError(f"Condition {cond} has different number of samples")

    # Organize data for Friedman test
    data_arrays = [scores_by_condition[cond] for cond in conditions]

    chi2_stat, p_value = friedmanchisquare(*data_arrays)

    return chi2_stat, p_value, conditions


def compute_confidence_interval(scores: List[float], confidence=0.95) -> tuple:
    """Compute confidence interval for mean"""
    if not scores:
        return 0.0, 0.0, 0.0

    mean = np.mean(scores)
    std = np.std(scores, ddof=1)
    n = len(scores)

    # t-distribution for small samples
    t_critical = stats.t.ppf((1 + confidence) / 2, n - 1)
    margin = t_critical * (std / np.sqrt(n))

    return mean, mean - margin, mean + margin


def analyze_monotonicity(scores_by_condition: Dict[str, List[float]]) -> Dict:
    """Check if scores show monotonic increase C1 < C2 < C3 < C4"""
    conditions = ['c1', 'c2', 'c3', 'c4']
    means = {cond: np.mean(scores_by_condition.get(cond, [0]))
             for cond in conditions if cond in scores_by_condition}

    # Check monotonic increase
    is_monotonic = all(
        means.get(f'c{i}', 0) <= means.get(f'c{i+1}', 0)
        for i in range(1, 4)
        if f'c{i}' in means and f'c{i+1}' in means
    )

    # Calculate violations
    violations = []
    for i in range(1, 4):
        curr, next_c = f'c{i}', f'c{i+1}'
        if curr in means and next_c in means:
            if means[curr] > means[next_c]:
                violations.append(f"{curr} ({means[curr]:.2f}) > {next_c} ({means[next_c]:.2f})")

    return {
        'is_monotonic': is_monotonic,
        'means': means,
        'violations': violations
    }


def compute_power_analysis(
    observed_effect_size: float,
    sample_size: int,
    alpha: float = 0.0125,  # Bonferroni corrected: 0.05/4
    alternative: str = 'two-sided'
) -> Dict[str, float]:
    """
    A priori power analysis to validate sample size sufficiency.

    This implements the power analysis described in the paper to demonstrate
    that n=121 samples is sufficient for detecting the observed effect size.

    Args:
        observed_effect_size: Cohen's d from the experiment
        sample_size: Actual sample size (n=121 in paper)
        alpha: Significance level (Bonferroni corrected)
        alternative: 'two-sided', 'larger', or 'smaller'

    Returns:
        Dictionary with:
        - achieved_power: Statistical power achieved (β)
        - required_sample_size: Minimum n needed for 80% power
        - effect_size: Cohen's d used
        - alpha: Significance level
        - interpretation: Whether sample size is sufficient
    """
    if not POWER_ANALYSIS_AVAILABLE:
        return {
            'error': 'statsmodels not available',
            'message': 'Install statsmodels for power analysis: pip install statsmodels'
        }

    power_analysis = TTestIndPower()

    # Compute achieved power with actual sample size
    achieved_power = power_analysis.solve_power(
        effect_size=observed_effect_size,
        nobs1=sample_size,
        alpha=alpha,
        alternative=alternative
    )

    # Compute required sample size for 80% power (standard threshold)
    required_n = power_analysis.solve_power(
        effect_size=observed_effect_size,
        power=0.80,
        alpha=alpha,
        alternative=alternative
    )

    results = {
        'achieved_power': float(achieved_power),
        'required_sample_size': int(np.ceil(required_n)),
        'actual_sample_size': sample_size,
        'effect_size': observed_effect_size,
        'alpha': alpha,
        'interpretation': (
            'Sufficient (well-powered)' if achieved_power >= 0.80
            else 'Insufficient (underpowered)'
        )
    }

    return results


def format_significance(p_value: float) -> str:
    """Format p-value with significance markers"""
    if p_value < 0.001:
        return f"p < 0.001 ***"
    elif p_value < 0.01:
        return f"p = {p_value:.4f} **"
    elif p_value < 0.05:
        return f"p = {p_value:.4f} *"
    else:
        return f"p = {p_value:.4f} ns"


def main():
    parser = argparse.ArgumentParser(description="Statistical analysis of PatchScribe results")
    parser.add_argument('--input', type=str, required=True,
                        help='Path to unified results directory')
    parser.add_argument('--output', type=str, required=True,
                        help='Output file for statistical report')
    parser.add_argument('--metrics', type=str, default='accuracy,completeness,causality,clarity',
                        help='Comma-separated list of metrics to analyze')
    parser.add_argument('--include-power-analysis', action='store_true',
                        help='Include power analysis to validate sample size')

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input path {input_path} does not exist")
        sys.exit(1)

    # Load results
    print(f"Loading results from {input_path}...")
    results_by_condition = load_unified_results(input_path)

    if not results_by_condition:
        print("Error: No results found")
        sys.exit(1)

    print(f"Found conditions: {sorted(results_by_condition.keys())}")

    # Open output file
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("STATISTICAL ANALYSIS REPORT - PatchScribe Experiments\n")
        f.write("=" * 80 + "\n\n")

        # Analyze patch success rates
        f.write("## 1. PATCH SUCCESS RATE ANALYSIS\n\n")

        for cond in sorted(results_by_condition.keys()):
            results = results_by_condition[cond]
            success_rate = extract_success_rate(results)
            n = len(results)

            # Confidence interval for proportion
            if n > 0:
                p = success_rate
                se = np.sqrt(p * (1 - p) / n)
                ci_lower = max(0, p - 1.96 * se)
                ci_upper = min(1, p + 1.96 * se)

                f.write(f"{cond.upper()}: {success_rate*100:.1f}% "
                       f"(95% CI: [{ci_lower*100:.1f}%, {ci_upper*100:.1f}%]), n={n}\n")

        f.write("\n")

        # Analyze explanation quality metrics
        metrics = args.metrics.split(',')

        for metric in metrics:
            f.write(f"\n## {metric.upper()} METRIC ANALYSIS\n\n")

            # Extract scores for all conditions
            scores_by_condition = {}
            for cond in sorted(results_by_condition.keys()):
                scores = extract_scores(results_by_condition[cond], metric)
                if scores:
                    scores_by_condition[cond] = scores

            if not scores_by_condition:
                f.write(f"No data available for {metric}\n")
                continue

            # Descriptive statistics
            f.write("### Descriptive Statistics\n\n")
            for cond in sorted(scores_by_condition.keys()):
                scores = scores_by_condition[cond]
                mean, ci_lower, ci_upper = compute_confidence_interval(scores)

                f.write(f"{cond.upper()}: {mean:.2f} ± {np.std(scores, ddof=1):.2f} "
                       f"(95% CI: [{ci_lower:.2f}, {ci_upper:.2f}]), n={len(scores)}\n")

            # Monotonicity check
            f.write("\n### Monotonicity Check\n\n")
            monotonicity = analyze_monotonicity(scores_by_condition)

            if monotonicity['is_monotonic']:
                f.write("[PASS] Scores show monotonic increase (C1 ≤ C2 ≤ C3 ≤ C4)\n")
            else:
                f.write("[FAIL] Scores do NOT show monotonic increase\n")
                f.write("Violations:\n")
                for violation in monotonicity['violations']:
                    f.write(f"  - {violation}\n")

            # Paired comparisons (C1 vs C4)
            if 'c1' in scores_by_condition and 'c4' in scores_by_condition:
                c1_scores = scores_by_condition['c1']
                c4_scores = scores_by_condition['c4']

                # Ensure same length (truncate to shorter)
                min_len = min(len(c1_scores), len(c4_scores))
                c1_scores = c1_scores[:min_len]
                c4_scores = c4_scores[:min_len]

                f.write("\n### Statistical Tests (C1 vs C4)\n\n")

                # Paired t-test
                t_stat, p_val_t, cohens_d = paired_ttest(c1_scores, c4_scores)
                f.write(f"Paired t-test:\n")
                f.write(f"  t = {t_stat:.3f}, {format_significance(p_val_t)}\n")
                f.write(f"  Effect size (Cohen's d): {cohens_d:.3f}\n")

                # Interpret effect size
                if abs(cohens_d) < 0.2:
                    effect = "negligible"
                elif abs(cohens_d) < 0.5:
                    effect = "small"
                elif abs(cohens_d) < 0.8:
                    effect = "medium"
                else:
                    effect = "large"
                f.write(f"  Effect size interpretation: {effect}\n\n")

                # Wilcoxon test
                w_stat, p_val_w, r = wilcoxon_test(c1_scores, c4_scores)
                f.write(f"Wilcoxon signed-rank test (non-parametric):\n")
                f.write(f"  W = {w_stat:.3f}, {format_significance(p_val_w)}\n")
                f.write(f"  Effect size (r): {r:.3f}\n\n")

                # Power analysis (if requested)
                if args.include_power_analysis and abs(cohens_d) > 0.01:
                    f.write(f"### Power Analysis\n\n")

                    power_results = compute_power_analysis(
                        observed_effect_size=abs(cohens_d),
                        sample_size=min_len,
                        alpha=0.0125  # Bonferroni correction: 0.05/4 conditions
                    )

                    if 'error' in power_results:
                        f.write(f"  {power_results['message']}\n\n")
                    else:
                        f.write(f"  Effect size (Cohen's d): {power_results['effect_size']:.3f}\n")
                        f.write(f"  Actual sample size: {power_results['actual_sample_size']}\n")
                        f.write(f"  Significance level (α): {power_results['alpha']:.4f} (Bonferroni corrected)\n")
                        f.write(f"  Required sample size (80% power): {power_results['required_sample_size']}\n")
                        f.write(f"  Achieved power (β): {power_results['achieved_power']:.3f} ({power_results['achieved_power']*100:.1f}%)\n")
                        f.write(f"  Interpretation: {power_results['interpretation']}\n\n")

                        # Comparison with paper
                        if power_results['achieved_power'] >= 0.85:
                            f.write(f"  ✅ Study is well-powered (β ≥ 0.85), consistent with paper's claim of β=0.86\n\n")
                        elif power_results['achieved_power'] >= 0.80:
                            f.write(f"  ✅ Study has adequate power (β ≥ 0.80)\n\n")
                        else:
                            f.write(f"  ⚠️ Study is underpowered (β < 0.80). Consider increasing sample size.\n\n")

            # Friedman test (all conditions)
            if len(scores_by_condition) >= 3:
                try:
                    chi2, p_val, conditions = friedman_test(scores_by_condition)
                    f.write(f"### Friedman Test (All Conditions)\n\n")
                    f.write(f"  χ² = {chi2:.3f}, {format_significance(p_val)}\n")
                    f.write(f"  Conditions tested: {', '.join(conditions)}\n\n")
                except ValueError as e:
                    f.write(f"### Friedman Test\n\n")
                    f.write(f"  Cannot perform: {e}\n\n")

        # Summary
        f.write("\n" + "=" * 80 + "\n")
        f.write("SUMMARY\n")
        f.write("=" * 80 + "\n\n")

        f.write("Statistical significance levels:\n")
        f.write("  *** : p < 0.001 (highly significant)\n")
        f.write("  **  : p < 0.01  (very significant)\n")
        f.write("  *   : p < 0.05  (significant)\n")
        f.write("  ns  : p ≥ 0.05  (not significant)\n\n")

        f.write("Effect size interpretations (Cohen's d):\n")
        f.write("  |d| < 0.2 : negligible\n")
        f.write("  |d| < 0.5 : small\n")
        f.write("  |d| < 0.8 : medium\n")
        f.write("  |d| ≥ 0.8 : large\n")

    print(f"\nStatistical analysis complete. Report saved to: {output_path}")


if __name__ == "__main__":
    main()
