#!/usr/bin/env python3
"""
Threshold Calibration Tool for PatchScribe

This script performs 10-fold cross-validation to find optimal thresholds for
consistency checking, generating ROC curves and precision-recall curves.

Usage:
    python scripts/calibrate_thresholds.py --dataset zeroday --output results/thresholds.json
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import roc_auc_score, roc_curve, precision_recall_curve, auc

# Suppress matplotlib warnings
import warnings
warnings.filterwarnings('ignore')


def load_validation_dataset(dataset_name: str, data_dir: Path) -> List[Dict]:
    """
    Load a validation dataset with ground truth labels.

    Returns:
        List of cases with:
        - 'id': case identifier
        - 'is_correct': ground truth label (True if patch is correct)
        - 'jaccard_score': computed Jaccard similarity
        - 'location_score': location alignment score
        - 'causal_overlap': causal path overlap
    """
    # This is a placeholder - in practice, you'd load actual evaluation results
    # For now, we'll generate synthetic data for demonstration

    print(f"Loading validation dataset: {dataset_name}")
    print(f"Note: Using synthetic data for demonstration. Replace with actual evaluation results.")

    # Generate synthetic data that mimics real evaluation results
    np.random.seed(42)
    n_samples = 121  # Total CVEs in paper

    cases = []
    for i in range(n_samples):
        # Generate realistic scores
        # Correct patches tend to have higher scores
        is_correct = np.random.rand() > 0.5

        if is_correct:
            jaccard_score = np.random.beta(5, 2)  # Skewed toward high values
            location_score = np.random.beta(4, 2)
            causal_overlap = np.random.beta(5, 2)
        else:
            jaccard_score = np.random.beta(2, 5)  # Skewed toward low values
            location_score = np.random.beta(2, 4)
            causal_overlap = np.random.beta(2, 5)

        cases.append({
            'id': f'{dataset_name}_{i:03d}',
            'is_correct': is_correct,
            'jaccard_score': float(jaccard_score),
            'location_score': float(location_score),
            'causal_overlap': float(causal_overlap)
        })

    return cases


def compute_consistency_score(case: Dict, weights: Dict[str, float]) -> float:
    """
    Compute overall consistency score as weighted combination of metrics.

    Args:
        case: Case data with individual scores
        weights: Weight for each metric

    Returns:
        Combined consistency score (0-1)
    """
    score = (
        weights['jaccard'] * case.get('jaccard_score', 0) +
        weights['location'] * case.get('location_score', 0) +
        weights['causal'] * case.get('causal_overlap', 0)
    )
    return score


def calibrate_thresholds(
    cases: List[Dict],
    n_folds: int = 10,
    output_dir: Path = Path('results/calibration')
) -> Dict[str, float]:
    """
    Perform 10-fold cross-validation to find optimal thresholds.

    Args:
        cases: List of validation cases with ground truth
        n_folds: Number of cross-validation folds (default: 10)
        output_dir: Directory to save plots and results

    Returns:
        Dictionary with optimal thresholds and performance metrics
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Prepare data
    labels = np.array([c['is_correct'] for c in cases])

    # Check class balance
    n_positive = labels.sum()
    n_negative = len(labels) - n_positive
    print(f"\nDataset statistics:")
    print(f"  Total samples: {len(cases)}")
    print(f"  Positive (correct): {n_positive} ({n_positive/len(labels)*100:.1f}%)")
    print(f"  Negative (incorrect): {n_negative} ({n_negative/len(labels)*100:.1f}%)")

    # Initialize cross-validation
    skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)

    # Store results from each fold
    fold_results = []
    all_fpr = []
    all_tpr = []
    all_roc_auc = []

    # Metric weights (can be tuned)
    weights = {
        'jaccard': 0.5,
        'location': 0.2,
        'causal': 0.3
    }

    print(f"\nPerforming {n_folds}-fold cross-validation...")
    print(f"Metric weights: {weights}")

    for fold, (train_idx, val_idx) in enumerate(skf.split(cases, labels)):
        print(f"\n--- Fold {fold + 1}/{n_folds} ---")

        # Split data
        val_cases = [cases[i] for i in val_idx]
        val_labels = labels[val_idx]

        # Compute consistency scores for validation set
        val_scores = np.array([
            compute_consistency_score(c, weights) for c in val_cases
        ])

        # Compute ROC curve
        fpr, tpr, thresholds = roc_curve(val_labels, val_scores)
        roc_auc = roc_auc_score(val_labels, val_scores)

        all_fpr.append(fpr)
        all_tpr.append(tpr)
        all_roc_auc.append(roc_auc)

        # Find optimal threshold using Youden's J statistic
        j_scores = tpr - fpr
        optimal_idx = np.argmax(j_scores)
        optimal_threshold = thresholds[optimal_idx]

        # Compute metrics at optimal threshold
        predictions = (val_scores >= optimal_threshold).astype(int)
        tp = ((predictions == 1) & (val_labels == 1)).sum()
        fp = ((predictions == 1) & (val_labels == 0)).sum()
        tn = ((predictions == 0) & (val_labels == 0)).sum()
        fn = ((predictions == 0) & (val_labels == 1)).sum()

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        fold_results.append({
            'fold': fold + 1,
            'optimal_threshold': float(optimal_threshold),
            'roc_auc': float(roc_auc),
            'precision': float(precision),
            'recall': float(recall),
            'f1': float(f1),
            'tp': int(tp),
            'fp': int(fp),
            'tn': int(tn),
            'fn': int(fn)
        })

        print(f"  Optimal threshold: {optimal_threshold:.3f}")
        print(f"  ROC AUC: {roc_auc:.3f}")
        print(f"  Precision: {precision:.3f}, Recall: {recall:.3f}, F1: {f1:.3f}")
        print(f"  Confusion: TP={tp}, FP={fp}, TN={tn}, FN={fn}")

        # Plot ROC curve for this fold
        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, label=f'Fold {fold + 1} (AUC = {roc_auc:.3f})')
        plt.plot([0, 1], [0, 1], 'k--', label='Random')
        plt.scatter([fpr[optimal_idx]], [tpr[optimal_idx]],
                   color='red', s=100, zorder=5,
                   label=f'Optimal (threshold={optimal_threshold:.3f})')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title(f'ROC Curve - Fold {fold + 1}')
        plt.legend()
        plt.grid(alpha=0.3)
        plt.savefig(output_dir / f'roc_fold_{fold + 1}.png', dpi=150, bbox_inches='tight')
        plt.close()

    # Aggregate results
    optimal_threshold = np.median([r['optimal_threshold'] for r in fold_results])
    mean_roc_auc = np.mean(all_roc_auc)
    std_roc_auc = np.std(all_roc_auc)

    mean_precision = np.mean([r['precision'] for r in fold_results])
    mean_recall = np.mean([r['recall'] for r in fold_results])
    mean_f1 = np.mean([r['f1'] for r in fold_results])

    # Calculate false negative rate
    total_fn = sum(r['fn'] for r in fold_results)
    total_positives = sum(r['tp'] + r['fn'] for r in fold_results)
    fn_rate = total_fn / total_positives if total_positives > 0 else 0

    print(f"\n{'=' * 60}")
    print("CALIBRATION SUMMARY")
    print(f"{'=' * 60}")
    print(f"Optimal threshold (median): {optimal_threshold:.3f}")
    print(f"Mean ROC AUC: {mean_roc_auc:.3f} ± {std_roc_auc:.3f}")
    print(f"Mean Precision: {mean_precision:.3f}")
    print(f"Mean Recall: {mean_recall:.3f}")
    print(f"Mean F1 Score: {mean_f1:.3f}")
    print(f"False Negative Rate: {fn_rate:.3f} ({fn_rate*100:.1f}%)")
    print(f"{'=' * 60}")

    # Plot mean ROC curve
    plt.figure(figsize=(8, 6))

    # Interpolate ROC curves to common FPR points
    mean_fpr = np.linspace(0, 1, 100)
    tprs = []
    for fpr, tpr in zip(all_fpr, all_tpr):
        interp_tpr = np.interp(mean_fpr, fpr, tpr)
        interp_tpr[0] = 0.0
        tprs.append(interp_tpr)

    mean_tpr = np.mean(tprs, axis=0)
    mean_tpr[-1] = 1.0
    std_tpr = np.std(tprs, axis=0)

    tprs_upper = np.minimum(mean_tpr + std_tpr, 1)
    tprs_lower = np.maximum(mean_tpr - std_tpr, 0)

    plt.plot(mean_fpr, mean_tpr, color='b',
            label=f'Mean ROC (AUC = {mean_roc_auc:.3f} ± {std_roc_auc:.3f})',
            lw=2)
    plt.fill_between(mean_fpr, tprs_lower, tprs_upper, color='b', alpha=0.2,
                    label='± 1 std. dev.')
    plt.plot([0, 1], [0, 1], 'k--', label='Random')

    plt.xlabel('False Positive Rate', fontsize=12)
    plt.ylabel('True Positive Rate', fontsize=12)
    plt.title('Mean ROC Curve (10-Fold Cross-Validation)', fontsize=14)
    plt.legend(loc='lower right')
    plt.grid(alpha=0.3)
    plt.savefig(output_dir / 'roc_mean.png', dpi=150, bbox_inches='tight')
    plt.close()

    print(f"\nPlots saved to: {output_dir}")

    # Prepare final results
    final_results = {
        'optimal_threshold': float(optimal_threshold),
        'metric_weights': weights,
        'performance': {
            'mean_roc_auc': float(mean_roc_auc),
            'std_roc_auc': float(std_roc_auc),
            'mean_precision': float(mean_precision),
            'mean_recall': float(mean_recall),
            'mean_f1': float(mean_f1),
            'false_negative_rate': float(fn_rate)
        },
        'fold_results': fold_results,
        'paper_comparison': {
            'paper_roc_auc': '0.92-0.94',
            'paper_false_negative': '1.1%',
            'achieved_roc_auc': f'{mean_roc_auc:.3f}',
            'achieved_false_negative': f'{fn_rate*100:.1f}%'
        }
    }

    return final_results


def save_thresholds(results: Dict, output_path: Path):
    """Save calibrated thresholds to JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n✅ Calibration complete. Results saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Calibrate consistency checking thresholds using cross-validation"
    )
    parser.add_argument(
        '--dataset',
        type=str,
        default='zeroday',
        choices=['zeroday', 'extractfix', 'both'],
        help='Dataset to use for calibration'
    )
    parser.add_argument(
        '--data-dir',
        type=Path,
        default=Path('data'),
        help='Directory containing validation data'
    )
    parser.add_argument(
        '--output',
        type=Path,
        default=Path('results/thresholds.json'),
        help='Output file for calibrated thresholds'
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('results/calibration'),
        help='Directory for calibration plots'
    )
    parser.add_argument(
        '--n-folds',
        type=int,
        default=10,
        help='Number of cross-validation folds (default: 10)'
    )
    parser.add_argument(
        '--plot',
        action='store_true',
        help='Generate and save ROC curve plots'
    )

    args = parser.parse_args()

    print("=" * 60)
    print("PatchScribe Threshold Calibration")
    print("=" * 60)

    # Load validation dataset
    cases = load_validation_dataset(args.dataset, args.data_dir)

    if not cases:
        print("Error: No validation data found")
        sys.exit(1)

    # Perform calibration
    results = calibrate_thresholds(
        cases,
        n_folds=args.n_folds,
        output_dir=args.output_dir
    )

    # Save results
    save_thresholds(results, args.output)

    print("\n" + "=" * 60)
    print("Calibration complete!")
    print("=" * 60)
    print("\nTo use the calibrated thresholds in experiments:")
    print(f"  python scripts/run_experiment.py \\")
    print(f"    --thresholds-config {args.output}")
    print()


if __name__ == "__main__":
    main()
