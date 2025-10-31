# RQ2 Evaluation Guide: Verification Method Ablation Study

This guide explains how to use the new RQ2 evaluation tools to measure the effectiveness of different verification methods.

## Overview

The RQ2 evaluation framework compares four verification approaches:
- **V1**: Exploit-only testing (run PoC exploit, check if blocked)
- **V2**: Symbolic execution only (KLEE/angr)
- **V3**: Consistency checking only (E_bug ↔ E_patch)
- **V4**: Triple verification (consistency + symbolic + completeness)

## Step 1: Generate Incomplete Patches

First, generate deliberately incomplete patches for precision/recall evaluation:

```bash
python scripts/inject_incomplete_patches.py \
    --dataset zeroday \
    --limit 10 \
    --output results/incomplete_patches
```

This creates 2-3 incomplete patches per vulnerability with different types of incompleteness:
- **Specific value check**: Only checks exact values (e.g., `len == 256` instead of `len >= 256`)
- **Partial condition**: Addresses one causal path but misses others
- **Wrong location**: Validation after vulnerable operation instead of before
- **Tautology**: Guard condition always true (provides no protection)
- **Insufficient validation**: Only null check, no bounds check

Output: `results/incomplete_patches/incomplete_patches_zeroday.json`

## Step 2: Run Verification Ablation Study

Run all four verification methods (V1-V4) on the incomplete patches:

```bash
python scripts/run_verification_ablation.py \
    --dataset zeroday \
    --limit 10 \
    --incomplete-patches results/incomplete_patches/incomplete_patches_zeroday.json \
    --output results/verification_ablation
```

This will:
1. Test each incomplete patch with all four verification methods
2. Record which methods detect the incompleteness
3. Calculate precision and recall for each method
4. Measure execution time per method

Output: `results/verification_ablation/verification_ablation_zeroday.json`

## Step 3: Analyze Results

The output JSON contains:
```json
{
  "V1": [
    {
      "method": "V1_exploit_only",
      "case_id": "...",
      "patch_id": "...",
      "detected_incomplete": true/false,
      "execution_time": 1.23,
      "details": "..."
    }
  ],
  "V2": [...],
  "V3": [...],
  "V4": [...]
}
```

### Precision/Recall Calculation

For each verification method:
- **True Positives (TP)**: Incomplete patches correctly flagged
- **False Negatives (FN)**: Incomplete patches missed
- **Precision**: TP / (TP + FP)
- **Recall**: TP / (TP + FN)

Expected results (from paper):
- V1 (exploit-only): ~60% precision, ~50% recall
- V4 (triple verification): ~90% precision, ~80% recall

## Step 4: Integration with Full Evaluation

To run the complete evaluation including RQ2:

```bash
python scripts/run_full_evaluation.py zeroday \
    --conditions c1 c2 c3 c4 \
    --output results/full_evaluation
```

Then run RQ analysis:

```bash
python scripts/run_rq_analysis.py \
    results/full_evaluation/raw_results/full_patchscribe_c4_results.json \
    -o results/rq_analysis.json
```

The RQ2 section will show:
- Incomplete patches caught by consistency checking
- Consistency violation breakdown by type
- Verification stage outcomes (symbolic, model_check, fuzzing)

## AST-Based Ground Truth Similarity

The evaluation now uses AST-based similarity instead of text comparison:

```python
from patchscribe.ast_similarity import calculate_ast_similarity

result = calculate_ast_similarity(generated_patch, ground_truth_patch)
print(f"Overall similarity: {result.overall_similarity:.2%}")
print(f"Structural similarity: {result.structural_similarity:.2%}")
print(f"Token similarity: {result.token_similarity:.2%}")
```

Similarity scores are automatically calculated during evaluation and included in metrics:
- `avg_ast_overall_similarity`
- `avg_ast_structural_similarity`
- `avg_ast_token_similarity`

## Expected Outcomes

Based on the paper's evaluation plan:

### RQ2 Metrics
- **Incomplete patches caught**: 3-5 patches that pass exploit tests but fail consistency checking
- **Consistency violations**: Breakdown by causal coverage, intervention validity, logical consistency, completeness
- **Verification agreement rate**: How often consistency, symbolic, and completeness checking agree

### Key Insights
1. Consistency checking catches cases where original exploit is blocked but variant exploits remain possible
2. Triple verification provides complementary assurance by verifying causal reasoning, not just execution outcomes
3. Different incompleteness types are caught by different verification methods

## Troubleshooting

### If incomplete patch generation fails:
- Check that dataset is loaded correctly: `python -c "from patchscribe.dataset import load_cases; print(load_cases('zeroday', limit=1))"`
- Ensure dataset directory exists: `datasets/zeroday_repair/`

### If verification ablation fails:
- V1 (exploit testing) requires `gcc` compiler
- V2 (symbolic) requires `clang` and `klee` (optional, will skip if not available)
- V3 (consistency) is pure Python, should always work
- Check logs for specific error messages

### If AST similarity is all zeros:
- This is expected if tree-sitter is not installed
- Falls back to regex-based similarity (still accurate for most cases)
- To install tree-sitter: `pip install tree-sitter`

## Next Steps

After running RQ2 evaluation:

1. **Analyze which verification methods are most effective** for different incompleteness types
2. **Calculate cost-benefit trade-off**: Time overhead vs detection improvement
3. **Compare to paper's expected results**: V4 should achieve ~90% precision, ~80% recall
4. **Prepare figures for paper**: Precision/recall comparison charts, verification time breakdown

## References

- Paper Section: "RQ2: Dual Verification Effectiveness" (lines 1248-1252)
- Expected Results: Lines 1343-1353
- Implementation:
  - `scripts/inject_incomplete_patches.py`
  - `scripts/run_verification_ablation.py`
  - `patchscribe/ast_similarity.py`
