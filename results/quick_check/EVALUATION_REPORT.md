# PatchScribe Evaluation Report

Generated: 2025-10-28 20:58:07

## Executive Summary

### RQ1: Theory-Guided Generation Effectiveness

| Condition | Success Rate | First Attempt | Ground Truth |
|-----------|--------------|---------------|--------------|
| baseline_c1 | 100.0% | 0.0% | 100.0% |
| vague_hints_c2 | 100.0% | 0.0% | 100.0% |
| prehoc_c3 | 100.0% | 0.0% | 100.0% |
| full_patchscribe_c4 | 100.0% | 0.0% | 100.0% |

### RQ2: Dual Verification Effectiveness

- Consistency pass rate: 33.3%
- Triple verification rate: 33.3%
- Vulnerability elimination rate: 66.7%

### RQ3: Scalability and Performance

See detailed performance breakdown in RQ3 analysis files.

### RQ4: Explanation Quality

- Avg explanation checklist coverage: 33.3%
- Avg LLM accuracy: 3.67/5
- Avg LLM clarity: 4.17/5
- Avg LLM causality: 4.17/5

## Detailed Results

See individual result files:
- `baseline_c1_results.json`
- `vague_hints_c2_results.json`
- `prehoc_c3_results.json`
- `full_patchscribe_c4_results.json`

## RQ Analysis Reports

Detailed RQ-specific analysis available in:
- `rq_comparative_analysis.json`
- Individual RQ analysis files for each condition