# PatchScribe Evaluation Report

Generated: 2025-10-29 12:15:23

## Executive Summary

### RQ1: Theory-Guided Generation Effectiveness

| Condition | Success Rate | First Attempt | Ground Truth |
|-----------|--------------|---------------|--------------|
| baseline_c1 | 100.0% | 0.0% | 100.0% |
| vague_hints_c2 | 100.0% | 0.0% | 100.0% |
| prehoc_c3 | 100.0% | 0.0% | 100.0% |
| full_patchscribe_c4 | 100.0% | 0.0% | 100.0% |

### RQ2: Dual Verification Effectiveness

- Consistency pass rate: 60.8%
- Triple verification rate: 60.8%
- Vulnerability elimination rate: 77.3%

### RQ3: Scalability and Performance

See detailed performance breakdown in RQ3 analysis files.

### RQ4: Explanation Quality

- Avg explanation checklist coverage: 8.6%
- Avg LLM accuracy: 3.11/5
- Avg LLM clarity: 2.88/5
- Avg LLM causality: 3.02/5

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