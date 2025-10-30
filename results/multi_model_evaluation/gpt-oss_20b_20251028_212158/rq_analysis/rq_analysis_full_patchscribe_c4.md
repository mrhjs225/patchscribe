# PatchScribe RQ Analysis Report

Generated from: full_patchscribe_c4_results.json
Total cases analyzed: 97

## RQ1: Theory-Guided Generation Effectiveness

**Research Question**: Does pre-hoc formal bug specification (E_bug) lead to more accurate patches?

### Condition: unknown
- Total cases: 97
- Triple verification rate: 67.0%
- Ground truth similarity: 100.0%
- First attempt success rate: 0.0%

## RQ2: Dual Verification Effectiveness

**Research Question**: How effective is consistency checking at detecting incomplete patches?

### Triple Verification (V4)
- Incomplete patches caught: 32

**Consistency violation breakdown:**
- causal_coverage: 0 cases
- intervention_validity: 4 cases
- logical_consistency: 13 cases
- completeness: 21 cases

## RQ3: Scalability and Performance

**Research Question**: What is the time overhead of the three-phase workflow?

## RQ4: Explanation Quality

**Research Question**: Do dual explanations provide useful insights to developers?

### Dual Explanations (E_bug + E_patch)
- Checklist coverage: 42.1%
- Accuracy score: 4.02/5
- Clarity score: 4.09/5
- Causality score: 4.24/5

## Overall Metrics

- total_cases: 97.0000
- success_rate: 1.0000
- expectation_match_rate: 1.0000
- false_positive_rate: 0.0000
- false_negative_rate: 0.0000
- vulnerability_elimination_rate: 0.7732
- ground_truth_match_rate: 1.0000
- avg_explanation_checklist: 0.4210
- first_attempt_success_rate: 0.0000
- consistency_pass_rate: 0.6701
- triple_verification_pass_rate: 0.6701
- avg_llm_accuracy: 4.0237
- avg_llm_clarity: 4.0897
- avg_llm_causality: 4.2412