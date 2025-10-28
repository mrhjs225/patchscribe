# PatchScribe RQ Analysis Report

Generated from: full_patchscribe_c4_results.json
Total cases analyzed: 3

## RQ1: Theory-Guided Generation Effectiveness

**Research Question**: Does pre-hoc formal bug specification (E_bug) lead to more accurate patches?

### Condition: unknown
- Total cases: 3
- Triple verification rate: 33.3%
- Ground truth similarity: 100.0%
- First attempt success rate: 0.0%

## RQ2: Dual Verification Effectiveness

**Research Question**: How effective is consistency checking at detecting incomplete patches?

### Triple Verification (V4)
- Incomplete patches caught: 2

**Consistency violation breakdown:**
- causal_coverage: 0 cases
- intervention_validity: 0 cases
- logical_consistency: 1 cases
- completeness: 2 cases

## RQ3: Scalability and Performance

**Research Question**: What is the time overhead of the three-phase workflow?

## RQ4: Explanation Quality

**Research Question**: Do dual explanations provide useful insights to developers?

### Dual Explanations (E_bug + E_patch)
- Checklist coverage: 33.3%
- Accuracy score: 3.67/5
- Clarity score: 4.17/5
- Causality score: 4.17/5

## Overall Metrics

- total_cases: 3.0000
- success_rate: 1.0000
- expectation_match_rate: 1.0000
- false_positive_rate: 0.0000
- false_negative_rate: 0.0000
- vulnerability_elimination_rate: 0.6667
- ground_truth_match_rate: 1.0000
- avg_explanation_checklist: 0.3333
- first_attempt_success_rate: 0.0000
- consistency_pass_rate: 0.3333
- triple_verification_pass_rate: 0.3333
- avg_llm_accuracy: 3.6667
- avg_llm_clarity: 4.1667
- avg_llm_causality: 4.1667