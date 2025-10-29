# PatchScribe RQ Analysis Report

Generated from: vague_hints_c2_results.json
Total cases analyzed: 97

## RQ1: Theory-Guided Generation Effectiveness

**Research Question**: Does pre-hoc formal bug specification (E_bug) lead to more accurate patches?

### Condition: unknown
- Total cases: 97
- Triple verification rate: 0.0%
- Ground truth similarity: 100.0%
- First attempt success rate: 0.0%

## RQ2: Dual Verification Effectiveness

**Research Question**: How effective is consistency checking at detecting incomplete patches?

### Triple Verification (V4)
- Incomplete patches caught: 0

**Consistency violation breakdown:**
- causal_coverage: 0 cases
- intervention_validity: 0 cases
- logical_consistency: 0 cases
- completeness: 0 cases

## RQ3: Scalability and Performance

**Research Question**: What is the time overhead of the three-phase workflow?

## RQ4: Explanation Quality

**Research Question**: Do dual explanations provide useful insights to developers?

### Dual Explanations (E_bug + E_patch)
- Checklist coverage: 18.0%
- Accuracy score: 4.15/5
- Clarity score: 3.68/5
- Causality score: 3.92/5

## Overall Metrics

- total_cases: 97.0000
- success_rate: 1.0000
- expectation_match_rate: 1.0000
- false_positive_rate: 0.0000
- false_negative_rate: 0.0000
- vulnerability_elimination_rate: 0.7732
- ground_truth_match_rate: 1.0000
- avg_explanation_checklist: 0.1804
- first_attempt_success_rate: 0.0000
- consistency_pass_rate: 0.0000
- triple_verification_pass_rate: 0.0000
- avg_llm_accuracy: 4.1548
- avg_llm_clarity: 3.6810
- avg_llm_causality: 3.9167