# PatchScribe: Evaluation Automation Guide

## Overview

본 문서는 PatchScribe 평가 프로세스에서 자동화 가능한 부분, 반자동 평가가 필요한 부분, 그리고 수동 평가가 필수적인 부분을 구분하고, 각각의 구현 방법과 예상 소요 시간을 명시합니다.

---

## 📊 Automation Classification

### Summary Statistics

```python
automation_summary = {
    'RQ1': {
        'fully_automated': '60%',
        'semi_automated': '25%',
        'manual_only': '15%',
    },
    'RQ2': {
        'fully_automated': '50%',
        'semi_automated': '30%',
        'manual_only': '20%',
    },
    'RQ3': {
        'fully_automated': '90%',
        'semi_automated': '10%',
        'manual_only': '0%',
    },
    'RQ4': {
        'fully_automated': '30%',
        'semi_automated': '20%',
        'manual_only': '50%',
    },
    'Overall': {
        'fully_automated': '~55%',
        'semi_automated': '~20%',
        'manual_only': '~25%',
        'total_human_effort': '~60 hours'
    }
}
```

---

## ✅ Fully Automated Metrics

### RQ1: Theory-Guided Generation Effectiveness

#### 1.1 Triple Verification Pass Rate
```python
# 완전 자동 - 결정론적
def measure_triple_verification_pass_rate():
    """
    Method: Automated consistency + symbolic + completeness checker
    Output: PASS/FAIL binary per vulnerability
    Reliability: HIGH
    """
    results = {}
    for vuln in vulnerabilities:
        consistency_pass = consistency_checker.check(E_bug, E_patch)
        symbolic_pass = symbolic_verifier.verify(patched_code, E_bug)
        completeness_pass = completeness_checker.check(E_bug, E_patch)
        
        results[vuln.id] = {
            'triple_pass': all([consistency_pass, symbolic_pass, completeness_pass]),
            'breakdown': {
                'consistency': consistency_pass,
                'symbolic': symbolic_pass,
                'completeness': completeness_pass
            }
        }
    return results

# Automation: 100%
# Human effort: 0 hours (setup script once)
# Runtime: ~5-10 minutes for 10 vulnerabilities
```

#### 1.2 First Attempt Success Rate
```python
# 완전 자동
def measure_first_attempt_success():
    """
    Method: Check if first LLM response passes verification
    Output: Boolean per vulnerability
    """
    results = {}
    for vuln in vulnerabilities:
        first_patch = llm_patcher.generate(vuln, E_bug, max_attempts=1)
        verification = verify_triple(first_patch)
        results[vuln.id] = verification.success
    
    return {
        'first_attempt_success_rate': sum(results.values()) / len(results),
        'per_vulnerability': results
    }

# Automation: 100%
# Human effort: 0 hours
# Runtime: ~3-5 minutes
```

### RQ2: Dual Verification Effectiveness

#### 2.1 Consistency Violation Counts
```python
# 완전 자동
def measure_consistency_violations():
    """
    Method: Automated consistency checker with categorization
    Output: Count of violations per category
    """
    violations = {
        'causal_coverage': [],      # E_bug causes not in E_patch addressed
        'intervention_validity': [], # Intervention not in code
        'logical_consistency': [],   # φ_bug not proven false
        'completeness': []           # Paths not disrupted
    }
    
    for vuln, patch in patches:
        result = consistency_checker.check_detailed(E_bug[vuln], E_patch[patch])
        for category, failed in result.failures.items():
            if failed:
                violations[category].append(vuln)
    
    return {
        'total_violations': sum(len(v) for v in violations.values()),
        'by_category': {k: len(v) for k, v in violations.items()},
        'details': violations
    }

# Automation: 100%
# Human effort: 0 hours
# Runtime: ~2-3 minutes
```

#### 2.2 Verification Agreement Rate
```python
# 완전 자동
def measure_verification_agreement():
    """
    Method: Compare results from 3 verification methods
    Output: Agreement rate (0.0-1.0)
    """
    agreements = []
    
    for vuln, patch in patches:
        v1_exploit = exploit_tester.test(patch)
        v2_symbolic = symbolic_verifier.verify(patch)
        v3_consistency = consistency_checker.check(E_bug, E_patch)
        
        # All three agree?
        all_pass = v1_exploit and v2_symbolic and v3_consistency
        all_fail = not (v1_exploit or v2_symbolic or v3_consistency)
        agreements.append(all_pass or all_fail)
    
    return {
        'agreement_rate': sum(agreements) / len(agreements),
        'disagreements': [i for i, a in enumerate(agreements) if not a]
    }

# Automation: 100%
# Human effort: 0 hours
# Runtime: ~5-8 minutes (symbolic execution takes time)
```

### RQ3: Scalability and Performance

#### 3.1 Time Measurements (All Automated)
```python
# 완전 자동
import time
import psutil

class PerformanceProfiler:
    def __init__(self):
        self.metrics = {
            'phase1_times': [],
            'phase2_times': [],
            'phase3_times': [],
            'total_times': [],
            'llm_api_times': [],
            'iteration_counts': [],
            'peak_memory_mb': [],
            'symbolic_paths': [],
            'smt_queries': []
        }
    
    def profile_vulnerability(self, vuln):
        start_total = time.time()
        process = psutil.Process()
        
        # Phase 1: Formalization
        start_p1 = time.time()
        E_bug, scm, pcg = formalize_vulnerability(vuln)
        phase1_time = time.time() - start_p1
        
        # Phase 2: Generation
        start_p2 = time.time()
        llm_start = time.time()
        patch = llm_patcher.generate(vuln, E_bug)
        llm_time = time.time() - llm_start
        E_patch = generate_patch_explanation(patch, E_bug, scm)
        phase2_time = time.time() - start_p2
        
        # Phase 3: Verification
        start_p3 = time.time()
        verification = verify_triple(patch, E_bug, E_patch)
        phase3_time = time.time() - start_p3
        
        total_time = time.time() - start_total
        peak_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        return {
            'phase1': phase1_time,
            'phase2': phase2_time,
            'phase3': phase3_time,
            'llm_api': llm_time,
            'total': total_time,
            'peak_memory_mb': peak_memory,
            'iterations': verification.iteration_count,
            'symbolic_paths': verification.paths_explored,
            'smt_queries': verification.smt_queries
        }

# Automation: 100%
# Human effort: ~2 hours (write profiling script once)
# Runtime: Same as normal execution (overhead minimal)
```

#### 3.2 Scalability by Complexity
```python
# 완전 자동
def analyze_scalability():
    """
    Method: Stratify by LoC and plot time vs complexity
    """
    import matplotlib.pyplot as plt
    import numpy as np
    
    results = []
    for vuln in vulnerabilities:
        loc = count_lines_of_code(vuln.code)
        time_taken = profile_vulnerability(vuln)['total']
        results.append({'loc': loc, 'time': time_taken})
    
    # Categorize
    simple = [r for r in results if r['loc'] < 50]
    medium = [r for r in results if 50 <= r['loc'] < 100]
    complex = [r for r in results if r['loc'] >= 100]
    
    # Statistics
    stats = {
        'simple': {
            'count': len(simple),
            'avg_time': np.mean([r['time'] for r in simple]),
            'max_time': np.max([r['time'] for r in simple]) if simple else 0
        },
        'medium': {
            'count': len(medium),
            'avg_time': np.mean([r['time'] for r in medium]),
            'max_time': np.max([r['time'] for r in medium]) if medium else 0
        },
        'complex': {
            'count': len(complex),
            'avg_time': np.mean([r['time'] for r in complex]),
            'max_time': np.max([r['time'] for r in complex]) if complex else 0
        }
    }
    
    # Auto-generate plot
    plt.scatter([r['loc'] for r in results], [r['time'] for r in results])
    plt.xlabel('Lines of Code')
    plt.ylabel('Processing Time (seconds)')
    plt.title('Scalability Analysis')
    plt.savefig('scalability_analysis.png')
    
    return stats

# Automation: 100%
# Human effort: 0 hours (automated plotting)
# Runtime: Included in profiling
```

### RQ4: Explanation Quality

#### 4.1 Checklist-Based Coverage
```python
# 완전 자동
import re
from typing import List, Dict

def measure_checklist_coverage(explanation: Dict) -> float:
    """
    Method: Regex/AST-based keyword detection
    Output: Coverage percentage (0.0-1.0)
    """
    checklist = {
        'vulnerability_type': {
            'patterns': [r'CWE-\d+', r'buffer overflow', r'null dereference', 
                        r'integer overflow', r'memory leak'],
            'found': False
        },
        'vulnerable_line': {
            'patterns': [r'line \d+', r'at line', r'location:'],
            'found': False
        },
        'root_cause': {
            'patterns': [r'cause:', r'root cause', r'because', r'due to'],
            'found': False
        },
        'formal_condition': {
            'patterns': [r'V_\w+\s*⟺', r'∧', r'∨', r'formal_condition'],
            'found': False
        },
        'intervention': {
            'patterns': [r'do\(', r'intervention', r'patch adds', r'patch ensures'],
            'found': False
        },
        'causal_paths': {
            'patterns': [r'→', r'path:', r'causal_paths'],
            'found': False
        }
    }
    
    text = str(explanation)
    for item, config in checklist.items():
        for pattern in config['patterns']:
            if re.search(pattern, text, re.IGNORECASE):
                config['found'] = True
                break
    
    coverage = sum(1 for item in checklist.values() if item['found']) / len(checklist)
    
    return {
        'coverage': coverage,
        'missing_items': [k for k, v in checklist.items() if not v['found']],
        'details': checklist
    }

# Automation: 100%
# Human effort: 1 hour (define checklist once)
# Runtime: <1 second per explanation
```

#### 4.2 LLM Judge Auto-Scoring
```python
# 완전 자동 (하지만 variance 있음)
async def llm_judge_score(explanation: str) -> Dict[str, float]:
    """
    Method: Private LLM API for automated grading
    Reliability: MEDIUM (LLM variance)
    """
    prompt = f"""
    You are an expert security researcher evaluating a vulnerability patch explanation.
    
    Rate the following explanation on three dimensions (1-5 scale):
    1. Accuracy: Are the causal relationships and technical details correct?
    2. Clarity: Is the explanation easy to understand?
    3. Causal Coherence: Does the intervention logically address the identified causes?
    
    Explanation:
    {explanation}
    
    Provide your response in JSON format:
    {{
        "accuracy": <score 1-5>,
        "clarity": <score 1-5>,
        "causal_coherence": <score 1-5>,
        "justification": "<brief explanation>"
    }}
    """
    
    response = await llm_client.complete(prompt, temperature=0.0)
    scores = json.loads(response)
    
    return scores

# Automation: 100% (but need validation)
# Human effort: 1 hour (validate on sample)
# Runtime: ~5 seconds per explanation (API call)
# Cost: ~$0.01 per explanation
```

---

## 🔄 Semi-Automated Metrics

### RQ1: Theory-Guided Generation

#### 1.3 Ground Truth Similarity
```python
# 반자동: Automated metric + Manual verification
def compute_ground_truth_similarity(generated_patch, ground_truth_patch):
    """
    Automated Part: AST diff, token-level similarity
    Manual Part: Semantic equivalence judgment
    """
    # Step 1: Automated - Structural similarity
    ast_similarity = compute_ast_similarity(generated_patch, ground_truth_patch)
    token_bleu = compute_bleu_score(generated_patch, ground_truth_patch)
    
    # Step 2: Automated - Flag potential semantic equivalents
    if 0.3 < ast_similarity < 0.7:
        flag_for_manual_review = True
    
    # Step 3: Manual - Human judges semantic equivalence
    # Example: 'if (len > 256) return;' vs 'len = min(len, 256);'
    # Both fix the bug but have different structure
    
    return {
        'automated_scores': {
            'ast_similarity': ast_similarity,
            'token_bleu': token_bleu
        },
        'needs_manual_review': flag_for_manual_review
    }

# Automation: 70%
# Manual effort: LOW - 10 cases × 3 min = 30 minutes
# Process:
#   1. Auto-compute structural metrics
#   2. Flag ambiguous cases
#   3. Manual: Judge semantic equivalence
```

#### 1.4 E_bug Completeness Analysis
```python
# 반자동: Ground truth extraction 필요
def evaluate_E_bug_completeness(E_bug, vuln):
    """
    Automated Part: Parse E_bug causes
    Manual Part: Extract ground truth causes from CVE
    """
    # Step 1: Manual - Extract ground truth causes
    # Researcher analyzes CVE description + actual patch
    # Identifies true root causes (done once per vulnerability)
    ground_truth_causes = load_manual_annotation(vuln.id)
    
    # Step 2: Automated - Parse E_bug
    identified_causes = set(E_bug['causal_paths'])
    
    # Step 3: Automated - Compute metrics
    true_positives = identified_causes & ground_truth_causes
    false_positives = identified_causes - ground_truth_causes
    false_negatives = ground_truth_causes - identified_causes
    
    precision = len(true_positives) / len(identified_causes) if identified_causes else 0
    recall = len(true_positives) / len(ground_truth_causes) if ground_truth_causes else 0
    
    return {
        'precision': precision,
        'recall': recall,
        'true_positives': list(true_positives),
        'false_positives': list(false_positives),
        'false_negatives': list(false_negatives)
    }

# Automation: 40%
# Manual effort: MEDIUM - 10 cases × 12 min = 2 hours
# Process:
#   1. Manual: Analyze CVE + patch to extract ground truth causes
#   2. Automated: Parse E_bug causes
#   3. Automated: Compute precision/recall
```

### RQ2: Dual Verification Effectiveness

#### 2.3 Incomplete Patch Injection & Detection
```python
# 반자동: Manual design + Automated testing
class IncompletePatchGenerator:
    """
    Automated Part: Template-based generation + Testing
    Manual Part: Design realistic incomplete patterns
    """
    
    def __init__(self):
        # Step 1: Manual - Design incomplete patterns (done once)
        self.patterns = self.design_incomplete_patterns()
    
    def design_incomplete_patterns(self):
        """
        Manual effort: HIGH - Design realistic incomplete patches
        Time: ~4 hours for 10 vulns × 2-3 variants each
        
        Example patterns:
        - Pattern 1: Check positive but miss negative values
        - Pattern 2: Patch one code path, miss alternative path
        - Pattern 3: Add type check but miss size check
        - Pattern 4: Fix symptom but not root cause
        """
        return {
            'buffer_overflow': [
                {
                    'name': 'positive_only_check',
                    'code_template': 'if (len > MAX) return;  // Misses len < 0',
                    'bypasses': ['negative_length']
                },
                {
                    'name': 'one_path_only',
                    'code_template': 'if (branch_A) { check(len); }  // Misses branch_B',
                    'bypasses': ['alternative_path']
                }
            ],
            'null_deref': [
                {
                    'name': 'shallow_check',
                    'code_template': 'if (ptr) { ... }  // Misses ptr->field null check',
                    'bypasses': ['nested_null']
                }
            ]
        }
    
    def generate_incomplete_patch(self, vuln, pattern_name):
        """Automated: Apply pattern to vulnerability"""
        pattern = self.patterns[vuln.type][pattern_name]
        return apply_template(vuln.code, pattern)
    
    def test_detection(self, incomplete_patches):
        """Automated: Test all verification methods"""
        results = []
        for patch in incomplete_patches:
            v1_result = exploit_test(patch)       # Automated
            v2_result = symbolic_verify(patch)    # Automated
            v3_result = consistency_check(patch)  # Automated
            v4_result = triple_verify(patch)      # Automated
            
            results.append({
                'patch_id': patch.id,
                'exploit_test': v1_result,
                'symbolic': v2_result,
                'consistency': v3_result,
                'triple': v4_result
            })
        
        return results

# Automation: 60%
# Manual effort: HIGH - ~4 hours (pattern design)
# Process:
#   1. Manual: Design realistic incomplete patterns
#   2. Automated: Generate incomplete patches from templates
#   3. Automated: Test with all verification methods
#   4. Manual: Validate ground truth (is it actually incomplete?)
```

#### 2.4 False Positive/Negative Analysis
```python
# 반자동: Automated collection + Manual judgment
def analyze_verification_errors():
    """
    Automated Part: Collect FAIL cases
    Manual Part: Judge if truly incorrect
    """
    # Step 1: Automated - Collect verification failures
    false_positive_candidates = [
        p for p in patches 
        if verification_result[p] == 'FAIL'
    ]
    
    # Step 2: Manual - Expert review
    # For each candidate, security expert answers:
    #   Q1: Is the vulnerability actually fixed?
    #   Q2: Is the verification too conservative?
    #   Q3: Is this an edge case?
    
    manual_reviews = {}
    for patch in false_positive_candidates:
        # Expert inspection: ~10-15 minutes per case
        review = {
            'actually_correct': None,  # True/False
            'reason': '',
            'variant_exploit_attempted': None  # Did we try to bypass?
        }
        manual_reviews[patch.id] = review
    
    # Step 3: Automated - Compute FP/FN rates
    true_fps = sum(1 for r in manual_reviews.values() if r['actually_correct'])
    
    return {
        'false_positive_count': true_fps,
        'false_positive_rate': true_fps / len(patches),
        'details': manual_reviews
    }

# Automation: 50%
# Manual effort: MEDIUM - 5-10 cases × 12 min = 1-2 hours
# Process:
#   1. Automated: Flag FAIL cases
#   2. Manual: Expert reviews each case
#   3. Automated: Compute statistics
```

### RQ3: Scalability and Performance

#### 3.3 Bottleneck Analysis
```python
# 반자동: Automated profiling + Manual interpretation
import cProfile
import pstats

def analyze_bottlenecks():
    """
    Automated Part: Profiling and data collection
    Manual Part: Root cause analysis and recommendations
    """
    # Step 1: Automated - Profile execution
    profiler = cProfile.Profile()
    profiler.enable()
    
    # Run system
    for vuln in vulnerabilities:
        patchscribe.run(vuln)
    
    profiler.disable()
    stats = pstats.Stats(profiler)
    
    # Step 2: Automated - Identify top time consumers
    top_functions = stats.sort_stats('cumulative').print_stats(20)
    
    # Step 3: Manual - Interpret results
    # Researcher analyzes:
    #   - Why is function X slow? (path explosion? large AST?)
    #   - Can it be optimized? (caching? pruning?)
    #   - Is it inherent complexity or implementation issue?
    
    # Manual report writing: ~1 hour
    
    return {
        'top_time_consumers': top_functions,
        'manual_analysis': 'See bottleneck_report.md'
    }

# Automation: 80%
# Manual effort: LOW - ~1 hour (analysis + report)
```

---

## 👤 Manual-Only Metrics

### RQ1: Theory-Guided Generation

#### 1.5 Patch Semantic Correctness
```
Why Manual: Functional equivalence requires domain expertise
Method: Security expert review
Effort: HIGH - 10 cases × 2 reviewers × 15 min = 5 hours

Process:
1. Reviewer examines:
   - Vulnerable code
   - Generated patch
   - CVE description
   - Ground truth patch (if available)

2. Answer questions:
   Q1: Does the patch fix the root cause?
       □ Yes, completely
       □ Partially (specify what's missing)
       □ No, superficial fix only
   
   Q2: Are there any potential bypasses?
       □ No bypasses found
       □ Possible bypass: [describe]
       □ Definite bypass: [describe + demonstrate]
   
   Q3: Is functionality preserved?
       □ Yes, no side effects
       □ Possible regression: [describe]
       □ Breaks functionality: [describe]
   
   Q4: Overall assessment:
       □ Production-ready
       □ Needs minor refinement
       □ Needs major rework
       □ Fundamentally flawed

3. Inter-rater reliability:
   - Cohen's Kappa between reviewers
   - Discuss disagreements
   - Reach consensus
```

#### 1.6 Intervention Relevance
```
Why Manual: Domain knowledge required
Method: Expert evaluation of E_bug intervention options
Effort: MEDIUM - 10 cases × 10 min = ~2 hours

For each E_bug, expert rates intervention options:
1. Are the suggested interventions technically sound?
   (1=incorrect, 5=perfect)

2. Do they address the actual root cause?
   (1=no, 5=directly addresses)

3. Are they practical to implement?
   (1=infeasible, 5=straightforward)

4. Completeness: Are any options missing?
   □ Complete
   □ Missing option: [describe]
```

### RQ2: Dual Verification Effectiveness

#### 2.5 Ground Truth Labeling (Complete/Incomplete)
```
Why Manual: Security domain expertise required
Method: Variant exploit generation + testing
Effort: HIGH - 10 patches × 30 min = ~5 hours

Process per patch:
1. Analyze original exploit
   - Understand attack vector
   - Identify assumptions

2. Design variant exploits
   - Different input values
   - Alternative code paths
   - Edge cases (negative, zero, MAX_INT, etc.)
   - Bypass attempts

3. Test each variant
   - Does it trigger vulnerability in original code?
   - Does it bypass the patch?

4. Classification:
   □ Complete: All variants blocked
   □ Incomplete: At least one variant succeeds
   
5. Document:
   - Which variants bypassed (if any)
   - Root cause of incompleteness
   - What the patch should have done
```

#### 2.6 False Negative Validation
```
Why Manual: Adversarial mindset required
Method: Security expert adversarial testing
Effort: MEDIUM - ~3 hours total

Goal: Find patches that PASSED verification but are actually vulnerable

Process:
1. For each PASS case, try to find bypasses:
   - Craft variant exploits
   - Test edge cases
   - Review code for logic flaws

2. If bypass found:
   - Document the bypass
   - Analyze why verification missed it
   - Categorize: false negative type

3. Report:
   - False negative count
   - Root causes (verification limitation)
   - Recommendations for improvement
```

### RQ4: Explanation Quality and Developer Trust

#### 4.3 User Study (Entire Process)
```
Why Manual: Human perception measurement
Participants: 12 security-aware developers
Effort: 
  - Participant time: 12 × 1.5 hours = 18 hours
  - Researcher time: Prep (4h) + Conduct (18h) + Analysis (6h) = 28 hours

Setup:
- Within-subject design (each participant sees all 4 conditions)
- 6 vulnerabilities total (counterbalanced order)
- 4 explanation conditions:
  E1: No explanation (code diff only)
  E2: Post-hoc LLM explanation
  E3: E_bug only
  E4: Dual explanations (E_bug + E_patch + verification)

Tasks per vulnerability (4 × 6 = 24 tasks total per participant):
1. Patch Review (5 min)
   - Read code + patch + explanation
   - Rate understanding (1-5 Likert)
   - Rate trust (1-5 Likert)

2. Bug Finding (5 min)
   - Deliberately incomplete patch provided
   - "Can you identify what's missing?"
   - Record: found issue (Y/N) + time taken

3. Deployment Decision (2 min)
   - "Would you deploy this to production?"
   - Yes / No / Needs more review
   - Brief rationale

4. Questionnaire per condition (3 min)
   - Understanding: "How well do you understand why the patch works?"
   - Trust: "How much do you trust this patch?"
   - Clarity: "How clear was the explanation?"
   - Helpfulness: "Did the explanation help you identify issues?"
   - Preference: "Which explanation style would you prefer in practice?"

Data Collection:
- Quantitative: Likert scores, decision counts, times
- Qualitative: Open-ended feedback, rationales

Analysis:
- Statistical: Repeated measures ANOVA (condition effect)
- Post-hoc: Pairwise comparisons with Bonferroni correction
- Qualitative: Thematic analysis of feedback
  - Code feedback statements
  - Identify recurring themes
  - Support with participant quotes

Expected Findings:
- E4 > E3 > E2 > E1 for trust and understanding
- E4 helps identify incomplete patches more often
- Participants prefer formal explanations for security-critical code
```

#### 4.4 Expert Quality Assessment
```
Why Manual: Deep domain expertise for quality judgment
Method: Security expert panel review
Participants: 2-3 security researchers
Effort: HIGH - 10 cases × 3 reviewers × 20 min = ~10 hours

For each vulnerability's E_bug and E_patch:

Rating Dimensions (1-5 Likert scale):

1. Accuracy
   E_bug: Are the identified causes actually the root causes?
   E_patch: Does the intervention correctly describe what the patch does?
   Score 1: Major errors
   Score 5: Perfectly accurate

2. Completeness  
   E_bug: Are all causal factors identified?
   E_patch: Are all addressed causes listed?
   Score 1: Missing critical elements
   Score 5: Comprehensive

3. Clarity
   Both: Can a developer understand the explanation?
   Score 1: Confusing, requires expertise
   Score 5: Crystal clear

4. Actionability
   E_bug: Do intervention options provide clear guidance?
   E_patch: Can a developer verify the fix from the explanation?
   Score 1: Vague, not actionable
   Score 5: Directly actionable

Open-ended questions:
- What information is most valuable in this explanation?
- What is missing or unclear?
- Would you trust a patch with this explanation?
- Suggestions for improvement?

Inter-rater Agreement:
- Compute ICC (Intraclass Correlation Coefficient)
- Discuss major disagreements (|score1 - score2| ≥ 2)
- Reach consensus on contentious cases

Final Output:
- Mean scores per dimension
- Variance/agreement metrics
- Qualitative themes from feedback
- Concrete examples of good/bad explanations
```

---

## 📅 Execution Timeline

```python
execution_timeline = {
    'Phase 1: Automated Execution': {
        'duration': '1-2 days',
        'human_effort': '~4 hours (setup + monitoring)',
        'tasks': [
            'Run all automated metrics (RQ1-RQ4)',
            'Triple verification on all patches',
            'Time/resource profiling',
            'LLM judge auto-scoring',
            'Checklist-based evaluation'
        ],
        'deliverables': [
            'metrics_automated.json',
            'time_breakdown.csv',
            'verification_results.json',
            'llm_judge_scores.json'
        ]
    },
    
    'Phase 2: Semi-Automated': {
        'duration': '2-3 days',
        'human_effort': '~10 hours',
        'tasks': [
            'Design incomplete patch patterns (~4h)',
            'Ground truth similarity validation (~2h)',
            'E_bug completeness annotation (~2h)',
            'False positive/negative analysis (~2h)'
        ],
        'deliverables': [
            'incomplete_patches.json',
            'ground_truth_annotations.json',
            'fp_fn_analysis.csv'
        ]
    },
    
    'Phase 3: Manual Expert Review': {
        'duration': '3-4 days',
        'human_effort': '~18 hours (2-3 experts)',
        'tasks': [
            'Patch semantic correctness review (~5h)',
            'Ground truth labeling (variant exploits) (~5h)',
            'Explanation quality expert review (~10h)',
            'False negative adversarial testing (~3h)'
        ],
        'deliverables': [
            'expert_reviews.csv',
            'inter_rater_agreement.json',
            'qualitative_notes.md',
            'variant_exploits.json'
        ]
    },
    
    'Phase 4: User Study': {
        'duration': '1-2 weeks (scheduling)',
        'human_effort': '~28h (researcher) + ~18h (participants)',
        'tasks': [
            'Study design + IRB (~4h)',
            'Material preparation (~4h)',
            'Participant recruitment (~2h)',
            'Study sessions (12 × 1.5h)',
            'Data analysis (~6h)'
        ],
        'deliverables': [
            'user_study_data.csv',
            'survey_responses.json',
            'thematic_analysis.md',
            'statistical_tests_results.csv'
        ]
    },
    
    'Phase 5: Analysis & Reporting': {
        'duration': '3-5 days',
        'human_effort': '~12 hours',
        'tasks': [
            'Aggregate all metrics',
            'Statistical analysis',
            'Generate plots/tables',
            'Write evaluation section',
            'Prepare artifact package'
        ],
        'deliverables': [
            'evaluation_results_final.pdf',
            'plots/',
            'tables/',
            'artifact.zip'
        ]
    }
}

total_timeline = {
    'calendar_time': '3-4 weeks',
    'total_human_effort': '~72 hours',
    'breakdown': {
        'automated_monitoring': '4 hours',
        'semi_automated': '10 hours',
        'manual_expert': '18 hours',
        'user_study_researcher': '28 hours',
        'analysis_reporting': '12 hours'
    }
}
```

---

## 🎯 Automation Priority Recommendations

### High Priority (Implement First)
```python
automate_first = [
    {
        'metric': 'Triple verification pipeline',
        'reason': 'Core contribution, frequently used',
        'effort': '1 week',
        'value': 'Very High'
    },
    {
        'metric': 'Time/resource profiling',
        'reason': 'Easy to automate, needed for all runs',
        'effort': '1 day',
        'value': 'High'
    },
    {
        'metric': 'Consistency checking automation',
        'reason': 'Deterministic, key innovation',
        'effort': '3 days',
        'value': 'Very High'
    },
    {
        'metric': 'Checklist-based evaluation',
        'reason': 'Simple regex/AST, reduces manual effort',
        'effort': '1 day',
        'value': 'Medium'
    }
]
```

### Medium Priority
```python
automate_next = [
    {
        'metric': 'LLM judge for explanation scoring',
        'reason': 'Reduces manual review time significantly',
        'effort': '2 days',
        'value': 'Medium',
        'note': 'Still need sampling validation'
    },
    {
        'metric': 'AST-based similarity metrics',
        'reason': 'Faster than manual comparison',
        'effort': '2 days',
        'value': 'Medium'
    },
    {
        'metric': 'Incomplete patch template generator',
        'reason': 'Reusable patterns once designed',
        'effort': '3 days',
        'value': 'Medium'
    }
]
```

### Keep Manual (or Low Priority)
```python
keep_manual = [
    {
        'task': 'User study',
        'reason': 'Inherently requires human judgment',
        'cannot_automate': True
    },
    {
        'task': 'Semantic correctness validation',
        'reason': 'Requires security expertise',
        'cannot_automate': True
    },
    {
        'task': 'Ground truth cause extraction',
        'reason': 'Requires CVE analysis expertise, low frequency',
        'effort_acceptable': '2 hours for 10 cases'
    },
    {
        'task': 'Adversarial testing (false negatives)',
        'reason': 'Requires creative adversarial mindset',
        'effort_acceptable': '3 hours total'
    }
]
```

---

## 📈 Expected Automation Benefits

```python
automation_benefits = {
    'time_savings': {
        'without_automation': '~120 hours',
        'with_automation': '~72 hours',
        'savings': '~40% reduction'
    },
    
    'consistency': {
        'automated_metrics': 'Perfect reproducibility',
        'manual_metrics': 'Subject to inter-rater variance'
    },
    
    'scalability': {
        'automated': 'Can easily extend to 50+ vulnerabilities',
        'manual': 'Linear increase in human effort'
    },
    
    'cost': {
        'initial_investment': '~2 weeks engineering time',
        'per_experiment_savings': '~48 hours',
        'break_even': 'After 1 full evaluation run'
    }
}
```

---

## 🔧 Implementation Notes

### Automation Infrastructure

```python
# Recommended tooling
automation_stack = {
    'profiling': ['cProfile', 'line_profiler', 'psutil'],
    'verification': ['angr', 'KLEE', 'Z3'],
    'analysis': ['pandas', 'numpy', 'scipy'],
    'visualization': ['matplotlib', 'seaborn'],
    'nlp_metrics': ['nltk', 'rouge-score'],
    'llm_interaction': ['openai', 'anthropic'],
    'orchestration': ['Python', 'Jupyter notebooks'],
    'ci_cd': ['GitHub Actions', 'Docker']
}

# Suggested project structure
automation_directory = """
evaluation/
├── automated/
│   ├── triple_verification.py      # RQ1, RQ2
│   ├── time_profiler.py            # RQ3
│   ├── checklist_evaluator.py      # RQ4
│   ├── llm_judge.py                # RQ4
│   └── metrics_aggregator.py       # All RQs
│
├── semi_automated/
│   ├── similarity_validator.py     # RQ1
│   ├── incomplete_generator.py     # RQ2
│   ├── fp_fn_analyzer.py           # RQ2
│   └── annotations/                # Manual annotations
│
├── manual/
│   ├── expert_review_protocol.md
│   ├── user_study_protocol.md
│   ├── review_forms/
│   └── results/
│
├── scripts/
│   ├── run_full_evaluation.py      # Main orchestrator
│   ├── generate_report.py          # Auto-generate tables/plots
│   └── export_artifact.py          # Package for reproducibility
│
└── configs/
    ├── datasets.yaml
    ├── baselines.yaml
    └── metrics.yaml
"""
```

### Quality Assurance

```python
qa_checklist = {
    'before_evaluation': [
        '☐ All automated scripts tested on sample data',
        '☐ Manual protocols reviewed by co-authors',
        '☐ IRB approval obtained (if needed for user study)',
        '☐ Baseline systems reproduced and verified',
        '☐ Ground truth annotations done independently'
    ],
    
    'during_evaluation': [
        '☐ Log all automated runs (timestamps, versions)',
        '☐ Backup raw data continuously',
        '☐ Inter-rater agreement checked regularly',
        '☐ Anomalies investigated immediately',
        '☐ Progress documented in lab notebook'
    ],
    
    'after_evaluation': [
        '☐ All metrics double-checked',
        '☐ Statistical tests validated',
        '☐ Qualitative themes reviewed by multiple researchers',
        '☐ Artifact package tested by external validator',
        '☐ Results reproducible from raw data'
    ]
}
```

---

## 📝 Summary

**Total Evaluation Effort:**
- Automated: ~55% (mostly one-time setup + monitoring)
- Semi-automated: ~20% (reduces from 100% manual)
- Manual-only: ~25% (inherently requires human judgment)

**Timeline:** 3-4 weeks calendar time, ~72 hours human effort

**Key Insight:** Strategic automation of verification, profiling, and checklist-based metrics saves ~40% time while maintaining rigor. Manual effort concentrates on irreducible tasks (expert review, user study) that provide unique insights automation cannot replace.

**Recommended Approach:** 
1. Automate everything possible (Phases 1-2)
2. Use semi-automation to scale manual tasks (Phase 3)
3. Focus precious human time on high-value manual evaluation (Phase 4)
4. Validate automated metrics with manual sampling

This balanced approach maximizes both efficiency and evaluation quality.

