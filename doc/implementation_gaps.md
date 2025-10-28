# PatchScribe: Draft vs Implementation Gap Analysis

## 분석 일자: 2025년 10월 28일

본 문서는 draft.txt에 명시된 방법론 및 평가 계획 대비 실제 구현된 코드의 부족한 점을 정리합니다.

---

## 1. 방법론 (Methodology) 관련 Gap

### 1.1 Phase 1: Vulnerability Formalization

#### ✅ 구현된 부분
- **PCG (Program Causal Graph) 구축**: `pcg_builder.py`에서 정적/동적/심볼릭 분석 통합
- **SCM (Structural Causal Model) 도출**: `scm.py`에서 변수 정의 및 구조 방정식 생성
- **Intervention Planning**: `intervention.py`에서 SMT 기반 최소 차단 조건 계산

#### ❌ 부족한 부분

**1.1.1 Formal Bug Specification (E_bug) Generation이 불완전**

Draft 요구사항:
```python
E_bug = {
    "formal_condition": "V_bug ⟺ φ(X₁, ..., Xₙ)",
    "variables": {...},
    "description": "...",
    "causal_paths": [...],
    "intervention_options": [...],
    "safety_property": "∀inputs: ¬V_bug(inputs)",
    "preconditions": [...],
    "postconditions": [...],
    "assertions": [...]
}
```

현재 구현 (`scm.py`):
```python
# vulnerable_condition만 생성됨
self.model.vulnerable_condition = condition  # 단순 AND 조합
# 하지만 다음이 누락됨:
# - 변수의 코드 위치 매핑이 PCG 노드에만 있고 E_bug에 통합되지 않음
# - preconditions/postconditions가 명시적으로 생성되지 않음
# - assertions가 자동 생성되지 않음
# - intervention_options가 InterventionSpec과 분리되어 있음
```

**문제점:**
1. `E_bug`가 독립적인 데이터 구조로 생성되지 않음
2. LLM에게 전달할 formal specification이 분산되어 있음
3. Verification을 위한 assertions이 자동 생성되지 않음

**필요한 작업:**
```python
# 새로운 모듈: patchscribe/formal_spec.py
@dataclass
class FormalBugExplanation:
    """Phase 1 output: Complete formal bug specification"""
    formal_condition: str  # From SCM
    variables: Dict[str, VariableSpec]  # From PCG + SCM
    description: str  # Natural language
    vulnerable_location: str  # From PCG
    causal_paths: List[CausalPath]  # From PCG
    intervention_options: List[InterventionOption]  # From InterventionSpec
    safety_property: str  # "∀inputs: ¬V_bug(inputs)"
    preconditions: List[str]  # Input constraints
    postconditions: List[str]  # What must hold after patch
    assertions: List[Assertion]  # For verification

def generate_E_bug(pcg, scm, intervention_spec) -> FormalBugExplanation:
    """통합된 E_bug 생성 함수"""
    # 현재 분산된 정보를 모아서 완전한 E_bug 구조 생성
    pass
```

**1.1.2 Variable-to-Code Mapping이 약함**

Draft 요구사항:
```python
"variables": {
    "len": {
        "type": "integer",
        "meaning": "Length of user input",
        "code_location": "computed from user_input at line 15"
    }
}
```

현재 구현:
- PCG 노드에 `location` 필드는 있음
- 하지만 SCM 변수와 코드 라인의 명확한 매핑이 없음
- "computed from X at line N" 같은 상세 정보 없음

**필요한 작업:**
- PCG 구축 시 더 정밀한 데이터 흐름 추적
- 변수 정의/사용 위치를 SCM 변수에 연결

**1.1.3 Assertions 자동 생성 누락**

Draft 요구사항:
```python
"assertions": [
    "assert(len <= 256) at line 41 (before memcpy)",
    "assert(unreachable(line 42) when len > 256)"
]
```

현재 구현:
- Verification에서 assertion injection을 언급하지만 실제 자동 생성 없음
- `verification.py`가 수동으로 작성된 assertion을 찾을 뿐

**필요한 작업:**
```python
def generate_assertions(E_bug, vulnerable_code):
    """
    E_bug.postconditions로부터 C assert 문 자동 생성
    예: "len ≤ 256 at line 42" → "assert(len <= 256);"
    """
    assertions = []
    for postcond in E_bug.postconditions:
        # 형식 언어 → C 코드 변환
        assertion = translate_to_c_assert(postcond)
        assertions.append(assertion)
    return assertions
```

---

### 1.2 Phase 2: Theory-Guided Patch Generation

#### ✅ 구현된 부분
- **Formal Prompt Construction**: `explanation.py`의 `build_prompt_context()` 함수
- **LLM Patch Generation**: `patch.py`의 `PatchGenerator` 클래스
- **Patch Effect Analysis**: `effect_model.py`의 `PatchEffectAnalyzer`

#### ❌ 부족한 부분

**1.2.1 Formal Patch Explanation (E_patch) Generation이 불완전**

Draft 요구사항:
```python
E_patch = {
    "code_diff": {...},
    "intervention": {
        "formal": "do(Variable = value)",
        "affected_variables": [...],
        "description": "..."
    },
    "effect_on_Vbug": {
        "before": "V_bug = φ(...)",
        "after": "V_bug = φ'(...) = false",
        "reasoning": "..."
    },
    "addressed_causes": [...],
    "unaddressed_causes": [...],
    "disrupted_paths": [...],
    "postconditions": [...],
    "new_assertions": [...]
}
```

현재 구현 (`effect_model.py`):
```python
# PatchEffect 클래스가 있지만 E_patch 구조를 완전히 따르지 않음
effect = {
    "original_condition": "...",
    "patched_condition": "...",
    "vulnerability_removed": bool,
    "signature_found": bool
}
# 누락된 것:
# - intervention의 formal representation
# - affected_variables 명시적 리스트
# - addressed_causes vs unaddressed_causes 구분
# - disrupted_paths 분석
# - new_assertions 생성
```

**문제점:**
1. Patch의 causal intervention이 명시적으로 표현되지 않음
2. E_bug와 E_patch 간 매핑이 약함 (consistency checking을 위해 필수)
3. 어떤 cause가 addressed되었는지 명확하지 않음

**필요한 작업:**
```python
# patchscribe/formal_spec.py에 추가
@dataclass
class FormalPatchExplanation:
    """Phase 2 output: Complete formal patch explanation"""
    code_diff: CodeDiff
    intervention: InterventionDescription
    effect_on_Vbug: EffectAnalysis
    addressed_causes: List[str]  # From E_bug.causal_paths
    unaddressed_causes: List[str]  # With justification
    disrupted_paths: List[str]  # From PCG
    summary: str
    mechanism: str
    consequence: str
    postconditions: List[str]
    new_assertions: List[str]

def generate_E_patch(
    patch: PatchResult, 
    E_bug: FormalBugExplanation,
    pcg: ProgramCausalGraph,
    scm: StructuralCausalModel
) -> FormalPatchExplanation:
    """Patch를 분석하여 완전한 E_patch 생성"""
    # 1. Code diff 추출
    # 2. Intervention 식별 (어떤 SCM 변수가 변경되었나?)
    # 3. E_bug.causal_paths 중 어느 것이 disrupted되었나?
    # 4. Addressed/unaddressed causes 분류
    # 5. New assertions 생성
    pass
```

**1.2.2 Intervention Formalization이 약함**

Draft에서 강조하는 "do(Variable = value)" 표기법이 현재 구현에 명시적으로 없음:
- `InterventionSpec`은 있지만 실제 patch가 어떤 intervention을 수행하는지 formal하게 표현하지 않음
- Patch가 SCM 변수에 미치는 영향이 자동으로 계산되지 않음

**필요한 작업:**
```python
def formalize_intervention(patch_code, scm):
    """
    Patch code를 분석하여 SCM intervention으로 표현
    예: "if (len > 256) len = 256;" 
        → do(len = min(len, 256))
    """
    interventions = []
    # AST 분석으로 변경된 변수 식별
    modified_vars = extract_modified_variables(patch_code)
    for var in modified_vars:
        # SCM 변수와 매핑
        scm_var = map_to_scm_variable(var, scm)
        # Intervention 표현 생성
        intervention = f"do({scm_var.name} = {new_value_expr})"
        interventions.append(intervention)
    return interventions
```

**1.2.3 Causal Path Disruption 분석 누락**

Draft 요구사항:
```
"disrupted_paths": [
    "user_input → len → (len > 256) → V_overflow: "
    "Path is broken because len is now bounded by 256"
]
```

현재 구현:
- PCG에 경로는 있지만, patch가 어느 경로를 끊는지 자동 분석하지 않음

**필요한 작업:**
```python
def analyze_disrupted_paths(patch, E_bug, pcg):
    """
    Patch가 PCG의 어떤 경로를 끊는지 분석
    """
    disrupted = []
    for path in E_bug.causal_paths:
        if is_path_disrupted(path, patch, pcg):
            reason = explain_disruption(path, patch)
            disrupted.append(f"{path}: {reason}")
    return disrupted
```

---

### 1.3 Phase 3: Dual Verification

#### ✅ 구현된 부분
- **Symbolic Verification**: `verification.py`의 기본 검증 (guard 체크, 컴파일 체크)
- **Model Check**: 컴파일 + insecure API 검출
- **Fuzzing Check**: fail-fast return 검출

#### ❌ 부족한 부분

**1.3.1 Consistency Verification이 구현되지 않음 ⚠️ 핵심 누락**

Draft의 핵심 혁신인 Consistency Checking (E_bug ↔ E_patch)이 **완전히 누락**됨:

Draft 요구사항:
```python
# Check 1: Causal Coverage
for cause in E_bug.causal_paths:
    assert cause in E_patch.addressed_causes

# Check 2: Intervention Validity
assert E_patch.intervention appears in code_diff

# Check 3: Logical Consistency
substitute E_patch.intervention into E_bug.formal_condition
assert simplified_result == False

# Check 4: Completeness
for path in E_bug.causal_paths:
    assert path in E_patch.disrupted_paths
```

현재 구현:
```python
# verification.py에 이런 체크가 전혀 없음
# symbolic/model_check/fuzzing만 있고 consistency check 없음
```

**문제점:**
1. Draft의 핵심 기여인 "dual explanation verification"이 구현되지 않음
2. E_bug와 E_patch가 생성되어도 일관성 검증이 없음
3. 논문의 주장 "pre-hoc formalization + consistency checking"이 불완전

**필요한 작업 (최우선):**
```python
# 새로운 모듈: patchscribe/consistency_checker.py
class ConsistencyChecker:
    def check(self, E_bug, E_patch) -> ConsistencyResult:
        """Dual explanation consistency verification"""
        results = {
            'causal_coverage': self.check_causal_coverage(E_bug, E_patch),
            'intervention_validity': self.check_intervention_validity(E_patch),
            'logical_consistency': self.check_logical_consistency(E_bug, E_patch),
            'completeness': self.check_completeness(E_bug, E_patch)
        }
        return ConsistencyResult(results)
    
    def check_causal_coverage(self, E_bug, E_patch):
        """E_bug의 모든 cause가 E_patch에서 addressed되었는가?"""
        for cause in E_bug.causes:
            if cause not in E_patch.addressed_causes:
                if cause not in E_patch.unaddressed_causes:
                    return CheckOutcome(False, f"Cause {cause} not addressed")
        return CheckOutcome(True, "All causes addressed")
    
    def check_logical_consistency(self, E_bug, E_patch):
        """Intervention을 대입했을 때 V_bug가 false가 되는가?"""
        # SMT solver로 검증
        formula = substitute_intervention(
            E_bug.formal_condition, 
            E_patch.intervention
        )
        solver = Solver()
        solver.add(formula)
        if solver.check() == unsat:
            return CheckOutcome(True, "V_bug is logically false")
        else:
            return CheckOutcome(False, "V_bug still satisfiable")
```

**1.3.2 Symbolic Verification이 피상적**

Draft 요구사항:
```python
# Method 1: Symbolic Execution
# - KLEE/angr로 모든 경로 탐색
# - φ_bug 만족하면서 vulnerable location 도달 가능한지 체크
```

현재 구현:
```python
# verification.py의 _symbolic_check()는:
# - 단순히 guard 문자열에 vulnerability 토큰이 있는지만 체크
# - 실제 symbolic execution 엔진을 사용하지 않음
```

**필요한 작업:**
```python
def symbolic_verification_with_klee(patched_code, E_bug):
    """실제 KLEE/angr 기반 symbolic execution"""
    # 1. Patched code를 LLVM bitcode로 컴파일
    # 2. φ_bug를 path constraint로 추가
    # 3. Vulnerable location 도달 가능 여부 체크
    result = klee_runner.run(
        bitcode=compile_to_llvm(patched_code),
        constraint=E_bug.formal_condition,
        target=E_bug.vulnerable_location
    )
    if result.path_found:
        return CheckOutcome(False, f"Counterexample: {result.input}")
    else:
        return CheckOutcome(True, "V_bug provably unreachable")
```

**1.3.3 Assertion Injection이 구현되지 않음**

Draft 요구사항:
```python
# Method 2: Assertion Injection
# E_patch.new_assertions를 코드에 삽입
# CBMC로 assertion violation 체크
```

현재 구현:
- Assertion 생성도 없고, injection도 없음

**1.3.4 Completeness Checking이 누락**

Draft의 Check 4 (모든 causal path가 disrupted되었는가?)가 구현되지 않음

---

## 2. 평가 (Evaluation) 관련 Gap

### 2.1 RQ1: Theory-Guided Generation Effectiveness

#### ✅ 구현된 부분
- `evaluation.py`에서 기본 metrics:
  - Success rate (verification.overall)
  - Ground truth match rate (코드 비교)

#### ❌ 부족한 부분

**2.1.1 Triple Verification Pass Rate이 불완전**

Draft 요구사항:
```
Triple verification = consistency + symbolic + completeness
```

현재 구현:
```python
# verification.py의 overall은:
# symbolic + model_check + fuzzing
# 하지만 consistency는 없음!
```

**수정 필요:**
```python
verification = {
    'consistency': consistency_checker.check(E_bug, E_patch),  # 누락됨
    'symbolic': symbolic_verifier.verify(...),
    'completeness': completeness_checker.check(...)  # 누락됨
}
```

**2.1.2 First-Attempt Success Rate 측정 안 됨**

Draft 요구사항:
```
LLM의 첫 시도가 성공하는 비율 (guidance 품질 지표)
```

현재 구현:
```python
# pipeline.py는 max_iterations로 여러 번 시도하지만
# 첫 시도만 따로 기록하지 않음
```

**필요한 작업:**
```python
# pipeline.py 수정
iterations: List[Dict] = []
first_attempt_success = None
for i in range(max_iterations):
    patch = generate_patch(...)
    verification = verify(patch)
    if i == 0:
        first_attempt_success = verification.overall
    iterations.append({...})
```

**2.1.3 Ablation Study가 없음**

Draft 요구사항:
```
C1: Post-hoc (no formal guidance)
C2: Vague hints
C3: Pre-hoc guidance (E_bug only)
C4: Full PatchScribe (E_bug + verification)
```

현재 구현:
- `strategy` 옵션 (minimal, formal, natural, only_natural)이 있지만
- Draft의 ablation conditions와 정확히 대응되지 않음
- C1 (post-hoc)이 명확하지 않음

**필요한 작업:**
```python
# 새로운 strategy 옵션:
strategies = {
    'baseline': {  # C1
        'use_E_bug': False,
        'prompt': "Fix this vulnerability: ..."
    },
    'vague_hints': {  # C2
        'use_E_bug': False,
        'prompt': "Fix by adding a check..."
    },
    'formal_guidance': {  # C3
        'use_E_bug': True,
        'use_verification': False
    },
    'full_patchscribe': {  # C4
        'use_E_bug': True,
        'use_verification': True
    }
}
```

**2.1.4 Ground Truth Similarity가 단순 문자열 비교**

현재 구현:
```python
def _compare_ground_truth(patched, ground_truth):
    return normalize_code(patched) == normalize_code(ground_truth)
```

Draft 제안:
- AST-based structural similarity
- Semantic equivalence (manual validation 필요)

**필요한 작업:**
```python
def ast_based_similarity(code1, code2):
    """AST 구조 비교"""
    ast1 = parse_ast(code1)
    ast2 = parse_ast(code2)
    return tree_edit_distance(ast1, ast2) / max(size(ast1), size(ast2))
```

---

### 2.2 RQ2: Dual Verification Effectiveness

#### ✅ 구현된 부분
- 없음 (RQ2 전체가 거의 구현되지 않음)

#### ❌ 부족한 부분

**2.2.1 Incomplete Patches Caught 측정 없음**

Draft 핵심:
```
일부러 incomplete patch를 생성하고,
consistency checking이 이를 잡아내는지 테스트
```

현재 구현:
- 이런 실험이 전혀 없음

**필요한 작업:**
```python
class IncompletePatchGenerator:
    def generate_variants(self, vuln):
        """의도적으로 불완전한 패치 생성"""
        return [
            {'type': 'partial_check', 'patch': add_partial_check(vuln)},
            {'type': 'wrong_location', 'patch': add_check_wrong_place(vuln)},
            {'type': 'one_path_only', 'patch': patch_one_branch(vuln)}
        ]

def evaluate_detection_capability():
    """각 verification method가 incomplete patch를 잡아내는지 테스트"""
    incomplete_patches = generate_incomplete_patches()
    results = {
        'exploit_only': [],
        'symbolic_only': [],
        'consistency_only': [],
        'triple': []
    }
    for patch in incomplete_patches:
        results['exploit_only'].append(exploit_test(patch))
        results['consistency_only'].append(consistency_check(patch))
        # ...
    return compute_precision_recall(results)
```

**2.2.2 Consistency Violation Breakdown 없음**

Draft 요구사항:
```
Consistency 실패 원인을 4가지로 분류:
- Causal coverage
- Intervention validity
- Logical inconsistency
- Completeness
```

현재:
- Consistency checking 자체가 없으므로 breakdown도 없음

**2.2.3 Verification Agreement Rate 계산 안 됨**

Draft:
```
V1 (exploit) vs V2 (symbolic) vs V3 (consistency)가 
얼마나 일치하는지 측정
```

현재:
- `evaluation.py`에 없음

**필요한 작업:**
```python
def compute_verification_agreement():
    agreements = []
    for patch in patches:
        v1 = exploit_test(patch)
        v2 = symbolic_verify(patch)
        v3 = consistency_check(patch)
        # 모두 pass or 모두 fail이면 agreement
        all_agree = (v1 == v2 == v3)
        agreements.append(all_agree)
    return sum(agreements) / len(agreements)
```

---

### 2.3 RQ3: Scalability and Performance

#### ✅ 구현된 부분
- 없음 (성능 측정이 전혀 없음)

#### ❌ 부족한 부분

**2.3.1 Time Breakdown by Phase 측정 없음**

Draft 요구사항:
```
Phase 1 (Formalization): ~40s
Phase 2 (Generation): ~80s
Phase 3 (Verification): ~40s
```

현재:
- `pipeline.py`에 시간 측정이 없음

**필요한 작업:**
```python
import time

class PerformanceProfiler:
    def run_with_profiling(self, vuln_case):
        times = {}
        
        start = time.time()
        pcg, scm = build_models(vuln_case)
        times['phase1_formalization'] = time.time() - start
        
        start = time.time()
        patch = generate_patch(...)
        times['phase2_generation'] = time.time() - start
        
        start = time.time()
        verification = verify(patch)
        times['phase3_verification'] = time.time() - start
        
        times['total'] = sum(times.values())
        return times
```

**2.3.2 Iteration Count 기록 있지만 분석 없음**

현재:
```python
# pipeline.py에 iterations 리스트는 있지만
# 평균 반복 횟수, 성공률 등 통계 없음
```

**2.3.3 Resource Usage (메모리, symbolic paths) 측정 없음**

Draft:
- Peak memory
- Symbolic paths explored
- SMT queries

현재:
- 전혀 측정하지 않음

**필요한 작업:**
```python
import psutil

def profile_resources(func):
    process = psutil.Process()
    initial_memory = process.memory_info().rss
    
    result = func()
    
    peak_memory = process.memory_info().rss
    return {
        'result': result,
        'peak_memory_mb': (peak_memory - initial_memory) / 1024 / 1024
    }
```

---

### 2.4 RQ4: Explanation Quality

#### ✅ 구현된 부분
- **Checklist-based evaluation**: `explanation_quality.py`의 `_compute_checklist()`
- **LLM Judge**: `_judge_with_llm()` 함수

#### ❌ 부족한 부분

**2.4.1 Expert Quality Scores 프레임워크 없음**

Draft 요구사항:
```
Security experts rate E_bug and E_patch on:
- Accuracy (1-5)
- Completeness (1-5)
- Clarity (1-5)
```

현재:
- LLM judge는 있지만 human expert evaluation 프레임워크 없음

**필요한 작업:**
```python
# scripts/expert_review_tool.py
class ExpertReviewTool:
    def present_case(self, vuln, E_bug, E_patch):
        """전문가에게 케이스 제시"""
        print(f"Vulnerability: {vuln.id}")
        print(f"E_bug:\n{E_bug}")
        print(f"E_patch:\n{E_patch}")
        
    def collect_ratings(self):
        """평가 점수 수집"""
        return {
            'accuracy': int(input("Accuracy (1-5): ")),
            'completeness': int(input("Completeness (1-5): ")),
            'clarity': int(input("Clarity (1-5): "))
        }
```

**2.4.2 User Study 구조 없음**

Draft:
- 12 participants
- 4 conditions (no exp, post-hoc, E_bug only, dual)
- Within-subject design

현재:
- 전혀 없음

**필요한 작업:**
```python
# scripts/user_study.py
class UserStudyFramework:
    def __init__(self, participants=12):
        self.conditions = ['none', 'posthoc', 'E_bug_only', 'dual']
        self.vulnerabilities = load_study_cases(6)
        self.assignments = self.counterbalance()
    
    def run_session(self, participant_id):
        """한 참가자의 세션 진행"""
        for vuln, condition in self.assignments[participant_id]:
            # 1. Patch review task
            # 2. Bug finding task
            # 3. Deployment decision
            # 4. Questionnaire
            pass
```

---

## 3. 우선순위별 작업 목록

### 🔴 Critical (논문 핵심 기여 관련)

1. **Consistency Verification 구현** (최우선)
   - E_bug ↔ E_patch consistency checker
   - 4가지 체크 (coverage, validity, logic, completeness)
   - 예상 작업: 3-5일

2. **Formal Bug Explanation (E_bug) 통합**
   - 분산된 정보를 FormalBugExplanation 구조로 통합
   - assertions 자동 생성
   - 예상 작업: 2-3일

3. **Formal Patch Explanation (E_patch) 완성**
   - addressed/unaddressed causes 분류
   - disrupted paths 분석
   - intervention formalization
   - 예상 작업: 2-3일

### 🟡 High Priority (평가 완성도)

4. **RQ2 Incomplete Patch 실험**
   - Incomplete patch generator
   - Detection capability 측정
   - 예상 작업: 2일

5. **RQ1 Ablation Study**
   - 4가지 조건 명확히 구현
   - 예상 작업: 1일

6. **RQ3 Performance Profiling**
   - Phase별 시간 측정
   - Resource usage 측정
   - 예상 작업: 1일

### 🟢 Medium Priority (개선)

7. **Symbolic Verification 강화**
   - 실제 KLEE/angr 통합 (선택적)
   - 예상 작업: 3-5일 (optional)

8. **Ground Truth Similarity 개선**
   - AST-based metric
   - 예상 작업: 1일

### 🔵 Low Priority (완성도)

9. **Expert Review Tool**
   - UI/스크립트
   - 예상 작업: 1일

10. **User Study Framework**
    - 실험 프로토콜 구현
    - 예상 작업: 2-3일 (선택적, 시간 있으면)

---

## 4. 총평

### 현재 구현 상태

**잘 된 부분:**
- ✅ PCG/SCM 기본 구조는 탄탄함
- ✅ Explanation 생성 파이프라인 있음
- ✅ LLM 통합 잘 됨
- ✅ Dataset loader 완성도 높음

**Critical한 누락:**
- ❌ **Consistency Verification 없음** (논문의 핵심 기여!)
- ❌ E_bug/E_patch가 draft의 완전한 형태가 아님
- ❌ RQ2 실험 구조 없음
- ❌ Performance 측정 없음

### 작업량 추정

- **Critical 작업**: 7-11일 (1-2주)
- **High Priority**: 4일
- **Medium Priority**: 4-6일
- **Low Priority**: 3-4일

**총 예상 작업**: 2-3주 full-time work

### 권장 사항

1. **먼저 Consistency Verification 구현** - 이것이 없으면 논문 기여가 약해짐
2. **E_bug/E_patch 구조 완성** - 현재는 분산되어 있어 일관성이 떨어짐
3. **RQ2 실험** - Dual verification의 효과를 보이는 핵심 실험
4. **Performance profiling** - 빠르게 추가 가능하고 RQ3에 필수

Symbolic execution을 KLEE로 대체하는 것은 선택적으로 나중에 해도 됨 (현재의 heuristic도 어느 정도 작동).

User study는 시간이 부족하면 생략하거나 간소화 가능 (checklist + LLM judge + expert review만으로도 RQ4 답변 가능).
