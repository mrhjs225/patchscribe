# PatchScribe 체계적 자동화 개선 계획

**작성일**: 2025-11-10
**목적**: 탑급 보안 학회 수준의 체계적 자동화 달성

---

## 🚨 현재 문제점 요약

### 1. 형식적 스펙 생성 (formal_spec.py)
- ❌ **하드코딩**: 4가지 CWE 타입별 if-else 체인
- ❌ **키워드 매칭**: 'NULL', 'BUFFER' 등 단순 문자열 검색
- ❌ **확장성 부재**: 새로운 CWE 추가 시 코드 수정 필요
- ❌ **PCG/SCM 미활용**: 이미 분석된 인과 정보를 충분히 활용하지 못함

### 2. Ground Truth 검증 (consistency_checker.py)
- ❌ **매직 넘버**: tolerance = 2 (근거 없음)
- ❌ **단순 substring**: 의미론적 검증 없음
- ❌ **휴리스틱 라인 번호 추출**: 정규식 없이 숫자만 필터링

### 3. 설명 생성 (explanation.py)
- ❌ **Diff 파싱 휴리스틱**: 간단한 문자열 분할
- ❌ **에러 무시**: try-except pass

---

## ✅ 체계적 개선 방안

### Phase 1: 형식적 스펙 생성 - 규칙 기반 → 분석 기반

#### 현재 (하드코딩):
```python
if 'NULL' in signature.upper():
    required_fixes = ["Add NULL check before...", ...]
```

#### 개선 후 (분석 기반):
```python
def _derive_fix_requirements_from_scm(
    scm: StructuralCausalModel,
    pcg: ProgramCausalGraph
) -> FixRequirements:
    """
    SCM과 PCG로부터 수정 요구사항을 체계적으로 도출

    이론적 근거:
    - Do-calculus: 인과 개입이 취약점 조건을 unsatisfiable하게 만들어야 함
    - 역 인과 추론: V_bug의 원인을 역으로 추적하여 필요한 개입 식별
    """

    # 1. SCM의 vulnerable_condition 분석
    vuln_condition = scm.vulnerable_condition
    involved_vars = extract_variables(vuln_condition)

    # 2. PCG에서 각 변수로의 인과 경로 추적
    causal_interventions = []
    for var in involved_vars:
        # 이 변수를 False로 만들 수 있는 조건 식별
        parents = pcg.predecessors(var)
        for parent in parents:
            intervention = infer_intervention_from_causal_edge(
                parent, var, pcg, scm
            )
            causal_interventions.append(intervention)

    # 3. 각 개입의 효과를 do-calculus로 검증
    valid_interventions = []
    for interv in causal_interventions:
        if verify_intervention_sufficiency(interv, vuln_condition, scm):
            valid_interventions.append(interv)

    # 4. 최소 개입 집합 선택 (커버리지 최대화)
    minimal_set = select_minimal_intervention_set(valid_interventions)

    return formulate_requirements(minimal_set)
```

**핵심 개선:**
- ✅ **이론 기반**: Do-calculus와 역 인과 추론
- ✅ **자동 도출**: PCG/SCM 분석으로 자동 생성
- ✅ **일반화**: 모든 취약점 유형에 적용 가능
- ✅ **검증 가능**: 개입의 충분성을 형식적으로 검증

---

### Phase 2: Ground Truth 검증 - 형식적 검증

#### 현재 (휴리스틱):
```python
if abs(spec_line - truth_line) > 2:  # 매직 넘버
    return False
if vuln_type.lower() not in E_bug.description.lower():  # substring
    return False
```

#### 개선 후 (형식적):
```python
def check_ground_truth_alignment_formal(
    E_bug: FormalBugExplanation,
    ground_truth: dict
) -> CheckOutcome:
    """
    형식적 검증: E_bug의 formal_condition이 ground truth와 일치하는지
    """

    # 1. 위치 검증: AST 기반 정확한 비교
    spec_ast_node = parse_location_to_ast(E_bug.vulnerable_location)
    truth_ast_node = parse_location_to_ast(ground_truth['location'])
    location_match = ast_nodes_semantically_equivalent(spec_ast_node, truth_ast_node)

    # 2. 조건 검증: 논리식 동등성 (SMT solver)
    spec_formula = parse_to_smt(E_bug.formal_condition)
    truth_formula = parse_to_smt(ground_truth['vulnerability_condition'])
    condition_equivalent = smt_check_equivalence(spec_formula, truth_formula)

    # 3. 인과 구조 검증: 그래프 동형성
    spec_causal_graph = extract_causal_graph(E_bug)
    truth_causal_graph = ground_truth.get('causal_graph')
    if truth_causal_graph:
        causal_isomorphic = check_graph_isomorphism(
            spec_causal_graph, truth_causal_graph
        )

    return CheckOutcome(
        success=location_match and condition_equivalent and causal_isomorphic,
        message="Formal verification results",
        diagnostics={
            'location_match': location_match,
            'condition_equivalent': condition_equivalent,
            'causal_isomorphic': causal_isomorphic
        }
    )
```

**핵심 개선:**
- ✅ **AST 기반**: 구조적 위치 비교 (라인 번호보다 정확)
- ✅ **SMT 검증**: 논리식 동등성 검증
- ✅ **그래프 동형성**: 인과 구조 비교
- ✅ **매직 넘버 제거**: 형식적 동등성 기준

---

### Phase 3: 설명 생성 - 템플릿 → 형식적 추론

#### 현재 (템플릿):
```python
return (
    "### What code was changed?\n"
    f"{patch_summary}\n\n"
    "### Why this change fixes the vulnerability?\n"
    f"{removal_reason}\n"
)
```

#### 개선 후 (추론 기반):
```python
def generate_explanation_from_proof(
    E_bug: FormalBugExplanation,
    E_patch: FormalPatchExplanation,
    intervention: InterventionSpec
) -> str:
    """
    수학적 증명으로부터 설명 자동 생성

    증명 구조:
    1. V_bug ⟺ φ(X₁, ..., Xₙ)  [E_bug의 formal_condition]
    2. do(Xᵢ = v) [intervention]
    3. φ(X₁, ..., Xᵢ₋₁, v, Xᵢ₊₁, ..., Xₙ) ⟹ False [do-calculus 적용]
    4. ∴ V_bug = False [결론]
    """

    # 1. 증명 구성
    proof_steps = construct_formal_proof(E_bug, E_patch, intervention)

    # 2. 각 증명 단계를 자연어로 변환
    explanation_parts = []
    for step in proof_steps:
        natural_lang = proof_step_to_natural_language(
            step,
            template_db=PROOF_TEMPLATES,
            context={'E_bug': E_bug, 'E_patch': E_patch}
        )
        explanation_parts.append(natural_lang)

    # 3. 구조화된 설명 조합
    return structure_explanation(
        vulnerability=explain_vulnerability_from_condition(E_bug),
        intervention=explain_intervention_from_do_operator(intervention),
        proof='\n'.join(explanation_parts),
        conclusion=derive_conclusion_from_proof(proof_steps)
    )
```

**핵심 개선:**
- ✅ **증명 기반**: 수학적 증명에서 설명 도출
- ✅ **자동 생성**: 템플릿이 아닌 논리적 추론
- ✅ **완전성**: 모든 증명 단계가 설명에 포함
- ✅ **정확성**: 증명이 올바르면 설명도 올바름

---

## 구현 우선순위

### High Priority (필수)

1. **형식적 스펙 생성 개선**
   - [ ] `_derive_fix_requirements_from_scm()` 구현
   - [ ] Do-calculus 기반 개입 검증
   - [ ] 역 인과 추론 알고리즘
   - [ ] 최소 개입 집합 선택 알고리즘

2. **Ground Truth 검증 강화**
   - [ ] AST 기반 위치 비교
   - [ ] SMT solver 논리식 동등성 검증
   - [ ] 그래프 동형성 검사

### Medium Priority (권장)

3. **설명 생성 자동화**
   - [ ] 형식적 증명 구성
   - [ ] 증명 단계 → 자연어 변환
   - [ ] 구조화된 설명 생성

4. **Diff 파싱 강화**
   - [ ] 표준 diff 라이브러리 사용 (difflib)
   - [ ] AST 기반 변경점 추출

### Low Priority (선택)

5. **메타 학습 기반 확장**
   - [ ] 과거 패치 패턴 학습
   - [ ] 자동 규칙 추출

---

## 이론적 배경

### 1. Do-Calculus (Pearl, 1995)

개입의 효과를 계산하는 형식적 프레임워크:

```
P(Y | do(X = x)) = ∑ₖ P(Y | X = x, Z = z) P(Z = z)
```

**적용**:
- 패치 = do(Variable = safe_value)
- 효과 검증 = P(V_bug = True | do(patch))가 0인지 확인

### 2. 역 인과 추론 (Counterfactual Reasoning)

```
V_bug가 False가 되려면 어떤 변수를 개입해야 하는가?
→ V_bug의 부모 노드들 중 어느 것을 차단하면 되는가?
```

### 3. 최소 개입 집합 (Minimum Vertex Cover)

```
Goal: V_bug의 모든 인과 경로를 차단하는 최소 개입 집합
Algorithm: Approximation algorithm for weighted vertex cover
```

---

## 구현 예시 (Phase 1)

### 1. 역 인과 추론으로 개입 도출

```python
def infer_required_interventions(
    vuln_condition: str,
    pcg: ProgramCausalGraph,
    scm: StructuralCausalModel
) -> List[Intervention]:
    """
    취약점 조건으로부터 필요한 개입을 역으로 추론

    알고리즘:
    1. vuln_condition을 파싱하여 관련 변수 추출
    2. 각 변수의 인과 부모 식별 (PCG 역방향 탐색)
    3. 부모를 제어하는 개입 생성
    4. Do-calculus로 개입의 충분성 검증
    """

    # Parse vulnerability condition
    formula = parse_logical_formula(vuln_condition)
    variables = extract_variables(formula)

    interventions = []

    for var in variables:
        # Get causal parents from PCG
        parents = pcg.predecessors(var)

        for parent_id in parents:
            parent_node = pcg.nodes[parent_id]

            # Infer what value would make this path safe
            safe_value = infer_safe_value(
                parent_node, var, scm, vuln_condition
            )

            if safe_value:
                intervention = Intervention(
                    target_variable=parent_node.variable,
                    target_value=safe_value,
                    rationale=f"Setting {parent_node.variable} to {safe_value} "
                              f"prevents {var} from satisfying vulnerability condition",
                    affected_paths=[path for path in get_paths_through(parent_id, pcg)]
                )

                # Verify intervention is sufficient
                if verify_do_calculus(intervention, vuln_condition, scm):
                    interventions.append(intervention)

    return select_minimal_cover(interventions, pcg)


def infer_safe_value(
    parent_node: Node,
    child_var: str,
    scm: StructuralCausalModel,
    vuln_condition: str
) -> Optional[str]:
    """
    부모 노드가 어떤 값을 가져야 자식 변수가 안전한지 추론

    방법:
    1. SCM에서 child_var의 구조 방정식 가져오기
    2. vuln_condition을 False로 만드는 제약 추출
    3. 제약을 만족하는 parent_node 값 계산 (SMT solver)
    """

    # Get structural equation for child
    equation = scm.get_equation(child_var)
    if not equation:
        return None

    # Create SMT formula
    solver = z3.Solver()

    # Add constraint: vulnerability condition must be False
    vuln_formula = parse_to_z3(vuln_condition)
    solver.add(z3.Not(vuln_formula))

    # Add structural equation
    eq_formula = parse_to_z3(equation.expression)
    solver.add(eq_formula)

    # Solve for parent variable
    if solver.check() == z3.sat:
        model = solver.model()
        parent_var = f"V_{parent_node.id}"
        if parent_var in model:
            return str(model[parent_var])

    return None


def verify_do_calculus(
    intervention: Intervention,
    vuln_condition: str,
    scm: StructuralCausalModel
) -> bool:
    """
    Do-calculus를 사용하여 개입이 충분한지 검증

    검증:
    P(V_bug = True | do(intervention)) = 0
    """

    # Apply intervention to SCM
    modified_scm = apply_intervention_to_scm(scm, intervention)

    # Check if vulnerability condition is unsatisfiable
    modified_condition = substitute_intervention(
        vuln_condition, intervention
    )

    # Use SMT solver to check satisfiability
    solver = z3.Solver()
    formula = parse_to_z3(modified_condition)
    solver.add(formula)

    # If UNSAT, intervention is sufficient
    return solver.check() == z3.unsat


def select_minimal_cover(
    interventions: List[Intervention],
    pcg: ProgramCausalGraph
) -> List[Intervention]:
    """
    모든 취약 경로를 커버하는 최소 개입 집합 선택

    이것은 Minimum Weighted Vertex Cover 문제
    - Vertices: interventions
    - Edges: causal paths in PCG
    - Goal: cover all paths with minimum cost
    """

    # Extract all causal paths to vulnerability
    vuln_node = pcg.get_vulnerability_node()
    all_paths = pcg.get_all_paths_to(vuln_node)

    # Greedy approximation (2-approximation for vertex cover)
    covered_paths = set()
    selected = []

    # Sort by coverage (number of paths covered)
    interventions_sorted = sorted(
        interventions,
        key=lambda i: len(i.affected_paths),
        reverse=True
    )

    for intervention in interventions_sorted:
        new_coverage = set(intervention.affected_paths) - covered_paths
        if new_coverage:
            selected.append(intervention)
            covered_paths.update(intervention.affected_paths)

            # Early termination if all paths covered
            if len(covered_paths) >= len(all_paths):
                break

    return selected
```

### 2. 형식적 요구사항 도출

```python
def formulate_requirements(
    minimal_interventions: List[Intervention]
) -> FixRequirements:
    """
    최소 개입 집합으로부터 형식적 요구사항 생성

    자동으로 도출:
    - required_fixes: 각 개입을 코드 수정으로 변환
    - fix_constraints: 개입의 충분성 조건
    - invalid_fixes: 불충분한 개입들
    - must_preserve: 보존해야 할 인과 관계
    """

    required_fixes = []
    fix_constraints = []
    invalid_fixes = []
    must_preserve = []

    for intervention in minimal_interventions:
        # Required fix: 개입을 코드 레벨로 번역
        code_fix = translate_intervention_to_code(intervention)
        required_fixes.append(code_fix)

        # Constraint: 개입의 충분성 조건
        constraint = f"Intervention {intervention.target_variable} = {intervention.target_value} " \
                    f"must be enforced on ALL paths: {intervention.affected_paths}"
        fix_constraints.append(constraint)

    # Invalid fixes: 선택되지 않은 불충분한 개입들
    all_interventions = get_all_possible_interventions()  # 이전에 생성된 모든 개입
    insufficient = set(all_interventions) - set(minimal_interventions)

    for interv in insufficient:
        invalid_fixes.append(
            f"Intervening only on {interv.target_variable} is insufficient "
            f"because it doesn't cover paths: {get_uncovered_paths(interv)}"
        )

    # Must preserve: 개입으로 영향받지 않아야 할 변수들
    safe_variables = identify_safe_variables(minimal_interventions)
    must_preserve = [
        f"Preserve normal behavior of {var}" for var in safe_variables
    ]

    return FixRequirements(
        required_fixes=required_fixes,
        fix_constraints=fix_constraints,
        invalid_fixes=invalid_fixes,
        must_preserve=must_preserve
    )
```

---

## 기대 효과

### 학술적 기여

1. **이론적 엄밀성**
   - Do-calculus와 인과 추론 이론 기반
   - 형식적 검증 가능
   - 수학적 완전성 증명 가능

2. **일반화 가능성**
   - 모든 취약점 유형에 적용 가능
   - 새로운 CWE 추가 시 코드 수정 불필요
   - PCG/SCM만 있으면 자동 생성

3. **재현 가능성**
   - 휴리스틱 제거로 결과 일관성 보장
   - 매개변수 최소화
   - 명확한 알고리즘

### 실용적 개선

1. **정확도 향상**
   - 거짓 양성 대폭 감소 (49.5% → <5%)
   - 형식적 검증으로 신뢰성 확보

2. **확장성**
   - 새로운 취약점 유형 자동 처리
   - 코드 수정 없이 확장 가능

3. **설명 품질**
   - 증명 기반 설명으로 완전성 보장
   - 논리적 일관성 자동 검증

---

## 구현 일정

### Week 1-2: Phase 1 (형식적 스펙 생성)
- Do-calculus 엔진 구현
- 역 인과 추론 알고리즘
- 최소 개입 집합 선택

### Week 3-4: Phase 2 (Ground Truth 검증)
- AST 파서 통합
- SMT solver 통합
- 그래프 동형성 검사

### Week 5-6: Phase 3 (설명 생성)
- 증명 구성 엔진
- 자연어 변환
- 템플릿 데이터베이스

### Week 7-8: 통합 및 평가
- 시스템 통합
- 벤치마크 평가
- 논문 작성

---

## 참고 문헌

1. Pearl, J. (1995). "Causal diagrams for empirical research." *Biometrika*, 82(4), 669-688.
2. Pearl, J. (2009). *Causality: Models, Reasoning and Inference*. Cambridge University Press.
3. Bareinboim, E., & Pearl, J. (2016). "Causal inference and the data-fusion problem." *PNAS*, 113(27), 7345-7352.

---

## 결론

현재 구현의 하드코딩과 휴리스틱을 제거하고, **인과 추론 이론과 형식적 검증**에 기반한 체계적 자동화로 전환함으로써:

1. 탑급 보안 학회 수준의 이론적 엄밀성 확보
2. 모든 취약점 유형에 일반화 가능한 프레임워크
3. 재현 가능하고 검증 가능한 결과
4. 확장성과 유지보수성 향상

을 달성할 수 있습니다.
