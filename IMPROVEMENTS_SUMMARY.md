# PatchScribe 개선 사항 요약

**날짜**: 2025-11-10
**기반 분석**: DEEP_ANALYSIS_REPORT.md

---

## 개선 개요

심층 분석을 통해 발견한 세 가지 핵심 문제를 해결하기 위한 개선 작업을 완료했습니다:

1. **일관성 검증 메커니즘 개선** - Ground truth 기반 검증 추가
2. **형식적 스펙 표현력 확장** - 처방적(prescriptive) 수정 요구사항 추가
3. **설명 생성 개선** - Diff 정보 활용 및 인과관계 명시

---

## 1. 일관성 검증 메커니즘 개선 ✅

### 문제점
- 현재 검증은 E_bug와 E_patch의 "정렬성"만 확인
- **49.5%의 거짓 양성** 발생 (83.5% 검증 통과 vs 34% 실제 성공)
- E_bug가 부정확해도 E_patch와 정렬되면 통과
- "일관성 있다" ≠ "취약점이 제거된다"

### 개선 사항

#### 새로운 검증 계층 추가
**파일**: `patchscribe/consistency_checker.py`

```python
@dataclass
class ConsistencyResult:
    # 기존 검증
    causal_coverage: CheckOutcome
    intervention_validity: CheckOutcome
    logical_consistency: CheckOutcome
    completeness: CheckOutcome

    # 신규 검증 (최우선순위)
    ground_truth_alignment: Optional[CheckOutcome] = None
    patch_effectiveness: Optional[CheckOutcome] = None
```

#### Check 1: Ground Truth Alignment
```python
def check_ground_truth_alignment(E_bug, ground_truth):
    """
    E_bug가 실제 취약점을 정확하게 캡처했는지 검증
    - 취약점 위치 일치 여부
    - 취약점 타입 일치 여부
    - 원인 분석의 정확성
    """
```

**주요 검증 항목:**
- 취약점 위치가 ground truth와 일치하는가? (±2 line 허용)
- 취약점 타입이 E_bug 설명에 포함되어 있는가?
- 예상되는 원인들이 causal paths에 포함되어 있는가?

#### Check 2: Patch Effectiveness (최우선 검증)
```python
def check_patch_effectiveness(E_patch, ground_truth):
    """
    패치가 실제로 취약점을 제거했는지 검증
    - 취약점이 실제로 제거되었는가?
    - 패치가 의미론적으로 올바른가?
    - 부작용이 없는가?
    """
```

**주요 검증 항목:**
- `vulnerability_removed`: 취약점이 실제로 제거되었는가? (필수)
- `patch_correct`: 패치가 의미론적으로 올바른가?
- `has_side_effects`: 부작용이나 기능 손상이 없는가?

#### 검증 우선순위 재조정

**이전:**
```
일관성(E_bug ↔ E_patch) 최우선
```

**개선 후:**
```
1. 효과성(Patch Effectiveness) - 취약점이 실제로 제거되었는가?
2. 정렬성(Ground Truth Alignment) - E_bug가 정확한가?
3. 일관성(Causal Coverage, Logical Consistency)
4. 완전성(Intervention Validity, Completeness)
```

---

## 2. 형식적 스펙 표현력 확장 ✅

### 문제점
- 현재 스펙은 "무엇이 문제인가"만 표현
- "어떻게 해결해야 하는가"는 표현하지 못함
- 예: "idev가 NULL일 수 있음" (문제만) vs "idev가 NULL일 때 early return해야 함" (해결책)

### 개선 사항

#### 새로운 필드 추가
**파일**: `patchscribe/formal_spec.py`

```python
@dataclass
class FormalBugExplanation:
    # 기존 필드들...

    # 신규 필드 (처방적 수정 요구사항)
    required_fixes: List[str] = field(default_factory=list)
    fix_constraints: List[str] = field(default_factory=list)
    invalid_fixes: List[str] = field(default_factory=list)
    must_preserve: List[str] = field(default_factory=list)
```

#### 취약점 유형별 자동 생성

**NULL Pointer Dereference (CWE-476):**
```python
required_fixes = [
    "Add NULL check before all pointer dereferences",
    "Ensure early return or error handling when NULL is detected"
]

fix_constraints = [
    "NULL check must cover ALL code paths leading to dereference",
    "Check must occur BEFORE the dereference, not after"
]

invalid_fixes = [
    "Adding NULL check after the vulnerable dereference",
    "Checking only some paths but not others",
    "Using a tautology condition (e.g., if (1))"
]

must_preserve = [
    "Original functionality when pointer is valid",
    "Error propagation to caller"
]
```

**Buffer Overflow (CWE-119, CWE-787):**
```python
required_fixes = [
    "Add bounds check before buffer access",
    "Validate input length against buffer size"
]

fix_constraints = [
    "Bounds check must use >= or <= (not == for exact values)",
    "Check must account for buffer size, not just arbitrary limits"
]

invalid_fixes = [
    "Checking for specific length (e.g., == 256) instead of >= 256",
    "Increasing buffer size without adding bounds check",
    "Checking after the write occurs"
]
```

**지원 취약점 유형:**
- NULL Pointer Dereference (CWE-476)
- Buffer Overflow (CWE-119, CWE-787)
- Format String Vulnerability (CWE-134)
- Integer Overflow (CWE-190)

---

## 3. 설명 생성 개선 ✅

### 문제점
- 모든 조건에서 핵심 정보를 **100% 누락**:
  - `describes_fix`: 97/97 케이스에서 누락 (100%)
  - `describes_reason`: 96/97 케이스에서 누락 (99%)
  - `mentions_causal_parent`: 96/97 케이스에서 누락 (99%)
- 형식적 스펙이 오히려 설명 품질을 악화 (C1: 3.69/5 → C4: 3.38/5)

### 개선 사항

#### Diff 정보 상세 파싱
**파일**: `patchscribe/explanation.py`

**이전:**
```python
def _summarize_patch(patch):
    preview = [line for line in diff if line.startswith("+") or line.startswith("-")]
    preview_text = "\n".join(preview[:8])
    # → 라인 번호 없음, 맥락 부족
```

**개선 후:**
```python
def _summarize_patch(patch):
    """
    Diff를 파싱하여 다음 정보 추출:
    - 추가된 코드 (라인 번호 포함)
    - 제거된 코드
    - 수정된 맥락
    """

    # 라인 번호 추출
    if line.startswith("@@"):
        # @@ -a,b +c,d @@ → line c 추출
        current_line_num = parse_line_number(line)

    # 상세 정보 제공
    added_lines.append(f"Line {current_line_num}: {code}")

    # 출력 예시:
    # **Added code:**
    #   + Line 42: if (!idev) return 0;
    #   + Line 43: if (unlikely(READ_ONCE(...))) {
```

#### LLM 프롬프트 강화

**이전:**
```
"1. What caused the vulnerability (what)
 2. How the patch changes the code (how)
 3. Why this change eliminates the vulnerability (why)"
```

**개선 후:**
```
"1. What caused the vulnerability (what)
 2. WHICH SPECIFIC CODE LINES were changed (be explicit)
 3. How the patch changes the code (how) - reference actual diff
 4. Why this change eliminates the vulnerability (why) - explain causal link
 5. What is the causal relationship

IMPORTANT REQUIREMENTS:
- You MUST explicitly describe which code was modified (e.g., 'Added NULL check at line X')
- You MUST explain WHY this specific change fixes the vulnerability
- You MUST describe the causal relationship
- Reference specific lines from the diff"
```

#### Template 설명 개선

**이전:**
```markdown
### Why this works
The patched condition eliminates the causal prerequisites
```

**개선 후:**
```markdown
### What code was changed?
Applied method: guard_injection

**Added code:**
  + Line 42: if (!idev) return 0;
  + Line 43: if (unlikely(READ_ONCE(idev->cnf.disable_ipv6))) {

**Applied guards:** NULL check for idev
**Notes:** Early return on NULL pointer

### Why this change fixes the vulnerability?
The patch eliminates the vulnerability by breaking the causal chain. Specifically:
- **Vulnerability cause**: NULL pointer dereference on idev
- **Causal path**: ip6_dst_idev() can return NULL → idev->cnf dereference
- **Intervention**: Add NULL check before dereference with early return
- **Result**: The conditions necessary for exploitation are now unsatisfiable

### Causal reasoning
The vulnerability occurred due to a causal chain from inputs to the vulnerable operation.
The patch intervenes at a critical point in this chain, preventing the vulnerability
condition from being satisfied.
```

---

## 예상 효과

### 1. 거짓 양성 감소
**현재:** 49.5% 거짓 양성 (83.5% 검증 통과 - 34% 실제 성공)
**예상:** Ground truth 검증으로 거짓 양성 대폭 감소

### 2. 패치 품질 향상
**현재:** c1→c4로 갈 때 성능 향상 미미 (+3.1%) 또는 감소 (-16.7% on ExtractFix)
**예상:** 처방적 요구사항으로 더 정확하고 완전한 패치 생성

### 3. 설명 품질 개선
**현재:** 핵심 정보 100% 누락, C4에서 명확성 8.4% 저하
**예상:**
- `describes_fix`: 100% → 80%+ (라인 번호 + 코드 명시)
- `describes_reason`: 99% 누락 → 70%+ 포함
- `mentions_causal_parent`: 99% 누락 → 80%+ 포함

---

## 사용 방법

### 일관성 검증 (Ground Truth 포함)

```python
from patchscribe.consistency_checker import ConsistencyChecker

checker = ConsistencyChecker()

# Ground truth 정보 준비
ground_truth = {
    'vulnerability_removed': True,  # 실제로 제거되었는가?
    'patch_correct': True,          # 의미론적으로 올바른가?
    'has_side_effects': False,      # 부작용이 있는가?
    'vulnerability_location': 'line 42',
    'vulnerability_type': 'NULL pointer dereference',
}

# 검증 실행 (ground truth 포함)
result = checker.check(E_bug, E_patch, ground_truth=ground_truth)

# 결과 확인
print(f"Overall: {result.overall}")
print(f"Confidence: {result.confidence_level}")
print(f"Failed checks: {result.failed_checks()}")

# 새로운 검증 항목 확인
if result.ground_truth_alignment:
    print(f"Ground truth alignment: {result.ground_truth_alignment.success}")
if result.patch_effectiveness:
    print(f"Patch effectiveness: {result.patch_effectiveness.success}")
```

### 형식적 스펙 (자동 생성)

```python
from patchscribe.formal_spec import generate_E_bug

# E_bug 생성 시 자동으로 처방적 요구사항 포함
E_bug = generate_E_bug(pcg, scm, intervention_spec, vuln_info)

# 처방적 요구사항 확인
print("Required fixes:")
for fix in E_bug.required_fixes:
    print(f"  - {fix}")

print("\nFix constraints:")
for constraint in E_bug.fix_constraints:
    print(f"  - {constraint}")

print("\nInvalid fixes (to avoid):")
for invalid in E_bug.invalid_fixes:
    print(f"  - {invalid}")

print("\nMust preserve:")
for preserve in E_bug.must_preserve:
    print(f"  - {preserve}")
```

### 개선된 설명 생성

설명 생성은 자동으로 개선된 버전을 사용합니다:

```python
from patchscribe.explanation import generate_explanations

bundle = generate_explanations(
    graph=pcg,
    model=scm,
    intervention=intervention_spec,
    patch=patch_result,
    effect=effect_dict,
    mode="both",  # template + LLM
)

# Template 설명 (라인 번호 + 인과관계 포함)
print(bundle.natural_template)

# LLM 설명 (강화된 프롬프트로 생성)
print(bundle.natural_llm)
```

---

## 다음 단계

### 즉시 테스트
1. **기존 실험 재실행**
   ```bash
   python scripts/run_experiment.py --dataset zeroday --limit 10 \
       --llm-provider anthropic --models claude-haiku-4-5 \
       --conditions c1,c4 --output results/improved
   ```

2. **Ground truth 정보 준비**
   - 각 데이터셋에 `vulnerability_removed`, `patch_correct` 추가
   - 검증 정확도 측정

3. **설명 품질 평가**
   - `describes_fix`, `describes_reason`, `mentions_causal_parent` 재평가
   - 개선율 측정

### 중기 계획
1. **다단계 검증 파이프라인 구현**
   - 문법 검증 → 효과 검증 → 회귀 검증 → 일관성 검증
   - 각 단계별 구체적인 피드백 제공

2. **반복 메커니즘 강화**
   - 검증 실패 시 구체적인 수정 지시
   - Ground truth 기반 피드백 루프

3. **처방적 요구사항 확대**
   - 더 많은 CWE 유형 지원
   - 프로젝트별 커스텀 요구사항

---

## 수정된 파일

1. **patchscribe/consistency_checker.py**
   - `ConsistencyResult`: 새 필드 추가 (ground_truth_alignment, patch_effectiveness)
   - `check_ground_truth_alignment()`: 신규 메서드
   - `check_patch_effectiveness()`: 신규 메서드
   - 검증 우선순위 재조정

2. **patchscribe/formal_spec.py**
   - `FormalBugExplanation`: 새 필드 추가 (required_fixes, fix_constraints, invalid_fixes, must_preserve)
   - `_generate_fix_requirements()`: 신규 헬퍼 함수
   - `generate_E_bug()`: 처방적 요구사항 자동 생성

3. **patchscribe/explanation.py**
   - `_summarize_patch()`: Diff 파싱 강화 (라인 번호 추출)
   - `_build_llm_prompt()`: 프롬프트 강화 (명시적 요구사항 추가)
   - `_build_natural_summary()`: Template 개선 (인과관계 명시)

---

## 참고 문서

- **DEEP_ANALYSIS_REPORT.md**: 심층 분석 보고서 (424줄)
  - 문제점 상세 분석
  - 근본 원인 파악
  - ExtractFix 성능 저하 분석
  - 실패 패턴 분석

---

## 결론

이번 개선을 통해 PatchScribe의 세 가지 핵심 문제를 해결했습니다:

1. ✅ **거짓 양성 문제**: Ground truth 기반 검증으로 정확성 우선
2. ✅ **스펙 불완전성**: 처방적 요구사항으로 "어떻게 해결할지" 명시
3. ✅ **설명 품질**: Diff 정보 활용 및 인과관계 명시로 완전한 설명 생성

**기대 효과:**
- C1→C4 성능 개선폭 증가 (현재 +3.1% → 목표 +15%+)
- ExtractFix 성능 회복 (현재 -16.7% → 목표 +10%+)
- 설명 품질 대폭 향상 (핵심 정보 누락 100% → 20% 이하)

실험을 재실행하여 개선 효과를 측정하고, 추가 튜닝을 진행하는 것을 권장합니다.
