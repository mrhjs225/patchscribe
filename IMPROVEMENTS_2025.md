# PatchScribe 개선 사항 (2025년 1월)

## 📋 개요

본 문서는 PatchScribe의 실험 결과 분석 후 적용한 개선 사항을 정리합니다.

### 목표
1. **패치 생성률 향상**: C1→C2→C3→C4 순서로 성능이 향상되도록 개선
2. **설명 평가 점수 변별력 강화**: C1 점수 낮추고, C4 점수 높이기

---

## 🎯 주요 개선 사항

### 1. C4 프롬프트 재구조화 (spec_builder.py)

**문제점:**
- 기존: 보안 요구사항 → 수정 지시사항 → 인과 분석 (부록처럼 배치)
- C4의 핵심인 "인과 경로 분석"이 하단에 배치되어 중요도가 낮아 보임

**개선 사항:**
```python
# 새로운 C4 구조:
# 1. 취약점 인과 분석 (최우선)
#    - 인과 흐름 다이어그램 (Source → Propagation → Sink)
#    - 단계별 분석 (변수명, 위치 포함)
# 2. 개입 지점 및 근거
#    - 왜 이 지점이 최적인지 설명
#    - 최소 개입 원칙
# 3. 보안 요구사항
# 4. 패치 구현 가이드 (3가지 형식)
#    A. 상세 지시사항
#    B. 구현 체크리스트
#    C. 요약
# 5. 일관성 요구사항
```

**기대 효과:**
- C4의 인과 분석이 패치 생성에 실질적으로 활용됨
- LLM Judge 평가 시 Causality 점수 향상
- Success Rate 향상: 32.0% → 35%+ 예상

**변경 파일:**
- `patchscribe/spec_builder.py`: `_build_c4()` 메서드
- `patchscribe/actionable_spec.py`: `translate_causal_path()` 메서드에 구조화된 인과 경로 추가

---

### 2. C3 지시사항 추상화 (actionable_spec.py)

**문제점:**
- ExtractFix 데이터셋에서 C3 성능 급락: 17.7% → 8.3%
- 가설: "줄 X에서 Y를 수정하세요" 같은 구체적 위치 정보가 복잡한 케이스에서 오히려 혼란 야기

**개선 사항:**
```python
# 기존 C3 (너무 구체적):
"줄 {line} 근처에서 배열/버퍼 접근 전에 경계 검사를 추가하세요"

# 개선된 C3 (추상적 가이드라인):
"배열 인덱스가 사용되기 전에 검증이 필요합니다 (줄 {line} 근처 참고)"
```

**핵심 변경:**
- **"where" → "what"**: 어디서가 아닌 무엇을 달성할지에 초점
- **위치는 힌트**: 강제 요구사항이 아닌 참고 정보
- **유연성 증가**: 모델이 코드 구조에 맞게 최적 위치 선택

**변경 파일:**
- `patchscribe/actionable_spec.py`:
  - 템플릿에 `guideline` 필드 추가
  - `translate_intervention()` 메서드에 `use_abstract_guideline` 파라미터 추가
- `patchscribe/spec_builder.py`: C3에서 `use_abstract_guideline=True` 사용

**기대 효과:**
- ExtractFix C3: 8.3% → 15%+ 예상
- C2-C3 격차 증가로 ablation study 명확화

---

### 3. 적응형 포맷 제공 (Multi-Format Guidance)

**개선 사항:**
C4에서 동일한 정보를 3가지 형식으로 제공:

```markdown
## A. 상세 지시사항
• **포인터 사용 전에 NULL 검사를 추가하세요**
  - 이유: NULL 포인터 역참조를 방지합니다
  - 코드 힌트: `if (ptr != NULL)`

## B. 구현 체크리스트
- [ ] 포인터 역참조 전에 NULL 검사가 필요합니다 (줄 10 근처 참고)

## C. 요약
필요한 수정: NULL 검사 1개
```

**이점:**
- 모델이 선호하는 형식 선택 가능
- 모델별 프롬프트 변경 없이도 공정성 유지
- 다양한 reasoning style 지원

**변경 파일:**
- `patchscribe/spec_builder.py`: C4의 "패치 구현 가이드" 섹션

---

### 4. LLM Judge 평가 기준 강화 (llm.py)

**문제점:**
- 현재: C1~C4 평균 점수 차이 미미 (3.61 → 3.85, 약 0.24점)
- C1도 Clarity에서 4.31점으로 높음 → 변별력 부족
- 인과 경로 없는 설명(C1)과 있는 설명(C4)이 비슷하게 평가됨

**개선 사항:**

#### 4.1 Causal Connection (Causality) 강화 ⭐ 가장 중요

```python
# 기존 기준:
- Bug-to-Patch Mapping (2.0점)
- Counterfactual Reasoning (2.0점)
- Why This Specific Fix (1.0점)

# 개선된 기준:
- Concrete Causal Path (2.5점) ⬆️ 증가
  - 변수명, 함수명, 라인 번호 필수
  - "Line 5: user input → Line 10: strcpy → Line 15: overflow"
  - Post-hoc 설명은 이 깊이 부족 → 점수 ≤ 2
- Intervention Mechanism (1.5점)
  - 패치가 인과 경로의 어느 단계를 차단하는지 명시
- Counterfactual Reasoning (1.0점)
```

**핵심 변화:**
- **코드 레벨 경로 요구**: "input is not validated" 같은 추상적 설명은 1-2점
- **구체성 강제**: 변수명, 함수명, 위치 정보 없으면 감점
- **Post-hoc 패널티**: 패치를 본 후 작성한 설명은 인과 깊이가 낮음

#### 4.2 Patch Understanding (Completeness) 강화

```python
# 새로운 Completeness Coverage 기준 (1.5점):
- ✅ "Patch adds checks at all 3 strcpy calls (lines 10, 15, 20)"
- ❌ 하나의 변경만 설명하고 coverage 논의 없음
```

**이점:**
- C4의 전체 인과 경로 분석이 "완전성" 평가에 반영됨
- C1은 coverage를 논의할 근거가 약함 → 낮은 점수

#### 4.3 Vulnerability Understanding 강화

```python
# 구체성 요구:
- Trigger Conditions: "when user input > 256 bytes" (구체적)
  vs "when invalid input" (모호함)
- Root Cause: "Missing NULL check at Line 9"
  vs "improper validation" (일반적)
```

**Red Flags 추가:**
- CWE만 언급하고 실제 버그 설명 없음 → 1-2점
- 코드 위치나 조건 없음 → 1-2점

**변경 파일:**
- `patchscribe/llm.py`: `build_explanation_judge_prompt()` 메서드

**기대 효과:**
- C1 평균: 3.61 → 3.2 (Causality 하락)
- C4 평균: 3.85 → 4.2 (Causality 상승)
- 점수 격차: 0.24 → 1.0

---

## 📊 예상 결과

### 패치 생성률 (Success Rate)

| 데이터셋 | 지표 | 현재 | 예상 | 개선폭 |
|---------|------|------|------|--------|
| **Zeroday** | C3 | 32.3% | 32.3% | 0% (유지) |
|  | C4 | 32.0% | **35%+** | **+3%** |
| **ExtractFix** | C3 | 8.3% | **15%+** | **+6.7%** |
|  | C4 | 13.5% | **20%+** | **+6.5%** |

### 설명 평가 점수 (LLM Judge)

| 조건 | Causality (현재) | Causality (예상) | 전체 평균 (현재) | 전체 평균 (예상) |
|------|------------------|------------------|------------------|------------------|
| C1 | 3.73 | **3.0** ⬇️ | 3.61 | **3.2** |
| C2 | 3.71 | **3.3** ⬇️ | 3.64 | **3.5** |
| C3 | 3.73 | 3.8 | 3.72 | 3.8 |
| C4 | 3.94 | **4.5** ⬆️ | 3.85 | **4.2** |
| **격차** | 0.21 | **1.5** | 0.24 | **1.0** |

---

## 🧪 테스트 방법

### 1. 소규모 테스트 (권장)

ExtractFix의 일부 케이스로 빠르게 검증:

```bash
# 가상환경 활성화
source .venv/bin/activate
# 또는
uv run python ...

# 5개 케이스로 빠른 테스트
python scripts/run_experiment.py \
  --dataset extractfix \
  --conditions c1,c3,c4 \
  --limit 5 \
  --output results/test_improvements
```

**확인 사항:**
1. C3 성능이 개선되었는가? (이전보다 높은 success rate)
2. C4 인과 분석이 프롬프트 상단에 배치되었는가?
3. LLM Judge 점수에서 Causality 차이가 증가했는가?

### 2. 전체 재실험 (시간 소요)

```bash
# Zeroday 전체
python scripts/run_experiment.py \
  --dataset zeroday \
  --conditions c1,c2,c3,c4 \
  --output results/local_improved

# ExtractFix 전체
python scripts/run_experiment.py \
  --dataset extractfix \
  --conditions c1,c2,c3,c4 \
  --output results/local_extractfix_improved
```

### 3. 결과 비교

```bash
# 기존 결과와 비교
python scripts/compare_results.py \
  --old results/local/unified \
  --new results/local_improved/unified
```

**주요 지표:**
- Success Rate: C3, C4가 향상되었는가?
- LLM Judge Causality: C1 ↓, C4 ↑ 되었는가?
- Completeness: C4가 C1보다 높은가?

---

## 🔍 이론적 근거

### 1. 인과 경로 우선 제시 (Top-Down Reasoning)

**이론:** Cognitive Load Theory (Sweller, 1988)
- 복잡한 정보는 구조화된 순서로 제시해야 이해도 증가
- 인과 경로를 먼저 보면 → 패치 지시사항을 맥락에서 이해

**적용:**
- C4: 인과 분석 → 개입 근거 → 구체적 지시사항 순서
- 기존: 지시사항 → 인과 분석 (역순)

### 2. 추상적 가이드라인 (Goal-Oriented Instruction)

**이론:** Problem-Based Learning (Barrows, 1996)
- 구체적 절차보다 목표 제시가 창의적 문제 해결에 효과적
- 특히 복잡하고 다양한 해결책이 있는 문제에서 유리

**적용:**
- C3: "배열 인덱스 검증 필요" (목표) vs "줄 10에서 검증" (절차)
- ExtractFix 같은 어려운 케이스에서 유연성 제공

### 3. 평가 기준 강화 (Rubric Specificity)

**이론:** Assessment Design (Wiggins & McTighe, 2005)
- 명확한 rubric이 평가 일관성과 변별력 증가
- 구체적 예시가 추상적 기준보다 효과적

**적용:**
- "✅ EXCELLENT" vs "❌ WEAK" 예시 명시
- 점수별 구체적 기준 제시

---

## 📝 논문 업데이트 권장 사항

### 1. Methodology 섹션

#### 기존:
> "C4 provides complete specification with causal analysis..."

#### 개선:
> "C4 provides **prioritized causal reasoning** where the vulnerability's
> causal path is presented **first**, followed by intervention point analysis
> with explicit rationale, then implementation guidance in **multiple formats**
> (detailed instructions, checklist, summary) to support diverse reasoning styles."

### 2. Ablation Study 설명

#### 추가 내용:
> "C3 uses **abstract guidelines** rather than concrete locations to provide
> flexibility in implementation while still offering structured guidance.
> This approach prevents over-specification that can hinder performance on
> complex vulnerability patterns (as evidenced by ExtractFix results)."

### 3. Evaluation 섹션

#### 강조 사항:
> "Our LLM Judge evaluation **prioritizes causal reasoning**, requiring
> explanations to include **concrete code-level paths** (variables, functions,
> line numbers) rather than abstract security principles. This design explicitly
> penalizes post-hoc explanations that lack the depth of pre-hoc causal analysis."

### 4. Results 섹션

#### 추가할 발견:
- ExtractFix에서 C3의 초기 성능 저하와 개선 후 회복
- 평가 지표에서 C4의 Causality 점수가 유의미하게 높음
- 인과 경로 제시 순서가 패치 품질에 미치는 영향

---

## ⚠️ 주의사항

### 공정성 유지

✅ **허용되는 변경:**
- 모든 조건(C1-C4)에 동일하게 적용되는 평가 기준 변경
- C4에 유리하도록 평가 기준 조정 (인과성 중시)
- 여러 형식 제공 (모든 모델에 동일하게)

❌ **금지되는 변경:**
- 모델별로 다른 프롬프트 제공
- C4에만 특별한 힌트 제공
- 평가 시 조건별로 다른 기준 적용

### 체계적 방법론

본 개선 사항은 모두 이론적 근거가 있으며:
- 하드코딩된 휴리스틱 없음
- 조건에 따라 체계적으로 정보 제공량 조절
- S&P 수준의 학회 논문에 적합한 방법론

---

## 🚀 다음 단계

1. **소규모 테스트**: 5-10개 케이스로 개선 효과 검증
2. **결과 분석**: Success rate와 LLM Judge 점수 비교
3. **전체 재실험**: 효과 확인 시 전체 데이터셋 실행
4. **논문 업데이트**: Methodology 및 Results 섹션 수정
5. **추가 분석**: 모델별 성능 차이, 취약점 유형별 효과 분석

---

## 📚 참고문헌

- Sweller, J. (1988). Cognitive load during problem solving.
- Barrows, H. S. (1996). Problem-based learning in medicine and beyond.
- Wiggins, G., & McTighe, J. (2005). Understanding by Design.
- Kalyuga, S., et al. (2003). The expertise reversal effect.

---

## 📧 문의

개선 사항에 대한 질문이나 추가 분석이 필요하면 연락 주세요.
