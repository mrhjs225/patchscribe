# 설명 평가 재평가 계획 (New Developer-Centric Criteria)

## 개요
새로운 개발자 중심 평가 기준으로 기존 실험 결과를 재평가합니다.

## 변경 사항

### 기존 평가 기준 (Old)
1. **Accuracy**: 기술적 정확성
2. **Completeness**: 완전성 (근본 원인, 공격 벡터, 완화)
3. **Clarity**: 명료성
4. **Causality**: 인과성

**문제점:**
- Clarity 과대평가 (모든 조건에서 4.24-4.29점)
- 개발자 관점 부족
- C1과 C4 구별 실패

### 새로운 평가 기준 (New)
1. **Vulnerability Understanding**: 개발자가 **왜** 취약한지 이해할 수 있는가?
   - Trigger Conditions (발생 조건)
   - Vulnerable Location (취약점 위치)
   - Impact (영향)

2. **Patch Understanding**: 개발자가 **어떻게** 패치가 작동하는지 이해할 수 있는가?
   - Code Changes (코드 변경 내용)
   - Mechanism (작동 메커니즘)
   - Side Effects & Constraints (부작용/제약)

3. **Causal Connection**: 개발자가 **왜** 이 패치가 문제를 해결하는지 이해할 수 있는가?
   - Bug-to-Patch Mapping (취약점-패치 연결)
   - Counterfactual Reasoning (반사실적 추론)
   - Why This Specific Fix (특정 해법 선택 이유)

4. **Actionability**: 개발자가 이 지식을 **적용**할 수 있는가?
   - Pattern Recognition (패턴 식별)
   - Similar Vulnerability Detection (유사 취약점 찾기)
   - Prevention Guidelines (예방 가이드라인)

**장점:**
- 개발자 실용성 중심
- 구체성 강조 (라인 번호, 코드 스니펫)
- 모호한 표현 패널티
- 실행 가능한 인사이트 보상

## 예상 효과

### C1 vs C4 점수 차이 (추정)
```
                          Old     New     차이
C1 (Post-hoc Natural):    3.29    3.0     -0.29
C4 (Full PatchScribe):    3.46    3.5     +0.04
----------------------------------------
차이:                     0.17    0.5     +0.33
```

**주요 개선:**
- **Patch Understanding**: C4가 형식적 명세로 더 체계적 (+0.7점 예상)
- **Actionability**: C4가 패턴/예방 가이드 제공 (+0.7점 예상)
- **Vulnerability Understanding**: 비슷 (+0.3점 예상)
- **Causal Connection**: C4 약간 우세 (+0.3점 예상)

## 실행 계획

### Phase 1: 소규모 테스트 (1-2 케이스)
**목적**: 새 프롬프트가 제대로 작동하는지 확인

```bash
# 테스트 케이스 선택 (예: GPT-5-mini C4 결과)
source .venv/bin/activate
python scripts/analyze.py \
  --judge-only \
  --judge-batch-size 1 \
  results/local/gpt-5-mini/c4_results.json
```

**확인사항:**
- [ ] JSON 응답 형식이 올바른가?
- [ ] 새 필드명(vulnerability_understanding 등)이 파싱되는가?
- [ ] 점수가 합리적인가? (1-5 범위)
- [ ] Reasoning이 상세한가?

### Phase 2: 단일 모델 전체 재평가
**목적**: 한 모델의 모든 조건(C1-C4) 재평가

```bash
# GPT-5-mini 모든 조건 재평가 (4 파일: c1, c2, c3, c4)
source .venv/bin/activate
python scripts/analyze.py \
  --judge-only \
  --judge-batch-size 5 \
  --all-conditions \
  results/local/gpt-5-mini/
```

**확인사항:**
- [ ] C1 점수가 낮아졌는가?
- [ ] C4 점수가 높아졌는가?
- [ ] 차이가 통계적으로 유의미한가? (>0.3점)

**예상 소요 시간:**
- 97 케이스 × 4 조건 = 388 케이스
- GPT-5 API 속도: ~2초/케이스 (병렬 5)
- 예상 시간: 388 / 5 × 2초 ≈ 2.6분

### Phase 3: 전체 데이터셋 재평가 (Zeroday)
**목적**: 모든 모델의 Zeroday 결과 재평가

```bash
# Zeroday 전체 재평가 (local 디렉토리)
source .venv/bin/activate
python scripts/analyze.py \
  --judge-only \
  --judge-batch-size 10 \
  --all-conditions \
  results/local/
```

**모델 목록:**
- gpt-5-mini
- claude-haiku-4-5
- gemini-2.5-flash

**확인사항:**
- [ ] 모든 모델에서 C1→C4 점수 향상?
- [ ] 평균 점수 차이 확인
- [ ] unified 결과 업데이트

**예상 소요 시간:**
- 97 케이스 × 4 조건 × 3 모델 = 1164 케이스
- GPT-5 API 속도: ~2초/케이스 (병렬 10)
- 예상 시간: 1164 / 10 × 2초 ≈ 3.9분

### Phase 4: ExtractFix 재평가
**목적**: ExtractFix 결과 재평가

```bash
# ExtractFix 전체 재평가
source .venv/bin/activate
python scripts/analyze.py \
  --judge-only \
  --judge-batch-size 10 \
  --all-conditions \
  results/local_extractfix/
```

**확인사항:**
- [ ] ExtractFix에서도 C1→C4 향상?
- [ ] 점수 차이가 더 명확해졌는가?

**예상 소요 시간:**
- 24 케이스 × 4 조건 × 4 모델 = 384 케이스
- 예상 시간: 384 / 10 × 2초 ≈ 1.3분

### Phase 5: 통합 분석 및 리포트 생성
**목적**: 재평가 결과 통합 분석

```bash
# Unified 결과 생성
source .venv/bin/activate
python scripts/analyze.py --unified results/local/
python scripts/analyze.py --unified results/local_extractfix/
```

**확인사항:**
- [ ] C1 vs C4 평균 점수 차이
- [ ] 각 차원별 점수 분포
- [ ] 통계적 유의성 검정

## 비용 및 시간 추정

### API 비용 (GPT-5)
- **입력 토큰**: ~3000 토큰/케이스 (프롬프트 + 코드 + 설명)
- **출력 토큰**: ~500 토큰/케이스 (JSON 응답)
- **총 케이스**: 1164 (Zeroday) + 384 (ExtractFix) = 1548 케이스
- **총 토큰**: 1548 × (3000 + 500) = 5,418,000 토큰 ≈ 5.4M 토큰

**GPT-5 가격 (2025년 기준):**
- 입력: $0.5/1M 토큰
- 출력: $1.5/1M 토큰
- **예상 비용**: (1548 × 3000 × 0.5 + 1548 × 500 × 1.5) / 1,000,000 ≈ $3.5

### 총 소요 시간
- Phase 1: 5분 (테스트)
- Phase 2: 3분 (단일 모델)
- Phase 3: 4분 (Zeroday 전체)
- Phase 4: 2분 (ExtractFix)
- Phase 5: 5분 (분석)
- **총 시간**: ~20분

## 검증 체크리스트

### 기술적 검증
- [ ] JSON 파싱 성공률 100%
- [ ] 모든 케이스에 4개 차원 점수 존재
- [ ] 점수 범위 1-5 준수
- [ ] Reasoning 필드 존재

### 과학적 검증
- [ ] C1 평균 점수 감소 (예상: 3.29 → 3.0)
- [ ] C4 평균 점수 유지 또는 증가 (예상: 3.46 → 3.5)
- [ ] C1-C4 차이 확대 (예상: 0.17 → 0.5)
- [ ] 통계적 유의성 (p < 0.05)

### 논문 기여
- [ ] RQ2 (설명 품질) 결과 업데이트
- [ ] C1 vs C4 비교 강화
- [ ] 개발자 관점 평가 방법론 추가
- [ ] Actionability 차원 강조

## 롤백 계획
만약 새 평가 기준이 예상대로 작동하지 않으면:

1. **결과 백업**: 기존 `llm_scores` 필드 보존
2. **새 필드 추가**: `llm_scores_v2` 필드에 새 점수 저장
3. **비교 분석**: 두 버전 점수 비교
4. **선택**: 더 나은 평가 방법 선택

## 다음 단계
1. ✅ Phase 1 실행: 테스트 케이스 재평가
2. ⏸️ 결과 검토: 점수 합리성 확인
3. ⏸️ Phase 2 실행: 단일 모델 전체 재평가
4. ⏸️ Phase 3-5 실행: 전체 데이터셋 재평가
5. ⏸️ 논문 업데이트: 새 결과 반영

---
**작성일**: 2025-11-11
**작성자**: Claude (PatchScribe 개선 프로젝트)
