# PatchScribe RQ 평가 실행 가이드

## 개요
이 가이드는 PatchScribe의 Research Questions (RQ1-RQ4)에 대한 실험을 실행하고 결과를 분석하는 방법을 설명합니다.

## 필수 요구사항

### 1. 의존성 설치
```bash
# 기본 의존성
pip install -r requirements.txt

# 선택적 의존성 (권장)
pip install psutil  # 메모리 프로파일링용
pip install z3-solver  # 정형 검증 강화용
```

### 2. 데이터셋 준비
평가에 사용할 데이터셋이 필요합니다:
- `datasets/zeroday_repair/` - APPATCH zeroday repair 데이터셋 (10 CVEs)
- `datasets/patchdb_cvefixes_for_appatch_train/` - 추가 CVE 데이터셋
- 또는 커스텀 데이터셋 (JSON 형식)

## 실행 방법

### 방법 1: 빠른 테스트 (개발/검증용)

샘플 데이터로 빠르게 시스템을 테스트:

```bash
# 샘플 케이스로 실행
python scripts/quick_eval.py

# 특정 데이터셋으로 실행
python scripts/quick_eval.py datasets/zeroday_repair/sample.json
```

**결과 위치**: `results/quick_test/quick_test_results.json`

### 방법 2: 전체 RQ 평가

4가지 조건 (C1-C4)을 모두 실행하여 RQ1-RQ4 분석:

```bash
# 모든 조건 실행 (C1, C2, C3, C4)
python scripts/run_full_evaluation.py datasets/zeroday_repair/ -o results/full_evaluation

# 특정 조건만 실행
python scripts/run_full_evaluation.py datasets/zeroday_repair/ --conditions c3 c4

# RQ 분석 건너뛰기 (나중에 별도 실행)
python scripts/run_full_evaluation.py datasets/zeroday_repair/ --skip-analysis
```

**결과 위치**: `results/full_evaluation/`
- `raw_results/` - 각 조건의 원시 결과
- `rq_analysis/` - RQ별 상세 분석
- `EVALUATION_REPORT.md` - 최종 요약 보고서

### 방법 3: RQ 분석만 실행

이미 생성된 결과 파일들에 대해 RQ 분석만 수행:

```bash
# 특정 결과 파일 분석
python scripts/run_rq_analysis.py results/full_evaluation/raw_results/full_patchscribe_c4_results.json

# 커스텀 출력 경로
python scripts/run_rq_analysis.py results/my_results.json -o results/my_analysis.json
```

**결과**: 
- `rq_analysis.json` - JSON 형식 분석
- `rq_analysis.md` - Markdown 형식 요약

## 실행 조건 설명

### RQ1: Theory-Guided Generation Effectiveness

4가지 조건 비교:

1. **C1 (Baseline)**: 형식 가이드 없는 순수 LLM
   - Strategy: `only_natural`
   - Consistency check: 비활성화
   - 목적: 베이스라인 성능 측정

2. **C2 (Vague Hints)**: 비형식적 프롬프트
   - Strategy: `natural`
   - Consistency check: 비활성화
   - 목적: 간단한 힌트의 효과 측정

3. **C3 (Pre-hoc Guidance)**: E_bug 명세 제공 (검증 없음)
   - Strategy: `formal`
   - Consistency check: 비활성화
   - 목적: 사전 형식화의 효과 분리 측정

4. **C4 (Full PatchScribe)**: E_bug + 삼중 검증
   - Strategy: `formal`
   - Consistency check: 활성화
   - Performance profiling: 활성화
   - 목적: 완전한 시스템 성능 측정

### RQ2: Dual Verification Effectiveness

일관성 검증의 효과를 측정 (C4 결과에서 자동 분석):
- 불완전한 패치 탐지 수
- 일관성 위반 유형별 분류
- 검증 방법 간 합의율

### RQ3: Scalability and Performance

성능 오버헤드 측정 (C4 결과에서 자동 분석):
- 단계별 시간 (Phase 1/2/3)
- 코드 복잡도별 분류
- 메모리 사용량
- 반복 횟수

### RQ4: Explanation Quality

설명 품질 평가:
- 체크리스트 커버리지 (자동)
- LLM 품질 점수 (수동 평가 필요)

## 출력 파일 구조

```
results/full_evaluation/
├── raw_results/
│   ├── baseline_c1_results.json          # C1 원시 결과
│   ├── vague_hints_c2_results.json       # C2 원시 결과
│   ├── prehoc_c3_results.json            # C3 원시 결과
│   └── full_patchscribe_c4_results.json  # C4 원시 결과
├── rq_analysis/
│   ├── rq_analysis_baseline_c1.json      # C1 RQ 분석
│   ├── rq_analysis_baseline_c1.md
│   ├── rq_analysis_vague_hints_c2.json
│   ├── rq_analysis_vague_hints_c2.md
│   ├── rq_analysis_prehoc_c3.json
│   ├── rq_analysis_prehoc_c3.md
│   ├── rq_analysis_full_patchscribe_c4.json
│   ├── rq_analysis_full_patchscribe_c4.md
│   └── rq_comparative_analysis.json      # 조건 간 비교
└── EVALUATION_REPORT.md                  # 최종 요약 보고서
```

## 결과 해석

### RQ1 지표
- **Triple verification rate**: 삼중 검증 통과율 (높을수록 좋음)
- **Ground truth similarity**: 실제 CVE 패치와의 유사도
- **First attempt success rate**: 첫 시도 성공률 (가이드 품질 지표)

### RQ2 지표
- **Incomplete patches caught**: 탐지된 불완전한 패치 수
- **Consistency violations**: 유형별 일관성 위반
  - `causal_coverage`: 인과 커버리지 실패
  - `intervention_validity`: 개입 유효성 실패
  - `logical_consistency`: 논리적 일관성 실패
  - `completeness`: 완전성 실패

### RQ3 지표
- **Phase times**: 각 단계별 소요 시간
  - Phase 1 (Formalization): PCG/SCM 구축, E_bug 생성
  - Phase 2 (Generation): 패치 생성 반복
  - Phase 3 (Verification): 설명 생성, 평가
- **Total time**: 총 처리 시간 (목표: <3분)
- **Iterations**: 평균 반복 횟수

### RQ4 지표
- **Checklist coverage**: 필수 요소 포함률
- **LLM scores**: 전문가 품질 평가 (1-5점)
  - Accuracy: 정확성
  - Clarity: 명확성
  - Causality: 인과 관계 설명력

## 일반적인 명령어 시퀀스

### 전체 평가 실행 (모든 RQ)

```bash
# 1. 전체 평가 실행
python scripts/run_full_evaluation.py \
    datasets/zeroday_repair/ \
    -o results/full_evaluation

# 결과 확인
cat results/full_evaluation/EVALUATION_REPORT.md

# 2. 상세 분석 확인
cat results/full_evaluation/rq_analysis/rq_comparative_analysis.json
```

### 단계별 실행 (디버깅용)

```bash
# 1. 빠른 테스트로 시스템 확인
python scripts/quick_eval.py

# 2. C4 (전체 시스템)만 실행
python scripts/run_full_evaluation.py \
    datasets/zeroday_repair/ \
    --conditions c4 \
    -o results/test_c4

# 3. RQ 분석 별도 실행
python scripts/run_rq_analysis.py \
    results/test_c4/raw_results/full_patchscribe_c4_results.json \
    -o results/test_c4/analysis.json
```

### 특정 RQ만 분석

```bash
# RQ1 비교를 위해 C1과 C4만 실행
python scripts/run_full_evaluation.py \
    datasets/zeroday_repair/ \
    --conditions c1 c4 \
    -o results/rq1_comparison

# RQ3 성능 분석을 위해 C4만 실행 (프로파일링 포함)
python scripts/run_full_evaluation.py \
    datasets/zeroday_repair/ \
    --conditions c4 \
    -o results/rq3_performance
```

## 트러블슈팅

### 오류: "Dataset not found"
```bash
# 데이터셋 경로 확인
ls datasets/zeroday_repair/

# 절대 경로 사용
python scripts/run_full_evaluation.py \
    /home/hjs/research/patchscribe/datasets/zeroday_repair/
```

### 오류: "Module not found"
```bash
# Python 경로 확인
export PYTHONPATH=/home/hjs/research/patchscribe:$PYTHONPATH

# 또는 스크립트 디렉토리에서 실행
cd /home/hjs/research/patchscribe
python scripts/run_full_evaluation.py datasets/zeroday_repair/
```

### 메모리 부족
```bash
# 작은 서브셋으로 테스트
head -n 5 datasets/zeroday_repair/cases.json > datasets/small_test.json
python scripts/run_full_evaluation.py datasets/small_test.json
```

### 시간 초과
```bash
# 환경 변수로 타임아웃 조정
export PATCHSCRIBE_TIMEOUT=600  # 10분
python scripts/run_full_evaluation.py datasets/zeroday_repair/
```

## 결과 활용

### 논문 작성용 표 생성
```bash
# RQ 분석 결과를 LaTeX 표로 변환
python scripts/convert_to_latex.py \
    results/full_evaluation/rq_analysis/rq_comparative_analysis.json \
    -o paper/tables/rq_results.tex
```

### 그래프 생성
```bash
# 성능 비교 그래프
python scripts/plot_rq_results.py \
    results/full_evaluation/rq_analysis/ \
    -o paper/figures/
```

## 다음 단계

1. ✅ **기본 테스트**: `quick_eval.py`로 시스템 동작 확인
2. ✅ **전체 평가**: `run_full_evaluation.py`로 모든 조건 실행
3. ✅ **결과 분석**: 생성된 `EVALUATION_REPORT.md` 검토
4. 📊 **상세 분석**: RQ별 JSON/MD 파일에서 세부 지표 확인
5. 📝 **논문 작성**: 결과를 논문의 Evaluation 섹션에 반영

## 추가 정보

- **구현 상세**: `doc/implementation_complete_report.md`
- **격차 분석**: `doc/implementation_gaps.md`
- **Draft 논문**: `doc/draft.txt`
- **테스트 코드**: `test_implementation.py`

## 문의

구현 관련 질문이나 이슈는 GitHub Issues에 등록하거나 개발 팀에 문의하세요.
