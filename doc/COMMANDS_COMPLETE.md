# PatchScribe RQ 실행 명령어 완전 가이드

## 📋 목차
1. [기본 명령어](#기본-명령어)
2. [RQ별 실행 방법](#rq별-실행-방법)
3. [예상 결과](#예상-결과)
4. [문제 해결](#문제-해결)

---

## 🚀 기본 명령어

### 준비 단계
```bash
# 프로젝트 디렉토리로 이동
cd /home/hjs/research/patchscribe

# 의존성 확인 (선택사항)
pip install psutil z3-solver

# 데이터셋 확인
ls datasets/zeroday_repair/
```

### 1단계: 빠른 기능 테스트 (30초-1분)
```bash
# 기본 구현 테스트
python test_implementation.py

# 샘플 케이스로 파이프라인 테스트
python scripts/quick_eval.py
```

**예상 출력**:
```
============================================================
Testing newly implemented PatchScribe features
============================================================
Testing FormalBugExplanation...
✓ E_bug created: V_bug ⟺ (x < 0)

Testing FormalPatchExplanation...
✓ E_patch created: Added bounds check

...

✅ All tests passed!
```

### 2단계: 전체 RQ 평가 실행 (수 시간)

#### Option A: 모든 조건 실행 (완전한 평가)
```bash
python scripts/run_full_evaluation.py \
    datasets/zeroday_repair/ \
    -o results/full_evaluation
```

#### Option B: 특정 조건만 실행 (시간 절약)
```bash
# C1 (baseline)과 C4 (full)만 비교
python scripts/run_full_evaluation.py \
    datasets/zeroday_repair/ \
    --conditions c1 c4 \
    -o results/rq1_comparison

# C4 (full)만 실행 (RQ2, RQ3 분석용)
python scripts/run_full_evaluation.py \
    datasets/zeroday_repair/ \
    --conditions c4 \
    -o results/full_system
```

### 3단계: 결과 확인
```bash
# 최종 보고서 확인
cat results/full_evaluation/EVALUATION_REPORT.md

# RQ별 상세 분석 확인
cat results/full_evaluation/rq_analysis/rq_comparative_analysis.json

# Markdown 요약 확인
cat results/full_evaluation/rq_analysis/rq_analysis_full_patchscribe_c4.md
```

---

## 📊 RQ별 실행 방법

### RQ1: Theory-Guided Generation Effectiveness

**목적**: 사전 형식 명세가 패치 품질을 개선하는지 측정

**명령어 (4가지 조건 비교)**:
```bash
python scripts/run_full_evaluation.py \
    datasets/zeroday_repair/ \
    --conditions c1 c2 c3 c4 \
    -o results/rq1_full
```

**조건 설명**:
- **C1** (baseline): LLM만 사용, 형식 가이드 없음
- **C2** (vague hints): 비형식적 힌트 제공
- **C3** (pre-hoc): E_bug 명세 제공, 검증 없음
- **C4** (full): E_bug + 삼중 검증

**예상 소요 시간**: 
- 10 cases: 약 2-3시간
- Case당 평균: C1(2분), C2(2분), C3(3분), C4(4분)

**결과 파일**:
```
results/rq1_full/
├── raw_results/
│   ├── baseline_c1_results.json
│   ├── vague_hints_c2_results.json
│   ├── prehoc_c3_results.json
│   └── full_patchscribe_c4_results.json
└── rq_analysis/
    └── rq_comparative_analysis.json
```

**주요 측정 지표**:
```python
# results에서 추출할 지표
{
  "triple_verification_rate": "삼중 검증 통과율",
  "ground_truth_similarity": "실제 CVE 패치 유사도",
  "first_attempt_success_rate": "첫 시도 성공률"
}
```

---

### RQ2: Dual Verification Effectiveness

**목적**: 일관성 검증이 불완전 패치를 탐지하는지 측정

**명령어 (C4만 필요)**:
```bash
python scripts/run_full_evaluation.py \
    datasets/zeroday_repair/ \
    --conditions c4 \
    -o results/rq2_verification
```

**예상 소요 시간**: 10 cases × 4분 = 약 40분

**결과 분석**:
```bash
# RQ2 특화 분석
python scripts/run_rq_analysis.py \
    results/rq2_verification/raw_results/full_patchscribe_c4_results.json \
    -o results/rq2_verification/rq2_analysis.json

# 일관성 위반 확인
cat results/rq2_verification/rq2_analysis.md | grep "Consistency violation"
```

**측정 지표**:
```python
{
  "incomplete_patches_caught": "탐지된 불완전 패치 수",
  "consistency_violations": {
    "causal_coverage": "인과 커버리지 실패",
    "intervention_validity": "개입 유효성 실패", 
    "logical_consistency": "논리적 일관성 실패",
    "completeness": "완전성 실패"
  }
}
```

---

### RQ3: Scalability and Performance

**목적**: 각 단계의 시간 오버헤드 측정

**명령어 (성능 프로파일링 포함 C4)**:
```bash
python scripts/run_full_evaluation.py \
    datasets/zeroday_repair/ \
    --conditions c4 \
    -o results/rq3_performance
```

**예상 결과 (복잡도별)**:
```
Simple (<50 LoC):
  Phase 1: ~30s (PCG/SCM 구축, E_bug 생성)
  Phase 2: ~50s (패치 생성 반복)
  Phase 3: ~20s (설명 생성, 검증)
  Total: ~100s (< 2분)

Medium (50-100 LoC):
  Phase 1: ~40s
  Phase 2: ~80s
  Phase 3: ~40s
  Total: ~160s (2-3분)

Complex (>100 LoC):
  Phase 1: ~60s
  Phase 2: ~120s
  Phase 3: ~60s
  Total: ~240s (3-4분)
```

**성능 데이터 확인**:
```bash
# 단계별 시간 확인
cat results/rq3_performance/rq_analysis/rq_analysis_full_patchscribe_c4.json | \
    jq '.rq3_scalability_performance'

# 평균 시간 계산
python -c "
import json
with open('results/rq3_performance/raw_results/full_patchscribe_c4_results.json') as f:
    data = json.load(f)
    times = [c['performance']['total_time_seconds'] for c in data['cases'] if 'performance' in c]
    print(f'Average time: {sum(times)/len(times):.2f}s')
"
```

---

### RQ4: Explanation Quality

**목적**: 설명의 품질과 유용성 측정

**자동 측정 (C4 결과에서)**:
```bash
python scripts/run_full_evaluation.py \
    datasets/zeroday_repair/ \
    --conditions c4 \
    -o results/rq4_quality

# 체크리스트 커버리지 확인
cat results/rq4_quality/rq_analysis/rq_analysis_full_patchscribe_c4.json | \
    jq '.rq4_explanation_quality[0].checklist_coverage'
```

**수동 평가 (추후 수행)**:
```bash
# 설명 추출
python scripts/extract_explanations.py \
    results/rq4_quality/raw_results/full_patchscribe_c4_results.json \
    -o results/rq4_quality/explanations/

# 전문가 평가 수행 (별도 프로세스)
# 1. explanations/ 폴더의 E_bug, E_patch 검토
# 2. 정확성, 명확성, 인과관계 평가 (1-5점)
# 3. 결과를 expert_scores.json에 기록
```

---

## 📈 예상 결과

### RQ1 예상 수치 (Draft 기반)
```
C1 (Baseline):           30% success rate
C2 (Vague hints):        35% success rate (+17%)
C3 (Pre-hoc guidance):   50% success rate (+67%)
C4 (Full PatchScribe):   70% success rate (+133%)

Key insight: 
- Pre-hoc formalization: +67% improvement
- Triple verification: +40% additional improvement
```

### RQ2 예상 수치
```
Incomplete patches caught: 3-5 cases
Precision: ~90%
Recall: ~80%

Verification method comparison:
V1 (Exploit-only):    60% precision, 50% recall
V4 (Triple):          90% precision, 80% recall
```

### RQ3 예상 수치
```
Average total time: 160s (2.7 min)
  Phase 1: ~40s (25%)
  Phase 2: ~80s (50%)
  Phase 3: ~40s (25%)

Time overhead vs VRpilot: +45% (110s → 160s)
Quality improvement: +56% (0.45 → 0.70)
```

### RQ4 예상 수치
```
Checklist coverage: ~85%
Expert scores (1-5):
  Accuracy: 4.5
  Clarity: 4.4
  Causality: 4.5

Trust scores (vs post-hoc LLM):
  Dual explanations: 4.3/5
  Post-hoc LLM: 3.2/5
```

---

## 🔧 문제 해결

### 일반적인 오류

#### 1. "ModuleNotFoundError: No module named 'patchscribe'"
```bash
# 해결 1: PYTHONPATH 설정
export PYTHONPATH=/home/hjs/research/patchscribe:$PYTHONPATH

# 해결 2: 프로젝트 디렉토리에서 실행
cd /home/hjs/research/patchscribe
python scripts/run_full_evaluation.py datasets/zeroday_repair/
```

#### 2. "FileNotFoundError: Dataset not found"
```bash
# 데이터셋 경로 확인
ls -la datasets/zeroday_repair/

# 절대 경로 사용
python scripts/run_full_evaluation.py \
    /home/hjs/research/patchscribe/datasets/zeroday_repair/
```

#### 3. 메모리 부족
```bash
# 작은 서브셋으로 테스트
python -c "
import json
with open('datasets/zeroday_repair/cases.json') as f:
    data = json.load(f)
    subset = data[:3]  # 첫 3개만
with open('datasets/small_test.json', 'w') as f:
    json.dump(subset, f)
"

python scripts/run_full_evaluation.py datasets/small_test.json
```

#### 4. 시간 초과
```bash
# 타임아웃 증가
export PATCHSCRIBE_TIMEOUT=600  # 10분

# 또는 코드에서 직접 수정
# pipeline.py에서 timeout 파라미터 조정
```

### 디버깅 팁

#### 상세 로그 활성화
```bash
# 환경 변수로 로그 레벨 설정
export PATCHSCRIBE_LOG_LEVEL=DEBUG

python scripts/run_full_evaluation.py datasets/zeroday_repair/
```

#### 중간 결과 확인
```bash
# 각 케이스의 중간 결과 저장
python scripts/run_full_evaluation.py \
    datasets/zeroday_repair/ \
    --save-intermediate \
    -o results/debug
```

#### 특정 케이스만 실행
```bash
# 단일 케이스로 테스트
python -c "
from patchscribe.pipeline import PatchScribePipeline
import json

with open('datasets/zeroday_repair/cases.json') as f:
    cases = json.load(f)

pipeline = PatchScribePipeline(
    strategy='formal',
    enable_consistency_check=True,
    enable_performance_profiling=True
)

result = pipeline.run(cases[0])  # 첫 번째 케이스만
print(json.dumps(result.as_dict(), indent=2))
"
```

---

## 📝 체크리스트

실행 전 확인사항:

- [ ] Python 3.8+ 설치됨
- [ ] 필수 의존성 설치 완료 (`pip install -r requirements.txt`)
- [ ] 선택적 의존성 설치 (psutil, z3-solver)
- [ ] 데이터셋 준비 완료
- [ ] 충분한 디스크 공간 (최소 1GB)
- [ ] 충분한 실행 시간 확보 (전체 평가: 2-4시간)

실행 순서:

1. [ ] `python test_implementation.py` - 기본 기능 테스트
2. [ ] `python scripts/quick_eval.py` - 파이프라인 테스트
3. [ ] `python scripts/run_full_evaluation.py ...` - 전체 평가
4. [ ] `cat results/*/EVALUATION_REPORT.md` - 결과 확인
5. [ ] RQ별 상세 분석 검토

---

## 🎯 요약: 필수 명령어

```bash
# 1. 기본 테스트 (1분)
python test_implementation.py

# 2. 빠른 평가 (1-2분)
python scripts/quick_eval.py

# 3. 전체 RQ 평가 (2-4시간)
python scripts/run_full_evaluation.py \
    datasets/zeroday_repair/ \
    -o results/full_evaluation

# 4. 결과 확인
cat results/full_evaluation/EVALUATION_REPORT.md
cat results/full_evaluation/rq_analysis/rq_comparative_analysis.json
```

이 명령어들을 순서대로 실행하면 모든 RQ에 대한 완전한 분석 결과를 얻을 수 있습니다.
