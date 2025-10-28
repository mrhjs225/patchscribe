# PatchScribe RQ 분석 스크립트 및 실행 가이드

## ✅ 완료된 작업

### 1. RQ 분석 스크립트 구현
- **`scripts/run_rq_analysis.py`**: RQ별 상세 분석 도구
  - RQ1: Theory-Guided Generation 효과 측정
  - RQ2: Dual Verification 효과성 분석
  - RQ3: Scalability/Performance 프로파일링
  - RQ4: Explanation Quality 평가

- **`scripts/run_full_evaluation.py`**: 전체 평가 파이프라인
  - C1-C4 조건별 실행
  - 자동 RQ 분석
  - 비교 보고서 생성

- **`scripts/quick_eval.py`**: 빠른 기능 테스트

### 2. 문서 작성
- **`doc/RQ_EVALUATION_GUIDE.md`**: 상세 실행 가이드
- **`doc/COMMANDS_COMPLETE.md`**: 완전한 명령어 레퍼런스
- **`QUICKSTART_RQ.md`**: 빠른 시작 가이드

## 🚀 실행 방법 요약

### 기본 워크플로우

```bash
# 1단계: 기본 테스트 (30초)
python test_implementation.py

# 2단계: 빠른 파이프라인 테스트 (1-2분)
python scripts/quick_eval.py

# 3단계: 전체 RQ 평가 (2-4시간)
python scripts/run_full_evaluation.py \
    datasets/zeroday_repair/ \
    -o results/full_evaluation

# 4단계: 결과 확인
cat results/full_evaluation/EVALUATION_REPORT.md
```

### RQ별 실행

#### RQ1: Theory-Guided Generation
```bash
# 4가지 조건 비교 (C1, C2, C3, C4)
python scripts/run_full_evaluation.py \
    datasets/zeroday_repair/ \
    --conditions c1 c2 c3 c4 \
    -o results/rq1_analysis
```

**측정 지표**:
- Triple verification rate
- Ground truth similarity
- First attempt success rate

#### RQ2: Dual Verification
```bash
# C4 (full PatchScribe) 실행
python scripts/run_full_evaluation.py \
    datasets/zeroday_repair/ \
    --conditions c4 \
    -o results/rq2_analysis
```

**측정 지표**:
- Incomplete patches caught
- Consistency violation breakdown
- Verification method comparison

#### RQ3: Scalability/Performance
```bash
# 성능 프로파일링 포함
python scripts/run_full_evaluation.py \
    datasets/zeroday_repair/ \
    --conditions c4 \
    -o results/rq3_analysis
```

**측정 지표**:
- Phase-by-phase timing
- Total time (목표: <3분)
- Memory usage
- Iteration count

#### RQ4: Explanation Quality
```bash
# C4 실행 (자동 측정)
python scripts/run_full_evaluation.py \
    datasets/zeroday_repair/ \
    --conditions c4 \
    -o results/rq4_analysis
```

**측정 지표**:
- Checklist coverage (자동)
- Expert scores (수동 평가 필요)

### RQ 분석만 별도 실행
```bash
# 기존 결과 파일 분석
python scripts/run_rq_analysis.py \
    results/full_evaluation/raw_results/full_patchscribe_c4_results.json \
    -o results/rq_analysis.json
```

## 📂 출력 구조

```
results/full_evaluation/
├── raw_results/                      # 조건별 원시 결과
│   ├── baseline_c1_results.json
│   ├── vague_hints_c2_results.json
│   ├── prehoc_c3_results.json
│   └── full_patchscribe_c4_results.json
│
├── rq_analysis/                      # RQ별 분석
│   ├── rq_analysis_baseline_c1.json
│   ├── rq_analysis_baseline_c1.md
│   ├── rq_analysis_vague_hints_c2.json
│   ├── rq_analysis_vague_hints_c2.md
│   ├── rq_analysis_prehoc_c3.json
│   ├── rq_analysis_prehoc_c3.md
│   ├── rq_analysis_full_patchscribe_c4.json
│   ├── rq_analysis_full_patchscribe_c4.md
│   └── rq_comparative_analysis.json  # 조건 간 비교
│
└── EVALUATION_REPORT.md              # 최종 요약 보고서
```

## 📊 예상 결과 (Draft 기반)

### RQ1: Generation Effectiveness
- **C1 (Baseline)**: 30% success rate
- **C2 (Vague hints)**: 35% (+17%)
- **C3 (Pre-hoc)**: 50% (+67%)
- **C4 (Full)**: 70% (+133%)

### RQ2: Verification Effectiveness
- **Incomplete patches caught**: 3-5 cases
- **Triple verification**: 90% precision, 80% recall
- vs Exploit-only: 60% precision, 50% recall

### RQ3: Performance
- **Average time**: ~160s (2.7분)
  - Phase 1: 40s (25%)
  - Phase 2: 80s (50%)
  - Phase 3: 40s (25%)
- **Time overhead**: +45% vs baseline
- **Quality gain**: +56%

### RQ4: Explanation Quality
- **Checklist coverage**: ~85%
- **Expert scores**: 4.4-4.5/5
- **Trust improvement**: 4.3 vs 3.2 (post-hoc)

## 🛠️ 트러블슈팅

### 일반적인 문제

1. **ModuleNotFoundError**
   ```bash
   export PYTHONPATH=/home/hjs/research/patchscribe:$PYTHONPATH
   ```

2. **Dataset not found**
   ```bash
   # 절대 경로 사용
   python scripts/run_full_evaluation.py \
       /home/hjs/research/patchscribe/datasets/zeroday_repair/
   ```

3. **메모리 부족**
   ```bash
   # 작은 서브셋으로 테스트
   python scripts/quick_eval.py
   ```

4. **시간 초과**
   ```bash
   export PATCHSCRIBE_TIMEOUT=600  # 10분
   ```

## 📝 체크리스트

실행 전:
- [ ] Python 3.8+ 설치
- [ ] 의존성 설치 (`pip install -r requirements.txt`)
- [ ] 선택적 패키지 (`pip install psutil z3-solver`)
- [ ] 데이터셋 준비
- [ ] 충분한 시간 (전체 평가: 2-4시간)

실행 순서:
1. [ ] `test_implementation.py` - 기능 테스트
2. [ ] `quick_eval.py` - 파이프라인 테스트
3. [ ] `run_full_evaluation.py` - 전체 평가
4. [ ] 결과 확인 및 분석

## 📚 참고 문서

- **상세 가이드**: `doc/RQ_EVALUATION_GUIDE.md`
- **명령어 레퍼런스**: `doc/COMMANDS_COMPLETE.md`
- **빠른 시작**: `QUICKSTART_RQ.md`
- **구현 보고서**: `doc/implementation_complete_report.md`
- **Draft 논문**: `doc/draft.txt`

## 🎯 다음 단계

1. ✅ **지금**: `python test_implementation.py` 실행
2. ✅ **다음**: `python scripts/quick_eval.py` 실행
3. 📊 **이후**: 전체 평가 실행 및 논문 작성

---

## 💡 핵심 명령어 요약

```bash
# 모든 것을 실행하는 한 줄
python scripts/run_full_evaluation.py datasets/zeroday_repair/ -o results/full_evaluation

# 결과 확인
cat results/full_evaluation/EVALUATION_REPORT.md
```

이 명령어 하나로 모든 RQ(1-4)에 대한 완전한 분석을 수행할 수 있습니다!
