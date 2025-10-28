# PatchScribe 실행 요약

## 🚀 빠른 시작

### 1. 기본 테스트 (30초)
```bash
# 샘플 케이스로 테스트
python scripts/quick_eval.py

# 또는 실제 데이터셋으로 테스트 (3 cases)
python scripts/quick_eval.py zeroday  # 2024 CVE 데이터
python scripts/quick_eval.py poc      # 간단한 테스트 케이스
```

### 2. 전체 RQ 평가 (수 시간)
```bash
# 내장 zeroday 데이터셋 사용 (100+ CVEs)
python scripts/run_full_evaluation.py zeroday -o results/full_evaluation

# 또는 디렉토리 경로 사용
python scripts/run_full_evaluation.py datasets/zeroday_repair/ -o results/full_evaluation
```

### 3. 결과 확인
```bash
cat results/full_evaluation/EVALUATION_REPORT.md
```

## 📊 데이터셋

- **`poc`**: 3개 간단한 테스트 케이스 (개발용)
- **`zeroday`**: 100+ 실제 2024 CVE 케이스 (평가용)
  - CWE-125, CWE-190, CWE-401, CWE-457, CWE-476, CWE-787
  - 7-517 라인 코드
  
자세한 내용: `doc/DATASET_GUIDE.md`

## 📊 Research Questions

### RQ1: Theory-Guided Generation Effectiveness
**질문**: 사전 형식 명세(E_bug)가 더 정확한 패치를 생성하는가?

**실행**:
```bash
# 4가지 조건 모두 실행 (C1: baseline, C2: vague hints, C3: pre-hoc, C4: full)
python scripts/run_full_evaluation.py datasets/zeroday_repair/ --conditions c1 c2 c3 c4
```

**측정 지표**:
- Triple verification rate (삼중 검증 통과율)
- Ground truth similarity (실제 패치 유사도)
- First attempt success rate (첫 시도 성공률)

### RQ2: Dual Verification Effectiveness
**질문**: 이중 설명(E_bug ↔ E_patch) + 일관성 검증이 불완전 패치를 탐지하는가?

**실행**:
```bash
# C4 (full PatchScribe) 실행
python scripts/run_full_evaluation.py datasets/zeroday_repair/ --conditions c4
```

**측정 지표**:
- Incomplete patches caught (불완전 패치 탐지 수)
- Consistency violation breakdown (일관성 위반 유형)
- Verification agreement rate (검증 합의율)

### RQ3: Scalability and Performance
**질문**: 3단계 워크플로우의 시간 오버헤드는?

**실행**:
```bash
# 성능 프로파일링 포함하여 C4 실행
python scripts/run_full_evaluation.py datasets/zeroday_repair/ --conditions c4
```

**측정 지표**:
- Phase 1 time (형식화)
- Phase 2 time (생성)
- Phase 3 time (검증)
- Total time (목표: <3분)
- Peak memory usage

### RQ4: Explanation Quality
**질문**: 이중 설명이 개발자에게 유용한 인사이트를 제공하는가?

**측정 지표**:
- Checklist coverage (자동)
- Expert quality scores (수동 - 추후)

## 📂 출력 구조

```
results/full_evaluation/
├── raw_results/                  # 원시 결과 (조건별)
│   ├── baseline_c1_results.json
│   ├── vague_hints_c2_results.json
│   ├── prehoc_c3_results.json
│   └── full_patchscribe_c4_results.json
├── rq_analysis/                  # RQ 분석
│   ├── rq_analysis_*.json
│   ├── rq_analysis_*.md
│   └── rq_comparative_analysis.json
└── EVALUATION_REPORT.md          # 최종 보고서
```

## 🔧 트러블슈팅

### 데이터셋 문제
```bash
# 데이터셋 경로 확인
ls datasets/zeroday_repair/

# 샘플로 테스트
python scripts/quick_eval.py
```

### 모듈 임포트 오류
```bash
# PYTHONPATH 설정
export PYTHONPATH=/home/hjs/research/patchscribe:$PYTHONPATH
```

### 메모리/시간 부족
```bash
# 작은 서브셋으로 테스트
python scripts/run_full_evaluation.py datasets/small_subset.json
```

## 📚 상세 가이드

전체 가이드는 `doc/RQ_EVALUATION_GUIDE.md` 참조
