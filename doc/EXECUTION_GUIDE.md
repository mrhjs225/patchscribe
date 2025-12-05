# PatchScribe 실행 가이드

본 문서는 PatchScribe 논문의 실험을 재현하고 시스템을 실행하는 방법을 설명합니다.

---

## 목차
1. [환경 설정](#1-환경-설정)
2. [데이터셋 준비](#2-데이터셋-준비)
3. [기본 실행 방법](#3-기본-실행-방법)
4. [논문 실험 재현](#4-논문-실험-재현)
5. [고급 사용법](#5-고급-사용법)
6. [결과 분석](#6-결과-분석)
7. [문제 해결](#7-문제-해결)

---

## 1. 환경 설정

### 1.1 Python 환경

**요구사항:**
- Python 3.10 이상
- LLVM/Clang (backward slicing용)
- Z3 SMT solver (선택사항, 성능 향상)

**설치:**

```bash
# 가상환경 생성
python3 -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# 의존성 설치
pip install -r requirements.txt

# LLVM/Clang 설치 (Ubuntu/Debian)
sudo apt-get install llvm-14 clang-14

# Z3 설치 (선택사항)
pip install z3-solver
```

### 1.2 LLM API 키 설정

**환경 변수 설정:**

```bash
# OpenAI
export OPENAI_API_KEY="your-openai-api-key"
export OPENAI_ENDPOINT="https://api.openai.com/v1/chat/completions"

# Anthropic (Claude)
export ANTHROPIC_API_KEY="your-anthropic-api-key"
export ANTHROPIC_ENDPOINT="https://api.anthropic.com/v1/messages"

# Google Gemini
export GEMINI_API_KEY="your-gemini-api-key"
```

**또는 `.env` 파일 생성:**

```bash
# .env 파일 생성
cat > .env << EOF
OPENAI_API_KEY=your-openai-api-key
ANTHROPIC_API_KEY=your-anthropic-api-key
GEMINI_API_KEY=your-gemini-api-key
EOF
```

### 1.3 캐시 디렉토리 설정 (선택사항)

```bash
# Stage-1 캐시 활성화 (성능 향상)
export PATCHSCRIBE_STAGE1_CACHE=".patchscribe_cache/stage1"

# 캐시 비활성화
export PATCHSCRIBE_STAGE1_CACHE=disable
```

---

## 2. 데이터셋 준비

### 2.1 사용 가능한 데이터셋

논문에서 사용한 데이터셋:

| 데이터셋 | 경로 | CVE 수 | 설명 |
|---------|------|--------|------|
| **Zero-Day** | `datasets/zeroday_repair/` | 97 | 2024년 최신 메모리 안전 취약점 |
| **ExtractFix** | `datasets/extractfix_dataset/` | 24 | 다양한 CWE, PoC 포함 |

### 2.2 데이터셋 구조 확인

```bash
# Zero-Day 데이터셋 확인
ls -l datasets/zeroday_repair/

# ExtractFix 데이터셋 확인
ls -l datasets/extractfix_dataset/

# 테스트용 작은 데이터셋
cat datasets/test_3cases.json
```

---

## 3. 기본 실행 방법

### 3.1 빠른 테스트 (3개 케이스)

```bash
# 가장 빠른 테스트 (quick mode)
python3 scripts/run_experiment.py --quick

# 위 명령은 다음과 동일:
# - 3개 케이스만 실행
# - 기본 모델 1개만 사용
# - C4 조건 (formal + consistency check)
```

### 3.2 단일 데이터셋 실행

```bash
# Zero-Day 데이터셋, 10개 케이스, OpenAI GPT-4.1-mini
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --limit 10 \
  --llm-provider openai \
  --models gpt-4.1-mini \
  --conditions c4

# ExtractFix 데이터셋, 전체 실행
python3 scripts/run_experiment.py \
  --dataset extractfix \
  --llm-provider anthropic \
  --models claude-haiku-4-5
```

### 3.3 Stage-1 사전 계산 (성능 최적화)

```bash
# Stage-1만 미리 계산 (PCG, SCM, E_bug 생성)
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --precompute-stage1

# 이후 실험에서 캐시 재사용
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --limit 10
```

---

## 4. 논문 실험 재현

### 4.1 전체 파이프라인 실행 (run.py 사용)

**가장 간단한 방법:**

```bash
# run.py 실행 (전체 실험 + 평가 + 분석)
python3 run.py
```

**run.py가 수행하는 작업:**

1. **Zero-Day 실험 실행**
   - Claude Haiku 4.5 모델 사용
   - 모든 조건 (C1-C4) 병렬 실행
   - 동시성 100 설정

2. **결과 평가**
   - LLM 기반 패치 품질 평가
   - Explanation quality 측정

3. **결과 분석**
   - 모델별, 조건별 통계 생성
   - 통합 분석 리포트 생성

4. **ExtractFix 실험** (동일 과정 반복)

### 4.2 RQ별 실험 재현

#### RQ1: Theory-Guided Generation Effectiveness

**목표:** C1 (baseline) vs C4 (formal+consistency) 성능 차이 검증

```bash
# C1 (baseline - minimal prompting) 실행
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --conditions c1 \
  --llm-provider openai \
  --models gpt-4.1-mini \
  --output results/rq1_c1

# C4 (formal + consistency) 실행
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --conditions c4 \
  --llm-provider openai \
  --models gpt-4.1-mini \
  --output results/rq1_c4

# 결과 비교
python3 scripts/analyze.py \
  results/rq1_c1_evaluated \
  results/rq1_c4_evaluated \
  --compare
```

**예상 결과 (논문):**
- C1: 26.4% correctness
- C4: 67.8% correctness (+41.4pp)

#### RQ2: Patch Quality

**목표:** Correctness, Ground truth similarity, Elimination rate 측정

```bash
# 전체 데이터셋 실행 (평가 포함)
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --conditions c4 \
  --output results/rq2

# 품질 평가
python3 scripts/evaluate_results.py results/rq2 \
  --concurrency 50

# PoC 실행 검증 (ExtractFix만 해당)
python3 scripts/run_experiment.py \
  --dataset extractfix \
  --enable-poc-execution \
  --output results/rq2_extractfix
```

#### RQ3: Scalability and Performance

**목표:** Phase 1/2 시간, iteration count 측정

```bash
# Performance profiling 활성화
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --enable-performance-profiling \
  --output results/rq3

# 복잡도별 분석
python3 scripts/analyze.py results/rq3_evaluated \
  --performance-breakdown
```

**예상 결과 (논문):**
- Phase 1: 0.30s (mean)
- Phase 2: 6.83s (mean)
- Total: 73.93s (mean)
- Iterations: 1.48 (mean)

#### RQ4: Explanation Quality

**목표:** Checklist coverage + expert evaluation

```bash
# Explanation 평가 모드
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --explain-mode both \
  --output results/rq4

# Explanation quality 분석
python3 scripts/evaluate_results.py results/rq4 \
  --evaluate-explanations

# Manual rubric 생성 (전문가 평가용)
python3 scripts/generate_manual_rubric.py results/rq4_evaluated \
  --output results/rq4_manual_evaluation.csv
```

### 4.3 Ablation Study (C1-C4 비교)

```bash
# 모든 조건 병렬 실행
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --llm-provider openai \
  --models gpt-4.1-mini \
  --parallel-conditions \
  --output results/ablation

# 또는 수동으로 각 조건 실행
for condition in c1 c2 c3 c4; do
  python3 scripts/run_experiment.py \
    --dataset zeroday \
    --conditions $condition \
    --output results/ablation_$condition
done

# 통합 분석
python3 scripts/analyze.py results/ablation* \
  --all-conditions \
  --compare-conditions
```

### 4.4 Multi-Model 실험

```bash
# 여러 모델 동시 실행
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --llm-provider openai \
  --models gpt-5-mini,gpt-4.1-mini \
  --conditions c4 \
  --output results/multi_model_openai

# Claude 모델들
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --llm-provider anthropic \
  --models claude-3-5-haiku,claude-haiku-4-5 \
  --conditions c4 \
  --output results/multi_model_claude

# 결과 통합 분석
python3 scripts/analyze.py \
  results/multi_model_* \
  --unified
```

---

## 5. 고급 사용법

### 5.1 분산 실험 (여러 서버)

**시나리오:** 4대 서버에서 데이터셋을 분할 처리

```bash
# 서버 0 (0-24번 케이스)
python3 scripts/run_experiment.py \
  --distributed 0 4 25 \
  --dataset zeroday \
  --output results/server0

# 서버 1 (25-49번 케이스)
python3 scripts/run_experiment.py \
  --distributed 1 4 25 \
  --dataset zeroday \
  --output results/server1

# 서버 2 (50-74번 케이스)
python3 scripts/run_experiment.py \
  --distributed 2 4 25 \
  --dataset zeroday \
  --output results/server2

# 서버 3 (75-97번 케이스)
python3 scripts/run_experiment.py \
  --distributed 3 4 25 \
  --dataset zeroday \
  --output results/server3
```

**결과 병합:**

```bash
# 모든 서버 결과 수집 후
python3 scripts/merge_results.py \
  results/server0 \
  results/server1 \
  results/server2 \
  results/server3 \
  --output results/merged
```

### 5.2 동시성 제어

```bash
# 높은 동시성 (빠른 모델용 - GPT-5-mini)
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --llm-provider openai \
  --models gpt-5-mini \
  --llm-concurrency 400

# 낮은 동시성 (느린 모델용 - GPT-4)
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --llm-provider openai \
  --models gpt-4 \
  --llm-concurrency 10
```

### 5.3 Prompt 커스터마이징

```bash
# 특정 컴포넌트만 포함
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --prompt-components interventions,natural \
  --conditions c3

# 모든 컴포넌트 포함
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --prompt-components all \
  --conditions c4

# 최소 프롬프트
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --prompt-components none \
  --conditions c1
```

**사용 가능한 컴포넌트:**
- `interventions`: 개입 카탈로그 포함
- `natural`: 자연어 설명 포함
- `guidelines`: LLM 가이드라인 포함
- `provider_hint`: Provider별 최적화 힌트

### 5.4 재현성 보장 (Random Seed)

```bash
# 논문의 3개 시드로 실험
for seed in 42 123 789; do
  python3 scripts/run_experiment.py \
    --dataset zeroday \
    --seed $seed \
    --output results/seed_$seed
done

# Multi-seed 분석
python3 scripts/multi_seed_analysis.py \
  results/seed_42 \
  results/seed_123 \
  results/seed_789 \
  --output results/multi_seed_report.json
```

---

## 6. 결과 분석

### 6.1 기본 분석

```bash
# 단일 실험 결과 분석
python3 scripts/analyze.py results/my_experiment

# 여러 실험 비교
python3 scripts/analyze.py \
  results/exp1 \
  results/exp2 \
  --compare

# 통합 분석 (모든 모델/조건)
python3 scripts/analyze.py results/my_experiment \
  --unified
```

### 6.2 통계 분석

```bash
# T-test, effect size 계산
python3 scripts/statistical_analysis.py \
  results/c1_evaluated \
  results/c4_evaluated \
  --test paired-t \
  --effect-size cohen-d

# 신뢰구간 계산
python3 scripts/statistical_analysis.py \
  results/my_experiment \
  --confidence-interval 0.95
```

### 6.3 Threshold Calibration

```bash
# ROC curve 기반 threshold 최적화
python3 scripts/calibrate_thresholds.py \
  results/my_experiment \
  --method roc \
  --output results/optimal_thresholds.json

# Logistic regression calibration
python3 scripts/calibrate_thresholds.py \
  results/my_experiment \
  --method logistic \
  --cv 5
```

### 6.4 결과 시각화

```bash
# Performance breakdown 그래프
python3 scripts/plot_results.py \
  results/my_experiment \
  --plot performance-breakdown \
  --output figures/

# Condition 비교 차트
python3 scripts/plot_results.py \
  results/ablation* \
  --plot condition-comparison \
  --output figures/

# Consistency score distribution
python3 scripts/plot_results.py \
  results/my_experiment \
  --plot consistency-distribution \
  --output figures/
```

---

## 7. 문제 해결

### 7.1 일반적인 오류

#### 오류: "LLVM slicer not available"

```bash
# LLVM/Clang 설치 확인
which llvm-config
which clang

# 환경 변수 설정
export LLVM_CONFIG=/usr/bin/llvm-config-14

# Heuristic 모드로 폴백 (정확도 낮음)
export PATCHSCRIBE_ALLOW_HEURISTICS=1
python3 scripts/run_experiment.py --dataset zeroday
```

#### 오류: "Z3 solver timeout"

```bash
# Timeout 증가
export PATCHSCRIBE_SMT_TIMEOUT=60000  # 60초

# Z3 비활성화 (heuristic으로 폴백)
pip uninstall z3-solver
```

#### 오류: "LLM API rate limit"

```bash
# 동시성 감소
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --llm-concurrency 10

# Retry 설정 증가
export PATCHSCRIBE_LLM_MAX_RETRIES=5
```

### 7.2 캐시 관련

```bash
# 캐시 초기화
rm -rf .patchscribe_cache/

# 캐시 강제 재계산
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --force-stage1-recompute

# 캐시 위치 변경
export PATCHSCRIBE_STAGE1_CACHE=/path/to/cache
```

### 7.3 디버깅 모드

```bash
# Verbose 로깅
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --verbose

# 특정 케이스만 실행
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --case-ids CVE-2024-12345

# 실패한 케이스 재시도
python3 scripts/retry_failures.py results/my_experiment
```

### 7.4 성능 최적화

```bash
# Stage-1 캐시 사용
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --precompute-stage1

# 병렬 조건 실행
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --parallel-conditions

# 메모리 사용량 모니터링
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --enable-performance-profiling \
  --memory-tracking
```

---

## 8. 결과 디렉토리 구조

실험 실행 후 결과 디렉토리 구조:

```
results/
├── my_experiment/
│   ├── gpt-4.1-mini/
│   │   ├── c1/
│   │   │   ├── CVE-2024-12345.json    # 개별 케이스 결과
│   │   │   ├── CVE-2024-67890.json
│   │   │   └── ...
│   │   ├── c2/
│   │   ├── c3/
│   │   └── c4/
│   ├── claude-haiku-4-5/
│   └── ...
├── my_experiment_evaluated/           # 평가 후 결과
│   ├── gpt-4.1-mini/
│   │   ├── c4/
│   │   │   ├── CVE-2024-12345_evaluated.json
│   │   │   └── ...
│   │   └── summary.json               # 조건별 요약
│   └── overall_summary.json           # 전체 요약
└── analysis/
    ├── performance_breakdown.json
    ├── condition_comparison.json
    └── figures/
        ├── roc_curve.png
        └── performance_chart.png
```

---

## 9. 빠른 참조 (Cheat Sheet)

### 자주 사용하는 명령어

```bash
# 1. 빠른 테스트
python3 scripts/run_experiment.py --quick

# 2. 전체 파이프라인
python3 run.py

# 3. 특정 모델/조건
python3 scripts/run_experiment.py --dataset zeroday \
  --llm-provider openai --models gpt-4.1-mini --conditions c4

# 4. 결과 평가
python3 scripts/evaluate_results.py results/my_experiment

# 5. 결과 분석
python3 scripts/analyze.py results/my_experiment_evaluated

# 6. Stage-1 캐시 생성
python3 scripts/run_experiment.py --dataset zeroday --precompute-stage1
```

### 주요 옵션

| 옵션 | 설명 | 예시 |
|------|------|------|
| `--dataset` | 데이터셋 선택 | `zeroday`, `extractfix` |
| `--limit` | 처리할 케이스 수 제한 | `--limit 10` |
| `--llm-provider` | LLM 제공자 | `openai`, `anthropic`, `gemini` |
| `--models` | 사용할 모델 | `gpt-4.1-mini,gpt-5-mini` |
| `--conditions` | 실험 조건 | `c1`, `c2`, `c3`, `c4` |
| `--parallel-conditions` | 조건들을 병렬 실행 | (플래그) |
| `--llm-concurrency` | LLM API 동시성 | `--llm-concurrency 100` |
| `--output` | 결과 저장 경로 | `--output results/exp1` |
| `--seed` | Random seed | `--seed 42` |
| `--quick` | 빠른 테스트 모드 | (플래그) |
| `--precompute-stage1` | Stage-1 캐시 생성 | (플래그) |

---

## 10. 추가 리소스

- **논문**: [doc/paper/patchscribe.tex](../paper/patchscribe.tex)
- **구현 상태**: [doc/implementation_status.md](implementation_status.md)
- **API 문서**: [patchscribe/README.md](../patchscribe/README.md) (작성 필요)
- **예제 노트북**: [examples/](../examples/) (작성 필요)

---

**마지막 업데이트**: 2025-11-20
