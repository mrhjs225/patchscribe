# PatchScribe

**Theory-Guided Vulnerability Repair Framework with Dual Causal Explanations**

PatchScribe는 형식적 인과 이론(formal causality theory)을 활용하여 취약점을 자동으로 수정하고, 이중 인과 설명(E_bug ↔ E_patch)을 생성하는 프레임워크입니다. LLM 기반 평가를 통해 패치 품질과 설명 품질을 측정합니다.

---

## 🚀 빠른 시작

### 1️⃣ 환경 설정

```bash
# Python 3.8 이상 필요
python3 --version

# Ollama 시작 (로컬 LLM 서버)
ollama serve  # 별도 터미널에서

# 실험 대상 모델 다운로드 (16개 중 필요한 것만)
ollama pull qwen3:14b
ollama pull gemma3:12b
ollama pull deepseek-r1:7b
# ... 필요한 모델 추가

# OpenAI API 키 설정 (GPT Judge 평가용)
export OPENAI_API_KEY=sk-...
```

**주의**: 환경 변수 `PATCHSCRIBE_LLM_*` 설정은 **불필요**합니다.
모델은 `--models` 옵션으로 지정하며, 실험 스크립트가 자동으로 설정합니다.

### 2️⃣ 실험 실행

PatchScribe는 **2개의 핵심 스크립트**로 모든 실험을 수행합니다:

#### 📊 **실험 스크립트** - `run_experiment.py`

모든 실험 워크플로우를 단일 스크립트로 실행합니다.

```bash
# 빠른 테스트 (3개 케이스)
python3 scripts/run_experiment.py --quick

# 로컬 실험 (10개 케이스)
python3 scripts/run_experiment.py --dataset zeroday --limit 10

# 분산 실험 (Server 0, 4대 서버 중)
python3 scripts/run_experiment.py --distributed 0 4 20 --dataset zeroday

# Stage-1 캐시만 미리 생성 (LLM 호출 전 준비)
python3 scripts/run_experiment.py --dataset zeroday --limit 10 --precompute-stage1

# Stage-1 캐시 경로 변경 / 강제 재계산
python3 scripts/run_experiment.py --dataset zeroday --limit 10 \
    --stage1-cache-dir results/cache/custom_stage1 \
    --refresh-stage1-cache
```

**주요 기능**:
- ✅ 로컬 및 분산 실험 지원
- ✅ 모든 모델 × 조건(C1-C4) 자동 실험
- ✅ RQ2용 불완전 패치 자동 생성
- ✅ 진행 상황 실시간 표시

#### 📈 **분석 스크립트** - `analyze.py`

실험 결과를 자동으로 분석하여 모든 RQ 분석 결과를 생성합니다.

```bash
# 로컬 실험 결과 분석
python3 scripts/analyze.py results/local

# 분산 실험 결과 병합 및 분석
python3 scripts/analyze.py --merge results/server*

# 다중 모델 비교
python3 scripts/analyze.py --compare results/model1 results/model2
```

**주요 기능**:
- ✅ RQ1-RQ4 자동 분석
- ✅ 분산 결과 자동 병합
- ✅ 다중 모델 비교 리포트
- ✅ Markdown + JSON 리포트 생성

---

## 📖 실험 예시

### 로컬 환경에서 전체 파이프라인

```bash
# 1. 실험 실행 (10개 케이스)
python3 scripts/run_experiment.py --dataset zeroday --limit 10

# 2. 결과 분석
python3 scripts/analyze.py results/local
```

### 분산 환경에서 대규모 실험

```bash
# 각 서버에서 실행
# Server 0:
python3 scripts/run_experiment.py --distributed 0 4 20 --dataset zeroday

# Server 1:
python3 scripts/run_experiment.py --distributed 1 4 20 --dataset zeroday

# Server 2:
python3 scripts/run_experiment.py --distributed 2 4 20 --dataset zeroday

# Server 3:
python3 scripts/run_experiment.py --distributed 3 4 20 --dataset zeroday

# 중앙 서버에서 결과 수집 및 분석
python3 scripts/analyze.py --merge results/server*
```

---

## 📊 Research Questions

### RQ1: Theory-Guided Patch Generation
**질문**: E_bug 사전 명세가 더 정확하고 안전한 패치를 생성하는가?

**측정 지표** (LLM Judge):
- Patch Correctness (패치가 취약점을 올바르게 수정했는가?)
- Patch Completeness (모든 취약점 경로를 제거했는가?)
- Patch Safety (부작용이 없는가?)
- Semantic Similarity to Ground Truth (실제 패치와의 유사도)
- First Attempt Success (첫 시도 성공률)

### RQ2: Explanation Quality and Alignment
**질문**: E_bug/E_patch 형식 명세와 자연어 설명이 유용하고 일치하는가?

**측정 지표**:
- **Formal Spec Completeness** (자동): E_bug/E_patch 완전성
- **Natural Explanation Quality** (LLM Judge): Accuracy, Clarity, Causality
- **Consistency Check Pass Rate** (자동): E_bug ↔ E_patch 논리적 일관성
- **Explanation-Patch Alignment** (LLM Judge): 설명과 패치의 일치도

### RQ3: Ablation Study
**질문**: E_bug와 Consistency Check의 기여도는?

**조건**:
- **C1** (Baseline): E_bug ✗, Consistency ✗
- **C2** (Vague Hints): 비형식 힌트, Consistency ✗
- **C3** (Pre-hoc): E_bug ✓, Consistency ✗
- **C4** (Full): E_bug ✓, Consistency ✓

**측정**: C1→C4 간 Patch Correctness 및 Explanation Quality 변화

### RQ4: Efficiency Analysis
**질문**: 형식화 단계의 시간/메모리 오버헤드는 수용 가능한가?

**측정 지표**:
- Phase 1 Time (Formalization: PCG/SCM/E_bug)
- Phase 2 Time (Generation: Patch + E_patch + Explanation)
- Total Time (목표: 실용적 시간 내)
- Memory Usage
- Scalability (LOC에 따른 시간 증가율)

---

## 🗂️ 프로젝트 구조

```
patchscribe/
├── scripts/
│   ├── run_experiment.py    # 통합 실험 스크립트 ⭐
│   └── analyze.py            # 통합 분석 스크립트 ⭐
├── patchscribe/
│   ├── pipeline.py           # PatchScribe 메인 파이프라인
│   ├── pcg.py                # Program Causal Graph
│   ├── scm.py                # Structural Causal Model
│   ├── verification.py       # Triple verification
│   └── evaluation.py         # 평가 프레임워크
├── datasets/
│   └── zeroday_repair/       # Zero-day 취약점 데이터셋
├── doc/
│   ├── QUICKSTART.md         # 빠른 시작 가이드
│   ├── RQ_EVALUATION_GUIDE.md
│   └── DISTRIBUTED_GUIDE.md
└── results/                   # 실험 결과 (자동 생성)
```

---

## 📚 상세 문서

- **[QUICKSTART.md](doc/QUICKSTART.md)** - 전체 실험 실행 가이드
- **[RQ_EVALUATION_GUIDE.md](doc/RQ_EVALUATION_GUIDE.md)** - RQ 평가 상세 가이드
- **[DISTRIBUTED_GUIDE.md](doc/DISTRIBUTED_GUIDE.md)** - 분산 실행 가이드
- **[DATASET_GUIDE.md](doc/DATASET_GUIDE.md)** - 데이터셋 가이드

---

## 🎯 실험 조건 (C1-C4)

| 조건 | E_bug | Consistency Check | 설명 |
|------|-------|-------------------|------|
| **C1** (Baseline) | ✗ | ✗ | 프롬프트만, 형식 명세 없음 |
| **C2** (Vague Hints) | Vague | ✗ | 비형식 힌트 제공 |
| **C3** (Pre-hoc) | ✓ | ✗ | E_bug 있음, 일관성 체크 없음 |
| **C4** (Full PatchScribe) | ✓ | ✓ | E_bug + E_patch + Consistency |

**주요 특징**:
- ✅ LLM Judge 기반 평가 → 패치 품질과 설명 품질을 직접 측정
- ✅ Consistency Check → E_bug ↔ E_patch 논리적 일관성 체크
- ✅ 실용적이고 빠른 평가 방식

---

## 💡 핵심 명령어

### 실험
```bash
# 빠른 테스트 (3개 케이스)
python3 scripts/run_experiment.py --quick

# 전체 모델 실험 (16개 모델)
python3 scripts/run_experiment.py --dataset zeroday --limit 10

# 특정 모델만
python3 scripts/run_experiment.py --dataset zeroday --limit 10 \
    --models qwen3:14b gemma3:12b

# 특정 모델 + 조건
python3 scripts/run_experiment.py --dataset zeroday --limit 10 \
    --models llama3.2:1b --conditions c4

# 일관성 체크 비활성화 (C1, C2 조건에서는 자동 비활성화됨)
python3 scripts/run_experiment.py --dataset zeroday --limit 10 \
    --conditions c1 c2 --disable-consistency-check
```

**전체 실험 대상 모델 (16개)**:
- `qwen3:14b`, `qwen3:8b`, `qwen3:4b`, `qwen3:1.7b`, `qwen3:0.6b`
- `gemma3:12b`, `gemma3:4b`, `gemma3:1b`, `gemma3:270m`
- `deepseek-r1:14b`, `deepseek-r1:8b`, `deepseek-r1:7b`, `deepseek-r1:1.5b`
- `llama3.2:3b`, `llama3.2:1b`
- `gpt-oss:20b`

### 분석
```bash
# 로컬 결과 분석
python3 scripts/analyze.py results/local

# 특정 모델만 분석 (gpt-oss-20b, qwen3-4b)
python3 scripts/analyze.py results/local --models gpt-oss-20b qwen3-4b

# 분산 결과 병합 + 분석 (특정 모델만)
python3 scripts/analyze.py --merge results/server* --models qwen3-4b deepseek-r1-7b

# 모델 비교
python3 scripts/analyze.py --compare results/model1 results/model2
```

---

## 🔧 상세 명령어 옵션

### 📊 실험 스크립트 (`run_experiment.py`)

#### 기본 사용법

```bash
python3 scripts/run_experiment.py [옵션]
```

#### 실행 모드

##### 1. **빠른 테스트 모드** (`--quick`)
개발 및 디버깅용 빠른 테스트 실행

```bash
python3 scripts/run_experiment.py --quick
```

**자동 설정**:
- 케이스 수: 3개
- 조건: C4만 (Full PatchScribe)
- 모델: 기본 모델 1개

**출력**: `results/quick_test/`

---

##### 2. **로컬 실험 모드** (기본)
단일 서버에서 전체 실험 실행

```bash
# 기본 실행 (모든 조건, 모든 모델)
python3 scripts/run_experiment.py --dataset zeroday --limit 10

# 특정 모델만 실행
python3 scripts/run_experiment.py --dataset zeroday --limit 10 \
    --models llama3.2:3b qwen3:4b

# 특정 조건만 실행
python3 scripts/run_experiment.py --dataset zeroday --limit 10 \
    --conditions c4

# 조합 예시: 특정 모델 + 특정 조건
python3 scripts/run_experiment.py --dataset zeroday --limit 10 \
    --models llama3.2:3b \
    --conditions c3 c4
```

**출력**: `results/local/`

---

##### 3. **분산 실험 모드** (`--distributed`)
여러 서버에 케이스를 분산하여 실행

```bash
# 문법
python3 scripts/run_experiment.py --distributed <서버ID> <전체서버수> <전체케이스수>

# 예시: 4대 서버로 20개 케이스 분산
# Server 0 (케이스 0-4, 5개)
python3 scripts/run_experiment.py --distributed 0 4 20 --dataset zeroday

# Server 1 (케이스 5-9, 5개)
python3 scripts/run_experiment.py --distributed 1 4 20 --dataset zeroday

# Server 2 (케이스 10-14, 5개)
python3 scripts/run_experiment.py --distributed 2 4 20 --dataset zeroday

# Server 3 (케이스 15-19, 5개)
python3 scripts/run_experiment.py --distributed 3 4 20 --dataset zeroday
```

**자동 케이스 분배**:
- 20개 케이스 ÷ 4대 서버 = 각 5개씩
- 나머지가 있으면 앞 서버부터 1개씩 추가 배정

**출력**: `results/server0/`, `results/server1/`, ...

---

#### 데이터 선택 옵션

```bash
# 데이터셋 선택
--dataset {zeroday,vulnfix}
  zeroday  : Zero-day 취약점 데이터셋 (기본값)
  vulnfix  : VulnFix 데이터셋

# 케이스 수 제한
--limit N
  처리할 최대 케이스 수
  예: --limit 10  # 10개만 처리

# 시작 오프셋
--offset N
  건너뛸 케이스 수 (기본값: 0)
  예: --offset 5 --limit 10  # 5번째부터 10개 처리
```

**예시**:
```bash
# 처음 10개 케이스
python3 scripts/run_experiment.py --dataset zeroday --limit 10

# 11번째부터 20개 케이스
python3 scripts/run_experiment.py --dataset zeroday --offset 10 --limit 20
```

---

#### 실험 설정 옵션

```bash
# 모델 선택
--models MODEL [MODEL ...]
  실험할 모델 리스트 (기본값: 16개 모델 전체)

  전체 실험 대상 모델 (16개):
  - qwen3:14b, qwen3:8b, qwen3:4b, qwen3:1.7b, qwen3:0.6b
  - gemma3:12b, gemma3:4b, gemma3:1b, gemma3:270m
  - deepseek-r1:14b, deepseek-r1:8b, deepseek-r1:7b, deepseek-r1:1.5b
  - llama3.2:3b, llama3.2:1b
  - gpt-oss:20b

  모델 이름 형식:
  - 기본: qwen3:14b, gemma3:12b, deepseek-r1:7b
  - provider(ollama)는 자동 설정됨

  예시:
  --models qwen3:14b gemma3:12b
  --models llama3.2:3b deepseek-r1:7b

# 조건 선택
--conditions {c1,c2,c3,c4} [...]
  실험할 조건 (기본값: c1 c2 c3 c4)

  조건 설명:
  c1 : Baseline (post-hoc, 형식 명세 없음)
  c2 : Vague hints (비형식 힌트)
  c3 : Pre-hoc (E_bug 있음, 검증 없음)
  c4 : Full PatchScribe (E_bug + 삼중 검증)

  예시:
  --conditions c4              # Full만
  --conditions c1 c4           # Baseline vs Full
  --conditions c1 c2 c3 c4     # 전체 ablation study

# RQ2 불완전 패치 생성 제어
--skip-incomplete-patches
  불완전 패치 생성을 건너뜁니다 (RQ2 평가 불필요 시)
```

**조합 예시**:
```bash
# C4만, 특정 모델 2개
python3 scripts/run_experiment.py --dataset zeroday --limit 10 \
    --models qwen3:14b gemma3:12b \
    --conditions c4

# Ablation study: C1-C4 전체, 16개 모델 전체
python3 scripts/run_experiment.py --dataset zeroday --limit 10 \
    --conditions c1 c2 c3 c4

# 소형 모델만 테스트
python3 scripts/run_experiment.py --dataset zeroday --limit 10 \
    --models qwen3:1.7b gemma3:1b llama3.2:1b \
    --conditions c4

# RQ2 제외, C4만
python3 scripts/run_experiment.py --dataset zeroday --limit 10 \
    --conditions c4 \
    --skip-incomplete-patches
```

---

#### GPT Judge 배치 평가 옵션 (NEW!)

```bash
# 배치 모드 활성화 (향후 지원 예정)
--batch-judge
  GPT Judge 평가를 배치로 병렬 처리 (속도 향상)

# 배치 크기 설정
--batch-size N
  동시 요청 수 (기본값: 5)

  권장 값:
  5  : 안정적 (기본값)
  10 : 빠른 처리
  20 : 최대 속도 (rate limit 주의)
```

**현재**: GPT Judge는 자동으로 실행되지만 순차 처리됩니다.
**배치 평가**: 실험 후 별도 스크립트로 가능 (아래 참조)

---

#### 출력 옵션

```bash
# 출력 디렉토리 지정
--output DIR
  결과 저장 경로 (기본값: results/)

  예시:
  --output results/experiment_20250103

# 최소 출력 모드
-q, --quiet
  진행 상황 메시지 최소화
```

---

#### 📖 실험 스크립트 전체 예시

```bash
# 1. 빠른 테스트 (개발용)
python3 scripts/run_experiment.py --quick

# 2. 로컬 전체 실험 (논문용)
python3 scripts/run_experiment.py --dataset zeroday --limit 50 \
    --conditions c1 c2 c3 c4

# 3. 특정 모델 벤치마크
python3 scripts/run_experiment.py --dataset zeroday --limit 20 \
    --models llama3.2:3b qwen3:4b deepseek-r1:7b \
    --conditions c4

# 4. 분산 실험 (4대 서버, 100개 케이스)
# 각 서버에서:
python3 scripts/run_experiment.py --distributed 0 4 100 --dataset zeroday
python3 scripts/run_experiment.py --distributed 1 4 100 --dataset zeroday
python3 scripts/run_experiment.py --distributed 2 4 100 --dataset zeroday
python3 scripts/run_experiment.py --distributed 3 4 100 --dataset zeroday

# 5. Ablation study (C1→C4 성능 비교)
python3 scripts/run_experiment.py --dataset zeroday --limit 30 \
    --models qwen3:4b \
    --conditions c1 c2 c3 c4

# 6. 조용한 백그라운드 실행
nohup python3 scripts/run_experiment.py --dataset zeroday --limit 100 \
    --quiet > experiment.log 2>&1 &
```

---

### 📈 분석 스크립트 (`analyze.py`)

#### 기본 사용법

```bash
python3 scripts/analyze.py [경로...] [옵션]
```

#### 분석 모드

##### 1. **단일 파일 분석**

```bash
# 특정 결과 파일 분석
python3 scripts/analyze.py results/local/qwen3-4b/c4_results.json
```

**출력**:
- `c4_results_analysis.json` - RQ1-RQ4 상세 분석
- `c4_results_summary.md` - 마크다운 요약

---

##### 2. **디렉토리 분석** (기본)

```bash
# 기본: C4만 분석
python3 scripts/analyze.py results/local

# 모든 조건 분석 (C1-C4 ablation study)
python3 scripts/analyze.py results/local --all-conditions
```

**동작**:
- `--all-conditions` 없이: C4 결과만 분석 (빠름)
- `--all-conditions` 사용: C1, C2, C3, C4 전부 분석 (느림)

**출력**:
```
results/local/
├── qwen3-4b/
│   ├── c4_results.json
│   ├── c4_results_analysis.json    # ← 생성됨
│   └── c4_results_summary.md       # ← 생성됨
├── llama3.2-3b/
│   ├── c4_results_analysis.json
│   └── c4_results_summary.md
└── comparison/                      # ← 자동 생성 (모델이 2개 이상일 때)
    ├── model_comparison.json
    └── model_comparison.md
```

---

##### 3. **분산 결과 병합** (`--merge`)

여러 서버의 결과를 병합한 후 분석

```bash
# 모든 서버 결과 병합
python3 scripts/analyze.py --merge results/server*

# 특정 서버만 병합
python3 scripts/analyze.py --merge results/server0 results/server1
```

**동작**:
1. 각 서버의 `{condition}_server{N}_results.json` 파일 찾기
2. 같은 모델 + 조건별로 병합
3. 병합된 결과를 `results/merged/` 저장
4. 통합 분석 수행

**출력**:
```
results/merged/
├── qwen3-4b/
│   ├── c4_merged.json              # ← 병합된 결과
│   ├── c4_merged_analysis.json     # ← 분석
│   └── c4_merged_summary.md
└── comparison/
    ├── model_comparison.json
    └── model_comparison.md
```

---

##### 4. **모델 비교** (`--compare`)

여러 모델의 성능을 비교

```bash
# 두 모델 비교
python3 scripts/analyze.py --compare results/model1 results/model2

# 세 모델 이상 비교
python3 scripts/analyze.py --compare results/model1 results/model2 results/model3
```

**출력**:
- `comparison/model_comparison.json` - 상세 비교 데이터
- `comparison/model_comparison.md` - 비교 테이블 및 요약

**비교 내용**:
- 성공률 (Success Rate)
- 삼중 검증 통과율 (Triple Verification)
- Ground Truth 유사도
- 설명 품질 점수 (LLM Judge)
- 성능 (시간, 메모리)

---

#### 필터 옵션

```bash
# 특정 모델만 분석
--models MODEL [MODEL ...]
  분석할 모델 필터링

  예시:
  --models qwen3-4b deepseek-r1-7b

  사용 시나리오:
  - 여러 모델 결과가 있지만 일부만 분석하고 싶을 때
  - 특정 모델 결과만 비교하고 싶을 때

# 모든 조건 분석 (C1-C4)
--all-conditions
  C1, C2, C3, C4 전부 분석 (기본값: C4만)

  언제 사용:
  - Ablation study 수행 시
  - C1→C4 성능 향상 추세 분석 시
  - 논문 Figure/Table 생성 시
```

**필터 예시**:
```bash
# qwen3-4b와 deepseek-r1-7b만 분석
python3 scripts/analyze.py results/local --models qwen3-4b deepseek-r1-7b

# 모든 조건 분석하되 특정 모델만
python3 scripts/analyze.py results/local --all-conditions \
    --models qwen3-4b

# 병합 시 특정 모델만
python3 scripts/analyze.py --merge results/server* \
    --models llama3.2-3b qwen3-4b
```

---

#### 출력 옵션

```bash
# 출력 디렉토리 지정
-o, --output DIR
  분석 결과 저장 경로
  기본값: 입력 경로와 동일 위치

# 최소 출력 모드
-q, --quiet
  진행 상황 메시지 최소화

  사용 시나리오:
  - 자동화 스크립트에서 실행
  - 로그 파일로 리다이렉트
```

---

#### 📖 분석 스크립트 전체 예시

```bash
# 1. 단일 파일 분석
python3 scripts/analyze.py results/local/qwen3-4b/c4_results.json

# 2. 디렉토리 전체 분석 (C4만)
python3 scripts/analyze.py results/local

# 3. 모든 조건 분석 (Ablation study)
python3 scripts/analyze.py results/local --all-conditions

# 4. 분산 결과 병합 및 분석
python3 scripts/analyze.py --merge results/server*

# 5. 특정 모델만 분석
python3 scripts/analyze.py results/local --models qwen3-4b deepseek-r1-7b

# 6. 특정 모델 비교
python3 scripts/analyze.py --compare \
    results/local/qwen3-4b \
    results/local/llama3.2-3b

# 7. 병합 + 모든 조건 + 특정 모델
python3 scripts/analyze.py --merge results/server* \
    --all-conditions \
    --models qwen3-4b

# 8. 조용한 분석 (자동화용)
python3 scripts/analyze.py results/local --quiet > analysis.log 2>&1
```

---

### 🔍 배치 GPT Judge 평가 (`batch_judge.py`)

실험 후 GPT Judge 평가를 배치로 추가하거나 재실행

#### 기본 사용법

```bash
python3 scripts/batch_judge.py [경로] [옵션]
```

#### 사용 시나리오

GPT Judge 평가는 기본적으로 **자동 실행**되지만, 다음 경우 이 스크립트 사용:

1. **평가가 실패한 케이스 재시도**
2. **배치 모드로 빠르게 재평가** (순차 실행보다 5-10배 빠름)
3. **API 키 변경 후 재평가**
4. **Judge 모델 업그레이드 후 재평가**

---

#### 명령어 예시

```bash
# 1. 단일 결과 파일 배치 평가
python3 scripts/batch_judge.py results/local/qwen3-4b/c4_results.json

# 2. 디렉토리 내 모든 결과 파일 배치 평가
python3 scripts/batch_judge.py results/local/qwen3-4b/

# 3. 배치 크기 조정 (동시 요청 10개)
python3 scripts/batch_judge.py results/local/ --batch-size 10

# 4. Dry run (평가할 케이스만 확인, 실제 평가 안함)
python3 scripts/batch_judge.py results/local/ --dry-run

# 5. 조용한 모드
python3 scripts/batch_judge.py results/local/ --quiet
```

---

#### 옵션 설명

```bash
# 배치 크기 (동시 요청 수)
--batch-size N
  기본값: 5
  권장 범위: 5-20

  값에 따른 특성:
  5  : 안정적, 적당한 속도 (기본값)
  10 : 빠른 처리, OpenAI rate limit 여유 있음
  20 : 최대 속도, rate limit 주의 필요

# Dry run (시뮬레이션)
--dry-run
  실제 평가 없이 평가 대상 케이스만 확인

  사용 시나리오:
  - 얼마나 많은 케이스가 평가될지 확인
  - API 비용 예측

# 최소 출력
-q, --quiet
  진행 상황 메시지 숨김
```

---

#### 동작 원리

1. **평가 필요 케이스 탐지**:
   - 설명은 있지만 LLM 점수가 없는 케이스 찾기
   - `natural_llm` 또는 `natural_template` 존재
   - `llm_scores` 없음

2. **배치 평가 실행**:
   - gpt-5 judge로 병렬 평가
   - ThreadPoolExecutor 사용
   - 순서 보장 (index 기반)

3. **결과 업데이트**:
   - 원본 파일 백업 (`.json.backup`)
   - LLM 점수 추가
   - 메트릭 재계산

---

#### 성능 비교

| 케이스 수 | 순차 실행 | 배치 (5) | 배치 (10) | 속도 향상 |
|----------|----------|---------|-----------|----------|
| 10개     | ~60초    | ~12초   | ~6초      | 5-10배   |
| 50개     | ~300초   | ~60초   | ~30초     | 5-10배   |
| 100개    | ~600초   | ~120초  | ~60초     | 5-10배   |

**추천**: `--batch-size 10` (빠르면서 안정적)

---

#### 전체 예시

```bash
# 1. 평가 필요 여부 확인
python3 scripts/batch_judge.py results/local/ --dry-run

# 출력 예시:
# 📄 Processing: results/local/qwen3-4b/c4_results.json
#    Found 15 cases needing evaluation
#       - case_001
#       - case_002
#       ...

# 2. 배치 평가 실행
python3 scripts/batch_judge.py results/local/ --batch-size 10

# 출력 예시:
# 📄 Processing: results/local/qwen3-4b/c4_results.json
#    Found 15 cases needing evaluation
#    Building evaluation prompts...
#    Evaluating 15 cases (batch_size=10)...
#    Parsing responses and updating results...
#    Backing up to: c4_results.json.backup
#    ✅ Updated 15 cases

# 3. 업데이트된 결과 분석
python3 scripts/analyze.py results/local/
```

---

#### 환경 변수

```bash
# OpenAI API 키 (필수)
export OPENAI_API_KEY=sk-...

# Judge 타임아웃 (옵션, 기본값: 120초)
export PATCHSCRIBE_JUDGE_TIMEOUT=180
```

---

#### 주의사항

1. **백업 자동 생성**: 원본 파일은 `.json.backup`으로 자동 백업됩니다.

2. **OpenAI Rate Limit**:
   - Tier 2: 500 requests/min
   - `--batch-size 10-20` 권장
   - Rate limit 초과 시 `--batch-size` 줄이기

3. **비용**: gpt-5는 저렴하지만 대량 평가 시 비용 확인 필요

4. **실패 처리**: 개별 케이스 실패 시 경고만 출력, 계속 진행

---

### 📋 전체 워크플로우 예시

#### 시나리오 1: 로컬 실험 → 분석

```bash
# 1. 실험 실행 (자동으로 GPT Judge 평가 포함)
python3 scripts/run_experiment.py --dataset zeroday --limit 20 \
    --models qwen3:4b deepseek-r1:7b \
    --conditions c4

# 2. (옵션) 평가 실패 케이스 재시도 (배치 모드)
python3 scripts/batch_judge.py results/local/ --batch-size 10

# 3. 결과 분석
python3 scripts/analyze.py results/local/

# 4. 모델 비교 리포트 생성
python3 scripts/analyze.py --compare \
    results/local/qwen3-4b \
    results/local/deepseek-r1-7b
```

---

#### 시나리오 2: 분산 실험 → 병합 → 분석

```bash
# 각 서버에서 실행
# Server 0:
python3 scripts/run_experiment.py --distributed 0 4 100 --dataset zeroday

# Server 1:
python3 scripts/run_experiment.py --distributed 1 4 100 --dataset zeroday

# Server 2:
python3 scripts/run_experiment.py --distributed 2 4 100 --dataset zeroday

# Server 3:
python3 scripts/run_experiment.py --distributed 3 4 100 --dataset zeroday

# 중앙 서버에서:
# 1. 결과 수집 (scp 등 사용)
scp -r user@server0:~/patchscribe/results/server0 results/
scp -r user@server1:~/patchscribe/results/server1 results/
scp -r user@server2:~/patchscribe/results/server2 results/
scp -r user@server3:~/patchscribe/results/server3 results/

# 2. 병합 및 분석
python3 scripts/analyze.py --merge results/server*

# 3. 전체 조건 분석 (Ablation study)
python3 scripts/analyze.py results/merged/ --all-conditions

# 4. 특정 모델만 비교
python3 scripts/analyze.py results/merged/ \
    --models qwen3-4b llama3.2-3b \
    --compare
```

---

#### 시나리오 3: Ablation Study (C1→C4 성능 분석)

```bash
# 1. 전체 조건 실험
python3 scripts/run_experiment.py --dataset zeroday --limit 30 \
    --models qwen3:4b \
    --conditions c1 c2 c3 c4

# 2. 전체 조건 분석
python3 scripts/analyze.py results/local/ --all-conditions

# 결과:
# results/local/qwen3-4b/
# ├── c1_results_analysis.json  # Baseline 분석
# ├── c2_results_analysis.json  # Vague hints 분석
# ├── c3_results_analysis.json  # Pre-hoc 분석
# ├── c4_results_analysis.json  # Full PatchScribe 분석
# └── comparison/
#     ├── ablation_study.json   # C1→C4 비교
#     └── ablation_study.md     # 마크다운 요약
```

---

#### 시나리오 4: 빠른 개발 및 디버깅

```bash
# 1. 빠른 테스트 (3개 케이스)
python3 scripts/run_experiment.py --quick

# 2. 결과 확인
python3 scripts/analyze.py results/quick_test/

# 3. 문제 발견 시 단일 케이스 재실행
python3 run.py case_001
```

---

## 🔗 추가 참고 문서

- **[BATCH_JUDGE.md](doc/BATCH_JUDGE.md)** - 배치 GPT Judge 평가 상세 가이드
- **[QUICKSTART.md](doc/QUICKSTART.md)** - 빠른 시작 가이드
- **[DISTRIBUTED_GUIDE.md](doc/DISTRIBUTED_GUIDE.md)** - 분산 실행 가이드

---

## 📄 라이선스

이 프로젝트는 연구 목적으로 개발되었습니다.

---

## 📮 문의

프로젝트 관련 문의사항이나 버그 리포트는 이슈를 등록해주세요.
