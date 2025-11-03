# PatchScribe

**Theory-Guided Vulnerability Repair Framework with Dual Causal Explanations**

PatchScribe는 형식적 인과 이론(formal causality theory)을 활용하여 취약점을 자동으로 수정하고, 이중 인과 설명(E_bug ↔ E_patch)을 통해 검증하는 프레임워크입니다.

---

## 🚀 빠른 시작

### 1️⃣ 환경 설정

```bash
# Python 3.8 이상 필요
python3 --version

# LLM 설정 (로컬 모델 사용 시)
export PATCHSCRIBE_LLM_PROVIDER=ollama
export PATCHSCRIBE_LLM_MODEL=llama3.2:1b

# Ollama 시작 및 모델 다운로드
ollama serve  # 별도 터미널에서
ollama pull llama3.2:1b
```

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

### RQ1: Theory-Guided Generation Effectiveness
**질문**: 사전 형식 명세(E_bug)가 더 정확한 패치를 생성하는가?

**측정 지표**:
- Triple verification rate (삼중 검증 통과율)
- Ground truth similarity (실제 패치 유사도)
- First attempt success rate (첫 시도 성공률)

### RQ2: Dual Verification Effectiveness
**질문**: 이중 설명(E_bug ↔ E_patch) + 일관성 검증이 불완전 패치를 탐지하는가?

**측정 지표**:
- Incomplete patches caught (불완전 패치 탐지 수)
- Consistency violation breakdown (일관성 위반 유형)

### RQ3: Scalability and Performance
**질문**: 3단계 워크플로우의 시간 오버헤드는?

**측정 지표**:
- Phase 1/2/3 time (단계별 시간)
- Total time (목표: <3분)
- Peak memory usage

### RQ4: Explanation Quality
**질문**: 이중 설명이 개발자에게 유용한 인사이트를 제공하는가?

**측정 지표**:
- Checklist coverage (자동)
- Expert quality scores (GPT 기반)

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

| 조건 | 설명 | 예상 성공률 |
|------|------|------------|
| **C1** (Baseline) | Post-hoc, no formal guidance | ~30% |
| **C2** (Vague Hints) | Informal prompts | ~40% |
| **C3** (Pre-hoc) | E_bug without verification | ~50% |
| **C4** (Full) | E_bug + triple verification | ~70% |

---

## 💡 핵심 명령어

### 실험
```bash
# 빠른 테스트
python3 scripts/run_experiment.py --quick

# 전체 실험
python3 scripts/run_experiment.py --dataset zeroday --limit 10

# 특정 모델만 (짧은 이름 - 간편!)
python3 scripts/run_experiment.py --dataset zeroday --limit 10 \
    --models gpt-oss-20b qwen3-4b

# 특정 모델 + 조건
python3 scripts/run_experiment.py --dataset zeroday --limit 10 \
    --models llama3.2:1b --conditions c4
```

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

## 🔧 고급 옵션

### 실험 스크립트 옵션

```bash
python3 scripts/run_experiment.py --help

주요 옵션:
  --quick                  빠른 테스트 (3개 케이스, C4만)
  --distributed ID N TOTAL  분산 실험 모드
  --dataset {zeroday,vulnfix}
  --limit N                처리할 케이스 수
  --models MODEL [MODEL ...]
  --conditions {c1,c2,c3,c4} [...]
  --skip-incomplete-patches  RQ2 패치 생성 건너뛰기
  --output DIR             출력 디렉토리
```

### 분석 스크립트 옵션

```bash
python3 scripts/analyze.py --help

주요 옵션:
  --merge                  분산 결과 병합
  --compare                다중 모델 비교
  -o, --output DIR         출력 디렉토리
  -q, --quiet              최소 출력
```

---

## 📄 라이선스

이 프로젝트는 연구 목적으로 개발되었습니다.

---

## 📮 문의

프로젝트 관련 문의사항이나 버그 리포트는 이슈를 등록해주세요.
