# PatchScribe 문제 해결 가이드

본 문서는 PatchScribe 실행 시 발생하는 일반적인 오류와 해결 방법을 설명합니다.

---

## 목차
1. [Import 오류](#1-import-오류)
2. [LLM API 오류](#2-llm-api-오류)
3. [LLVM/Clang 오류](#3-llvmclang-오류)
4. [캐시 관련 오류](#4-캐시-관련-오류)
5. [성능 관련 문제](#5-성능-관련-문제)

---

## 1. Import 오류

### ❌ 오류: `cannot import name 'Evaluator' from 'patchscribe.evaluation'`

**증상:**
```
ImportError: cannot import name 'Evaluator' from 'patchscribe.evaluation'
```

**원인:**
- `patchscribe/evaluation.py` (파일)과 `patchscribe/evaluation/` (디렉토리)가 충돌
- `evaluation/__init__.py`가 `Evaluator`를 export하지 않음

**해결 방법 (이미 적용됨):**

```bash
# evaluation.py 파일을 evaluation/evaluator.py로 이동
mv patchscribe/evaluation.py patchscribe/evaluation/evaluator.py

# evaluation/__init__.py 수정하여 Evaluator export
# (이미 수정됨)
```

**검증:**
```bash
python3 -c "from patchscribe.evaluation import Evaluator; print('✓ OK')"
```

### ❌ 오류: `ModuleNotFoundError: No module named 'patchscribe'`

**증상:**
```
ModuleNotFoundError: No module named 'patchscribe'
```

**원인:**
- 프로젝트 루트 디렉토리가 Python path에 없음

**해결 방법:**

```bash
# 방법 1: 프로젝트 루트에서 실행
cd /home/selab0228/research/patchscribe
python3 scripts/run_experiment.py --quick

# 방법 2: PYTHONPATH 설정
export PYTHONPATH=/home/selab0228/research/patchscribe:$PYTHONPATH
python3 scripts/run_experiment.py --quick

# 방법 3: 패키지 설치 (개발 모드)
pip install -e .
```

---

## 2. LLM API 오류

### ❌ 오류: `API key not found`

**증상:**
```
Error: OPENAI_API_KEY not set
Error: ANTHROPIC_API_KEY not set
```

**해결 방법:**

```bash
# 환경 변수 설정
export OPENAI_API_KEY="your-key-here"
export ANTHROPIC_API_KEY="your-key-here"
export GEMINI_API_KEY="your-key-here"

# 또는 .env 파일 생성
cat > .env << EOF
OPENAI_API_KEY=your-key
ANTHROPIC_API_KEY=your-key
GEMINI_API_KEY=your-key
EOF
```

### ❌ 오류: `Rate limit exceeded`

**증상:**
```
Error: Rate limit exceeded for model gpt-4.1-mini
```

**해결 방법:**

```bash
# 1. 동시성 감소
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --llm-concurrency 10  # 100 → 10으로 감소

# 2. Retry 횟수 증가
export PATCHSCRIBE_LLM_MAX_RETRIES=5

# 3. Timeout 증가
export PATCHSCRIBE_LLM_TIMEOUT=120  # 120초
```

### ❌ 오류: `LLM timeout`

**증상:**
```
Error: LLM request timed out after 60s
```

**해결 방법:**

```bash
# Timeout 증가
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --llm-timeout 120  # 기본 60초 → 120초
```

---

## 3. LLVM/Clang 오류

### ❌ 오류: `LLVM slicer not available`

**증상:**
```
[WARN] LLVM backward slicing unavailable, falling back to heuristics
```

**원인:**
- LLVM/Clang이 설치되지 않음
- LLVM 경로가 설정되지 않음

**해결 방법:**

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install llvm-14 clang-14 llvm-14-dev

# 환경 변수 설정
export LLVM_CONFIG=/usr/bin/llvm-config-14
export PATH=/usr/lib/llvm-14/bin:$PATH

# 확인
which llvm-config
which clang

# Heuristic 모드로 실행 (정확도 낮음)
export PATCHSCRIBE_ALLOW_HEURISTICS=1
python3 scripts/run_experiment.py --dataset zeroday
```

### ❌ 오류: `Cannot compile C source`

**증상:**
```
Error: Failed to compile source code for analysis
```

**해결 방법:**

```bash
# 필수 컴파일러 도구 설치
sudo apt-get install build-essential

# Clang 컴파일러 확인
clang --version
```

---

## 4. 캐시 관련 오류

### ❌ 오류: `Cache corruption detected`

**증상:**
```
Error: Failed to load Stage-1 cache
```

**해결 방법:**

```bash
# 캐시 초기화
rm -rf .patchscribe_cache/

# 캐시 강제 재계산
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --refresh-stage1-cache

# 또는 캐시 비활성화
export PATCHSCRIBE_STAGE1_CACHE=disable
python3 scripts/run_experiment.py --dataset zeroday
```

### ❌ 오류: `Permission denied` (캐시 디렉토리)

**증상:**
```
PermissionError: [Errno 13] Permission denied: '.patchscribe_cache/stage1/...'
```

**해결 방법:**

```bash
# 권한 수정
chmod -R 755 .patchscribe_cache/

# 또는 다른 위치 사용
export PATCHSCRIBE_STAGE1_CACHE=/tmp/patchscribe_cache
python3 scripts/run_experiment.py --dataset zeroday
```

---

## 5. 성능 관련 문제

### ❌ 문제: 너무 느림

**증상:**
- 97개 케이스 처리에 3시간 이상 소요

**해결 방법:**

```bash
# 1. Stage-1 캐시 사용
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --precompute-stage1  # 먼저 캐시 생성

# 이후 실험에서 캐시 재사용 (빠름)
python3 scripts/run_experiment.py --dataset zeroday

# 2. LLM 동시성 증가
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --llm-concurrency 200  # 기본값보다 높게

# 3. 조건 병렬 실행
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --parallel-conditions  # C1-C4 동시 실행

# 4. 빠른 모델 사용
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --llm-provider openai \
  --models gpt-5-mini  # GPT-4보다 빠름
```

### ❌ 문제: 메모리 부족 (Out of Memory)

**증상:**
```
MemoryError: Unable to allocate array
```

**해결 방법:**

```bash
# 1. 동시성 감소
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --llm-concurrency 20  # 메모리 사용량 감소

# 2. 배치 크기 제한
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --limit 10  # 한 번에 10개씩만 처리

# 3. 순차 처리
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --llm-concurrency 1  # 완전 순차
```

---

## 6. 데이터셋 오류

### ❌ 오류: `Dataset not found`

**증상:**
```
Error: Dataset 'zeroday' not found
```

**해결 방법:**

```bash
# 데이터셋 위치 확인
ls -la datasets/

# Zero-Day 데이터셋 확인
ls -la datasets/zeroday_repair/

# ExtractFix 데이터셋 확인
ls -la datasets/extractfix_dataset/

# 사용 가능한 데이터셋 확인
python3 -c "
from patchscribe.dataset import list_available_datasets
print(list_available_datasets())
"
```

### ❌ 오류: `Invalid case format`

**증상:**
```
KeyError: 'source' not found in case
```

**원인:**
- 데이터셋 JSON 형식이 잘못됨

**해결 방법:**

```bash
# 데이터셋 JSON 검증
python3 -c "
import json
from pathlib import Path

# Zero-Day 케이스 확인
case_files = list(Path('datasets/zeroday_repair/').glob('*.json'))
for f in case_files[:3]:
    with open(f) as fp:
        case = json.load(fp)
        print(f'{f.name}: ✓' if 'source' in case else f'{f.name}: ✗ Missing source')
"
```

---

## 7. Z3 SMT Solver 오류

### ❌ 오류: `Z3 solver timeout`

**증상:**
```
[WARN] Z3 solver timed out, falling back to heuristics
```

**해결 방법:**

```bash
# 1. Timeout 증가
export PATCHSCRIBE_SMT_TIMEOUT=60000  # 60초 (기본 30초)

# 2. Z3 비활성화 (heuristic으로 폴백)
pip uninstall z3-solver

# 3. Z3 재설치
pip install --upgrade z3-solver
```

---

## 8. 실험 결과 오류

### ❌ 오류: `No results found`

**증상:**
```
Error: No evaluation results found in results/my_experiment
```

**원인:**
- 실험이 제대로 완료되지 않음
- 출력 디렉토리 경로가 잘못됨

**해결 방법:**

```bash
# 1. 출력 디렉토리 확인
ls -la results/

# 2. 실험 재실행 (verbose 모드)
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --limit 3 \
  --verbose

# 3. 로그 확인
tail -100 results/my_experiment/run.log
```

### ❌ 오류: `Evaluation failed`

**증상:**
```
Error: evaluate_results.py failed to process results
```

**해결 방법:**

```bash
# 1. 결과 파일 형식 확인
python3 -c "
import json
from pathlib import Path

results_dir = Path('results/my_experiment/gpt-4.1-mini/c4/')
for f in results_dir.glob('*.json'):
    try:
        with open(f) as fp:
            data = json.load(fp)
        print(f'{f.name}: ✓')
    except json.JSONDecodeError as e:
        print(f'{f.name}: ✗ {e}')
"

# 2. 평가 재실행 (verbose)
python3 scripts/evaluate_results.py \
  results/my_experiment \
  --verbose

# 3. 개별 케이스만 평가
python3 scripts/evaluate_results.py \
  results/my_experiment \
  --case-id CVE-2024-12345
```

---

## 9. 일반적인 디버깅 팁

### 디버깅 모드 활성화

```bash
# Verbose 출력
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --limit 3 \
  --verbose

# Python 디버거 사용
python3 -m pdb scripts/run_experiment.py --quick

# 로그 레벨 조정
export PATCHSCRIBE_LOG_LEVEL=DEBUG
python3 scripts/run_experiment.py --dataset zeroday
```

### 특정 케이스만 테스트

```bash
# 단일 케이스 실행
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --case-ids CVE-2024-12345

# 처음 3개 케이스만
python3 scripts/run_experiment.py \
  --dataset zeroday \
  --limit 3
```

### 실패한 케이스 재시도

```bash
# 실패한 케이스 목록 추출
python3 -c "
import json
from pathlib import Path

results = Path('results/my_experiment/gpt-4.1-mini/c4/')
failed = []
for f in results.glob('*.json'):
    with open(f) as fp:
        data = json.load(fp)
        if not data.get('success', True):
            failed.append(f.stem)

print('Failed cases:', ', '.join(failed))
"

# 실패한 케이스만 재실행
python3 scripts/retry_failures.py results/my_experiment
```

---

## 10. 환경 변수 참조

PatchScribe에서 사용하는 환경 변수 전체 목록:

| 환경 변수 | 기본값 | 설명 |
|----------|--------|------|
| `OPENAI_API_KEY` | (필수) | OpenAI API 키 |
| `ANTHROPIC_API_KEY` | (필수) | Anthropic API 키 |
| `GEMINI_API_KEY` | (필수) | Google Gemini API 키 |
| `PATCHSCRIBE_STAGE1_CACHE` | `.patchscribe_cache/stage1` | Stage-1 캐시 디렉토리 |
| `PATCHSCRIBE_ALLOW_HEURISTICS` | `0` | LLVM 없이 heuristic 사용 (`1`로 설정) |
| `PATCHSCRIBE_SMT_TIMEOUT` | `30000` | Z3 solver timeout (ms) |
| `PATCHSCRIBE_LLM_TIMEOUT` | `60` | LLM API timeout (초) |
| `PATCHSCRIBE_LLM_MAX_RETRIES` | `3` | LLM API 재시도 횟수 |
| `PATCHSCRIBE_LLM_PROVIDER` | `openai` | LLM 제공자 (`openai`, `anthropic`, `gemini`) |
| `PATCHSCRIBE_LLM_MODEL` | (provider별 기본값) | 사용할 모델 |
| `PATCHSCRIBE_LLM_ENDPOINT` | (provider별 기본값) | API 엔드포인트 |
| `PATCHSCRIBE_LLM_MAX_TOKENS` | `2048` | LLM 최대 토큰 수 |
| `PATCHSCRIBE_LOG_LEVEL` | `INFO` | 로그 레벨 (`DEBUG`, `INFO`, `WARN`, `ERROR`) |

---

## 11. 추가 도움말

### 도움말 확인

```bash
# 실험 스크립트 도움말
python3 scripts/run_experiment.py --help

# 평가 스크립트 도움말
python3 scripts/evaluate_results.py --help

# 분석 스크립트 도움말
python3 scripts/analyze.py --help
```

### 커뮤니티 지원

문제가 해결되지 않으면:

1. **이슈 확인**: GitHub Issues에서 유사한 문제 검색
2. **로그 첨부**: 에러 메시지와 실행 로그를 포함하여 이슈 생성
3. **환경 정보**: Python 버전, OS, LLVM 버전 등 포함

---

**마지막 업데이트**: 2025-11-20
