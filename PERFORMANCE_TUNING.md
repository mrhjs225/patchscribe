# PatchScribe 성능 튜닝 가이드

## ⚠️ 중요: Ollama 병목 현상

병렬 실행 시 단일 Ollama 인스턴스가 병목이 됩니다.

### 증상
- `ReadTimeoutError: Read timed out` 경고 메시지 다수 발생
- 재시도(Retry) 빈번하게 발생
- 케이스 처리 시간이 예상보다 길어짐
- Success rate가 0%로 나타남

### 해결 방법 1: Ollama 동시 실행 제한 조정

Ollama의 동시 요청 수를 늘리세요:

```bash
# Ollama 환경 변수 설정
export OLLAMA_NUM_PARALLEL=4  # 기본값: 1
export OLLAMA_MAX_LOADED_MODELS=2  # 동시 로드 모델 수

# Ollama 재시작
systemctl restart ollama  # 또는 ollama serve
```

### 해결 방법 2: 여러 Ollama 인스턴스 실행

다른 포트로 여러 인스턴스를 실행:

```bash
# 인스턴스 1 (기본)
OLLAMA_HOST=0.0.0.0:11434 ollama serve &

# 인스턴스 2
OLLAMA_HOST=0.0.0.0:11435 ollama serve &

# 각 모델에 다른 엔드포인트 지정
python scripts/run_full_evaluation.py zeroday \
    --llm-endpoint http://127.0.0.1:11434/api/chat \
    --llm-model llama3.2:1b
```

### 해결 방법 3: 병렬도 조정 ⭐ **권장**

#### A. 모델 레벨: 순차 실행
```bash
# --parallel 플래그 제거
python scripts/run_multi_model_evaluation.py zeroday \
    --models "llama3.2:1b" "deepseek-r1:1.5b"
```

#### B. 케이스 레벨: 워커 수 감소 (권장)
커맨드라인에서 직접 지정:

```bash
# 4개 워커로 실행
python scripts/run_full_evaluation.py zeroday \
    --max-workers 4 \
    --llm-model "llama3.2:1b"

# 순차 실행 (디버깅용)
python scripts/run_full_evaluation.py zeroday \
    --max-workers 1 \
    --llm-model "llama3.2:1b"
```

### 해결 방법 4: 타임아웃 증가

```bash
export PATCHSCRIBE_LLM_TIMEOUT=180  # 기본 60초 → 180초

python scripts/run_multi_model_evaluation.py zeroday \
    --models "llama3.2:1b" "deepseek-r1:1.5b" \
    --parallel
```

## 권장 설정

### 단일 Ollama 인스턴스 (현재 상황에 적합) ⭐

```bash
# 방법 1: 순차 모델 실행 + 케이스 병렬도 감소
python scripts/run_multi_model_evaluation.py zeroday \
    --models "llama3.2:1b" "deepseek-r1:1.5b" \
    --limit 10

# 각 run_full_evaluation.py 실행 시 자동으로 --max-workers 4 적용되도록 수정
```

**즉시 적용 가능한 명령어:**
```bash
# Ollama 설정 증가
export OLLAMA_NUM_PARALLEL=8
export OLLAMA_MAX_LOADED_MODELS=2
systemctl restart ollama  # 또는 ollama를 재시작

# 워커 수 4로 제한하여 실행
python scripts/run_full_evaluation.py zeroday \
    --max-workers 4 \
    --limit 10 \
    --llm-model "llama3.2:1b"
```

### 여러 Ollama 인스턴스 (권장)
```bash
# Ollama 설정
export OLLAMA_NUM_PARALLEL=8
export OLLAMA_MAX_LOADED_MODELS=4

# 병렬 모델 + 병렬 케이스
python scripts/run_multi_model_evaluation.py zeroday \
    --models "llama3.2:1b" "deepseek-r1:1.5b" \
    --parallel \
    --max-parallel-models 2
```

## 성능 모니터링

### Ollama 상태 확인
```bash
# Ollama 로그 확인
journalctl -u ollama -f

# GPU 사용률 확인 (CUDA)
nvidia-smi -l 1

# CPU/메모리 사용률
htop
```

### 병목 지점 파악
1. **Ollama가 100% 사용 중**: 동시 실행 제한 증가 필요
2. **GPU 메모리 부족**: 모델 수 감소 또는 작은 모델 사용
3. **CPU 병목**: max_workers 감소
4. **네트워크 타임아웃**: 타임아웃 증가 또는 로컬 요청 최적화
