# LLM 속도 벤치마크 가이드

## 개요

`benchmark_llm_speed.py`는 **로컬 Ollama**와 **원격 Ollama** (동일 모델) 간의 성능을 비교하는 스크립트입니다.

## 테스트 설정

- **로컬 Ollama**: `http://127.0.0.1:11434/api/generate`
- **원격 Ollama**: `http://115.145.178.10:11434/api/generate`
- **기본 모델**: `deepseek-r1:1.5b`
- **기본 요청 횟수**: 10회

## 사전 준비

### 1. 로컬 Ollama 설정

```bash
# Ollama 서버 시작
ollama serve

# 모델 다운로드 (새 터미널에서)
ollama pull deepseek-r1:1.5b

# 모델 확인
ollama list
```

### 2. 원격 Ollama 접근 확인

```bash
# 테스트 요청
curl -X POST http://115.145.178.10:11434/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-r1:1.5b",
    "prompt": "test",
    "stream": false
  }'
```

## 실행 방법

### 기본 실행 (둘 다 테스트)

```bash
python scripts/benchmark_llm_speed.py
```

### 요청 횟수 변경

```bash
# 20번씩 요청
python scripts/benchmark_llm_speed.py --num-requests 20

# 50번씩 요청 (더 정확한 통계)
python scripts/benchmark_llm_speed.py -n 50
```

### 다른 모델 테스트

```bash
# Llama 3.2 1B 모델로 테스트
python scripts/benchmark_llm_speed.py --model llama3.2:1b

# Qwen 모델로 테스트
python scripts/benchmark_llm_speed.py --model qwen3:0.6b
```

### 부분 테스트

```bash
# 로컬만 테스트
python scripts/benchmark_llm_speed.py --only-local

# 원격만 테스트
python scripts/benchmark_llm_speed.py --only-remote
```

## 출력 결과 해석

### 개별 벤치마크 결과

```
============================================================
벤치마킹: 로컬 Ollama - deepseek-r1:1.5b
============================================================
엔드포인트: http://127.0.0.1:11434/api/generate

10번의 요청을 보내는 중...

  요청 # 1: 0.85초 - 응답 길이: 156자
  요청 # 2: 0.72초 - 응답 길이: 142자
  ...

────────────────────────────────────────────────────────────
📊 결과 요약:
────────────────────────────────────────────────────────────
  성공률:        100.0% (10/10)
  총 소요 시간:  8.45초
  평균 응답 시간: 0.85초
  최소 응답 시간: 0.72초
  최대 응답 시간: 1.02초
```

### 최종 비교 결과

```
======================================================================
🏁 최종 비교 - deepseek-r1:1.5b
======================================================================

항목                  로컬 Ollama               원격 Ollama               차이           
─────────────────────────────────────────────────────────────────────────────────────
엔드포인트            127.0.0.1:11434          115.145.178.10:11434
성공률                100.0%                   100.0%                   0.0%p
평균 응답 시간         0.85초                   1.23초                   0.38초
총 소요 시간          8.45초                   12.30초                  3.85초
최소 응답 시간         0.72초                   1.10초                   0.38초
최대 응답 시간         1.02초                   1.45초                   0.43초

======================================================================
📊 성능 분석
======================================================================
⚡ 로컬 Ollama가 원격보다 1.45배 빠릅니다!
   (요청당 평균 0.38초 절약)

📈 처리량 (초당 요청 수):
   로컬 Ollama:  1.183 req/s
   원격 Ollama:  0.813 req/s

🌐 네트워크 오버헤드 추정:
   평균 왕복 시간 차이: 0.38초

📉 응답 시간 안정성 (표준편차):
   로컬 Ollama:  0.09초
   원격 Ollama:  0.12초
   → 로컬이 1.33배 더 안정적입니다
```

## 성능 지표 설명

- **평균 응답 시간**: 각 요청의 평균 소요 시간
- **총 소요 시간**: 모든 요청의 총 시간 (순차 실행)
- **처리량 (req/s)**: 초당 처리 가능한 요청 수
- **네트워크 오버헤드**: 로컬과 원격 간의 시간 차이 (주로 네트워크 왕복 시간)
- **표준편차**: 응답 시간의 일관성 (낮을수록 안정적)

## 활용 예시

### 1. 다양한 모델 크기 비교

```bash
# 작은 모델
python scripts/benchmark_llm_speed.py --model qwen3:0.6b -n 20

# 중간 모델
python scripts/benchmark_llm_speed.py --model deepseek-r1:1.5b -n 20

# 큰 모델
python scripts/benchmark_llm_speed.py --model llama3.2:3b -n 20
```

### 2. 네트워크 부하에 따른 성능 변화

```bash
# 낮은 부하 (10회)
python scripts/benchmark_llm_speed.py -n 10

# 중간 부하 (50회)
python scripts/benchmark_llm_speed.py -n 50

# 높은 부하 (100회)
python scripts/benchmark_llm_speed.py -n 100
```

## 문제 해결

### 로컬 Ollama 연결 실패

```bash
# Ollama가 실행 중인지 확인
ps aux | grep ollama

# Ollama 재시작
killall ollama
ollama serve
```

### 원격 Ollama 연결 실패

```bash
# 네트워크 연결 확인
ping 115.145.178.10

# 포트 확인
nc -zv 115.145.178.10 11434

# 방화벽 설정 확인 (필요시)
```

### 모델 없음 오류

```bash
# 모델 다운로드
ollama pull deepseek-r1:1.5b

# 사용 가능한 모델 확인
ollama list
```

## 추가 옵션

```bash
# 도움말 보기
python scripts/benchmark_llm_speed.py --help

# 커스텀 엔드포인트 사용
python scripts/benchmark_llm_speed.py \
  --local-endpoint http://localhost:11434/api/generate \
  --remote-endpoint http://your-server:11434/api/generate
```
