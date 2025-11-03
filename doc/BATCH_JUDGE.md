# 배치 모드 GPT Judge 평가

## 개요

PatchScribe의 RQ4(설명 품질 평가)를 위한 GPT Judge 평가를 배치 모드로 수행하여 속도를 향상시킬 수 있습니다.

## 자동 평가 여부

**네, RQ4 GPT 평가는 자동으로 실행됩니다.**

`run_experiment.py`를 실행하면:
1. **패치 생성**: 로컬 LLM (ollama)
2. **설명 생성**: 로컬 LLM + 템플릿 (both 모드)
3. **RQ4 품질 평가**: GPT-4o-mini judge **자동 실행**

설정:
- [scripts/run_experiment.py:339](../scripts/run_experiment.py#L339): `explain_mode='both'`
- [patchscribe/pipeline.py:284](../patchscribe/pipeline.py#L284): `use_llm=True` 자동 설정
- [patchscribe/explanation_quality.py:48](../patchscribe/explanation_quality.py#L48): `use_llm=True`일 때 judge 자동 호출
- Judge는 **항상 GPT-4o-mini** 사용 (OpenAI API)

## 배치 모드 사용법

### 방법 1: 기존 결과 파일에 배치 평가 추가

실험을 먼저 실행한 후, 나중에 배치 모드로 평가를 추가할 수 있습니다:

```bash
# 1. LLM judge 평가 없이 실험 실행 (빠름)
python3 scripts/run_experiment.py --dataset zeroday --limit 10

# 2. 나중에 배치 모드로 평가 추가 (병렬 처리)
python3 scripts/batch_judge.py results/local/ --batch-size 10
```

### 방법 2: 배치 평가 유틸리티 직접 사용

```bash
# 단일 결과 파일 평가
python3 scripts/batch_judge.py results/local/llama3.2:3b/c4_results.json

# 디렉토리 내 모든 결과 파일 평가
python3 scripts/batch_judge.py results/local/llama3.2:3b/

# 배치 크기 조정 (동시 요청 수)
python3 scripts/batch_judge.py results/local/ --batch-size 10

# Dry run (평가할 케이스만 확인)
python3 scripts/batch_judge.py results/local/ --dry-run
```

## 배치 크기 설정

배치 크기는 동시 요청 수를 제어합니다:

- **기본값: 5** - 안정적이고 적당한 속도
- **10-20**: OpenAI API rate limit 내에서 빠른 처리
- **너무 크면**: Rate limit 초과 가능성

권장 설정:
```bash
# 안정적 (기본값)
--batch-size 5

# 빠른 처리 (OpenAI API가 안정적일 때)
--batch-size 10

# 최대 속도 (rate limit 주의)
--batch-size 20
```

## 구현 세부사항

### 1. Judge 아키텍처

- **생성 LLM**: 로컬 ollama (환경변수 `PATCHSCRIBE_LLM_MODEL`)
- **Judge LLM**: GPT-4o-mini (하드코딩, `OPENAI_API_KEY` 필요)

### 2. 배치 처리 구현

#### LLM Client 배치 메서드

[patchscribe/llm.py](../patchscribe/llm.py):

```python
@staticmethod
def batch_score_explanations(prompts: List[str], *, max_workers: int = 5) -> List[Optional[str]]:
    """Score multiple explanations in parallel using GPT-4o-mini judge."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # Create judge client once
    judge_config = LLMConfig.from_env(for_judge=True)
    judge_client = LLMClient(judge_config)

    # Execute in parallel with ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(score_single, i, prompt) for i, prompt in enumerate(prompts)]
        # Collect results as they complete
        for future in as_completed(futures):
            index, score = future.result()
            results[index] = score

    return results
```

#### 배치 평가 스크립트

[scripts/batch_judge.py](../scripts/batch_judge.py):

1. 결과 파일에서 평가가 필요한 케이스 찾기
2. 각 케이스에 대한 evaluation prompt 생성
3. `LLMClient.batch_score_explanations()`로 병렬 평가
4. 결과 파싱 및 업데이트
5. 메트릭 재계산

### 3. 평가 기준

GPT-4o-mini judge는 다음 3가지 차원을 1-5 스케일로 평가:

- **Accuracy** (정확도): 설명이 기술적으로 정확한가?
- **Clarity** (명확성): 설명이 이해하기 쉬운가?
- **Causality** (인과성): 취약점의 원인과 패치의 효과를 설명하는가?

응답 형식:
```json
{
  "accuracy": 4.5,
  "clarity": 4.0,
  "causality": 4.8,
  "reason": "Clear explanation with good causal chain"
}
```

## 환경 변수 설정

```bash
# 패치 생성용 로컬 LLM
export PATCHSCRIBE_LLM_PROVIDER=ollama
export PATCHSCRIBE_LLM_MODEL=llama3.2:3b
export PATCHSCRIBE_LLM_ENDPOINT=http://localhost:11434/api/chat

# Judge용 OpenAI API
export OPENAI_API_KEY=sk-...

# Judge 타임아웃 (옵션)
export PATCHSCRIBE_JUDGE_TIMEOUT=120
```

## 성능 비교

### 순차 평가 (기본)
- 10개 케이스: ~60초 (케이스당 ~6초)
- 100개 케이스: ~600초 (10분)

### 배치 평가 (batch_size=5)
- 10개 케이스: ~12초 (5개씩 병렬)
- 100개 케이스: ~120초 (2분)

**속도 향상: 약 5배**

### 배치 평가 (batch_size=10)
- 10개 케이스: ~6초 (한 번에 처리)
- 100개 케이스: ~60초 (1분)

**속도 향상: 약 10배**

## 주의사항

### 1. OpenAI API Rate Limit

배치 크기가 너무 크면 rate limit에 걸릴 수 있습니다:

```
Rate limit: 500 requests/min (tier 2)
Recommended batch_size: 10-20
```

### 2. 백업 생성

배치 평가는 자동으로 백업을 생성합니다:

```
results/local/llama3.2:3b/c4_results.json
results/local/llama3.2:3b/c4_results.json.backup
```

### 3. 메트릭 재계산

배치 평가 후 메트릭이 자동으로 재계산됩니다:
- `avg_llm_accuracy`
- `avg_llm_clarity`
- `avg_llm_causality`

## 문제 해결

### Judge가 실행되지 않는 경우

```bash
# 1. OpenAI API 키 확인
echo $OPENAI_API_KEY

# 2. 네트워크 연결 확인
curl https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"

# 3. 로그 확인
python3 scripts/batch_judge.py results/local/ --batch-size 1
```

### Rate Limit 에러

```bash
# 배치 크기 줄이기
python3 scripts/batch_judge.py results/local/ --batch-size 3

# 또는 순차 실행
python3 scripts/batch_judge.py results/local/ --batch-size 1
```

### 특정 케이스만 실패

```bash
# Dry run으로 문제 케이스 확인
python3 scripts/batch_judge.py results/local/ --dry-run

# 개별 파일 평가
python3 scripts/batch_judge.py results/local/llama3.2:3b/c4_results.json
```

## 다음 단계

배치 평가 후:

```bash
# 1. 결과 분석
python3 scripts/analyze.py results/local/

# 2. RQ4 메트릭 확인
python3 scripts/analyze.py results/local/ --rq rq4

# 3. 모델 비교
python3 scripts/analyze.py results/local/ --compare
```

## 참고

- [RQ4 평가 방법론](../doc/paper/patchscribe.tex#L1380-L1436)
- [Judge 구현](../patchscribe/llm.py#L180-L250)
- [배치 스크립트](../scripts/batch_judge.py)
