# PatchScribe PoC

PatchScribe는 취약점에 대한 인과적 설명을 구축하고, LLM 기반 패치 생성을 안내하며, 
형식적 설명과 자연어 설명을 모두 생성하는 개념 증명(Proof-of-Concept) 파이프라인입니다. 
현재 저장소는 APPATCH 데이터셋(`zeroday_repair` 하위 집합에 중점)에 대해 파이프라인을 
실행하고 수동 검사를 위한 결과를 수집하는 데 중점을 두고 있습니다.

## 프로젝트 구조

```
.
├── patchscribe/
│   ├── analysis/              # 휴리스틱 정적/동적/기호 분석기
│   ├── tools/                 # 선택적 래퍼 (clang, angr)
│   ├── dataset.py             # poc/zeroday 데이터셋 로더
│   ├── pipeline.py            # 엔드투엔드 오케스트레이션
│   ├── patch.py               # LLM 가이드 패치 합성 (formal/natural/minimal)
│   ├── verification.py        # 기호/모델/퍼징 검증 (KLEE/CBMC/LibFuzzer + 휴리스틱 폴백)
│   ├── explanation.py         # 형식적 + 자연어 설명 생성기
│   ├── cli.py                 # 커맨드라인 진입점
│   └── evaluation.py          # 집계 메트릭 및 보고서
├── datasets/                  # APPATCH 데이터셋 (zeroday, extractfix, patchdb)
├── README.md                  # 이 파일
└── poc_plan_clean.md          # 통합 PoC 계획
```

## PoC 실행하기

아래의 모든 명령어는 저장소 루트에서 실행되며, Python 3.11+ 버전과 
필요한 의존성이 설치되어 있다고 가정합니다.

### 기본 실행

```
# 기본 PoC 데이터셋 실행 (휴리스틱 toy 예제)
python -m patchscribe.cli

# ID로 특정 케이스 실행
python -m patchscribe.cli buffer_overflow_simple
```

### 전략 (C1–C3)

| 플래그 | 설명 |
|------|-------------|
| `--strategy minimal` | C1: 서명만으로 패치 (PCG/SCM 컨텍스트 없음) |
| `--strategy formal`  | C2: PCG/SCM 유도 개입 사용 (기본값) |
| `--strategy natural` | C3: 형식적 컨텍스트 + 인과적 자연어 요약(개입·패치·효과를 모두 제공) |
| `--strategy only_natural` | 형식식 대신 자연어 설명(인과 경로·개입 계획·패치 영향)을 사용 |

자연어 설명은 두 가지 방식으로 생성할 수 있습니다:

| 플래그 | 설명 |
|------|-------------|
| `--explain-mode template` | PCG/SCM에서 구축된 결정적 템플릿 (기본값) |
| `--explain-mode llm`      | 인과적 컨텍스트를 사용하여 LLM에게 설명 작성 요청 (참조용 템플릿 표시) |
| `--explain-mode both`     | 템플릿 및 LLM 작성 설명 모두 생성 |

`natural`/`only_natural` 전략을 선택하면 LLM 프롬프트에 다음과 같은 자연어 서술이 자동으로
추가됩니다:
- 취약점 개요, 논리식(PCG/SCM)의 자연어 해석
- 인과 경로 및 개입 계획(원인·조치·기대효과)
- 적용된 패치 diff 요약과 패치 효과 분석
- (필요 시) ground truth 패치로부터 도출한 전/후 비교

zeroday 데이터셋에서 (C3) 예제 실행 (처음 5개 샘플):
```
python -m patchscribe.cli --dataset zeroday --limit 5 --strategy natural
```

### 결과 저장

결과를 디스크에 저장하려면 `--output`을 사용하세요. 기본값인 `--format json` 또는
패치 차이, 설명, 프롬프트 컨텍스트를 포함하는 검토자 친화적인 보고서를 위한
`--format markdown`을 선택할 수 있습니다.

```
python -m patchscribe.cli \
    --dataset zeroday --limit 20 --strategy formal \
    --explain-mode both \
    --output results/zeroday_formal.md --format markdown
```

### 자동 메트릭 및 GPT 평가

집계 메트릭(성공률, 정답 일치 등)을 평가합니다. GPT API를 구성하면 패치 안정성(GPT 점수)과
설명 품질(정확성/명확성/인과성)을 자동으로 수집합니다:
```
python -m patchscribe.cli \
    --dataset zeroday --limit 20 --strategy formal \
    --evaluate --output results/zeroday_metrics.json
```

### Ollama를 사용한 로컬 LLM 실험

[Ollama](https://ollama.com/)를 통해 대체 경량 모델(예: Qwen, LLaMA, DeepSeek, Gemma)을 
시도할 수 있습니다. Ollama 데몬이 로컬에서 실행 중인지 확인하고(`ollama serve`), 
다음과 같이 몇 가지 모델을 가져옵니다(24GB GPU 환경 기준):

```
./scripts/setup_ollama_models.sh
```

`patchscribe.cli`를 호출하기 전에 다음 변수를 내보내 파이프라인이 Ollama를 
대상으로 하도록 구성합니다:

```
export PATCHSCRIBE_LLM_PROVIDER=ollama
# 예제 모델: qwen3:0.6b, DeepSeek-R1:1.5b, gemma3:1b, Llama3.2:1b
export PATCHSCRIBE_LLM_MODEL=Llama3.2:1b
# Ollama가 기본 포트에서 실행되는 경우 선택 사항:
export PATCHSCRIBE_LLM_ENDPOINT=http://127.0.0.1:11434/api/chat
python -m patchscribe.cli --dataset zeroday --limit 1 --strategy formal
```

동일한 구성을 CLI 옵션으로 직접 전달할 수도 있습니다:

```
python -m patchscribe.cli \
    --dataset zeroday --limit 1 --strategy formal \
    --llm-provider ollama --llm-model Llama3.2:1b
```

가져온 로컬 모델(예: `qwen3:0.6b`, `DeepSeek-R1:1.5b`, `gemma3:1b`, `Llama3.2:1b`)로 `--llm-model` 값을 
변경하여 응답을 비교할 수 있습니다. 필요한 경우 `--llm-timeout`으로 초 단위 타임아웃을 조정하세요.
Ollama의 HTTP API는 모델 이름 대소문자를 구분하므로 `ollama list`에 표시된 표기와 동일하게 지정해야 합니다.

설명용 LLM 프롬프트에 추가 지시를 전달하려면 `--explanation-prompt` 또는
`--explanation-prompt-file`을 사용할 수 있습니다. 두 옵션을 함께 쓰면 텍스트가 결합되어
LLM 프롬프트 마지막에 덧붙습니다.

`run.py` 스크립트는 기본 전략(minimal/formal/natural)을 한 번에 실행하는 단순 래퍼입니다.

## 수동 평가 워크플로우

1. `--output ... --format markdown`으로 파이프라인을 실행하여 사람이 읽을 수 있는 
   보고서를 생성합니다. 각 케이스 섹션에는 다음이 포함됩니다:
   - 패치 차이(diff)
   - 정답 미리보기 (`nonvul.c` 스니펫)
   - 템플릿 + (선택적) LLM 생성 자연어 설명
   - 형식적 SCM 요약
   - LLM에 사용된 프롬프트 컨텍스트 및 설명 프롬프트
2. 베이스라인 비교를 위해 다른 `--strategy` 플래그 또는 `--compare`(플레이스홀더)로 
   재실행하고 출력을 별도의 파일 이름으로 저장합니다.
3. 검토자는 Markdown 파일에 주석을 달거나 PDF로 변환하고 `poc_plan_clean.md` 
   (섹션 3.3)의 루브릭을 사용하여 설명에 점수를 매길 수 있습니다.

## 현재 상태

- ✅ APPATCH zeroday 데이터셋에 대한 패치/설명 번들을 생성하는 엔드투엔드 PoC 파이프라인
- ✅ 프롬프트 컨텍스트가 있는 전환 가능한 LLM 전략 (minimal/formal/natural)
- ✅ 수동/자동 검토를 위한 메트릭 + Markdown 보고서 (KLEE/CBMC/LibFuzzer 기반 삼중 검증 및 GPT 점수 포함)
- ⚠️ 베이스라인 전략(`raw_gpt4`, `vrpilot` 등)에는 구체적인 프롬프트 정의가 필요

전체 연구 계획 및 남은 작업에 대해서는 `poc_plan_clean.md`를 참조하세요.
