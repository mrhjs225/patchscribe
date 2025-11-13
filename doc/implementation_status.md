# PatchScribe 구현 상태 보고

## 1. 방법론 및 시스템 차이

### 1.1 PCG/SCM 전처리
- **논문 주장**: Phase 1은 Clang/LLVM backward slicing, 다중 분석 융합, absence 패턴 감지를 수행한다고 설명합니다 (`doc/paper/patchscribe.tex:154`, `doc/paper/patchscribe.tex:175`, `doc/paper/patchscribe.tex:825`).
- **구현 현실**: 기본 Static/Taint/Symbolic 분석기는 정규식 기반 휴리스틱에 머물며 (`patchscribe/analysis/static_analysis.py:1`, `patchscribe/analysis/dynamic_analysis.py:1`, `patchscribe/analysis/symbolic_analysis.py:1`), MissingGuard/absence 노드 감지는 전혀 구현되어 있지 않습니다. LLVM/Clang 통합 모듈은 존재하지만 외부 의존성이 없으면 자동으로 비활성화되어 기본 휴리스틱으로 폴백됩니다 (`patchscribe/pcg_builder.py:32`).
- **영향**: PCG 노드/엣지가 단순한 “call foo”, “assign bar” 수준에 머물러 논문에서 언급한 10~25개 핵심 predicate·absence 노드를 재현하지 못하고, 이후 SCM/Intervention 품질도 낮아집니다.
- **갭 해소 가이드라인**:
  1. LLVM/Clang 의존성 설치 여부를 런타임에서 강제 검사하고 실패 시 오류를 반환하도록 PCGBuilder를 강화해 휴리스틱 폴백을 “테스트 모드”로만 허용합니다.
  2. `patchscribe/tools/llvm_slicer.py`와 `patchscribe/analysis/static_analysis_llvm.py`를 실제 실행 경로로 끌어오고, slice 결과를 `MissingGuard` 패턴 라이브러리(32개 absence 패턴)를 구현한 새 모듈에서 후처리하도록 합니다.
  3. Stage-1 캐시(`patchscribe/stage1_cache.py`)를 기본 활성화하여 동일 CVE 반복 시 분석 재사용을 보장하고, 캐시에 분석 통계(노드/엣지 수, absence 탐지 로그)를 저장해 논문과 동일한 감사를 가능케 합니다.

### 1.2 SCM 및 E_bug/E_patch 패키징
- **논문 주장**: PCG를 구조적 방정식으로 매핑하고, SMT가 읽을 수 있는 JSON과 자연어를 동시에 내보낸다고 기술합니다 (`doc/paper/patchscribe.tex:177`, `doc/paper/patchscribe.tex:183`).
- **구현 현실**: `SCMBuilder`는 부모 노드 이름을 “AND”로 단순 연결한 문자열만 만들고 (`patchscribe/scm.py:69`), `generate_E_bug` 역시 텍스트 설명을 합치는 수준입니다 (`patchscribe/formal_spec.py:253`). SMT 식, 변수 타입 제약, 개입 카탈로그도 실제 공식 대신 자연어 문장으로 대체돼 있습니다.
- **영향**: E_bug/E_patch가 논문에서 요구하는 “machine-checkable” 스펙이 아니라 인간 가독용 설명에 가깝고, ConsistencyChecker가 활용할 구조 정보도 제한적입니다.
- **갭 해소 가이드라인**:
  1. PCG 노드 메타데이터에 타입/범위/식별자를 보존하고, `SCMVariable` 도메인을 AST/CFG에서 실제 값 범위로 채워 SMT 변수를 구성합니다.
  2. `formal_spec.py`에서 SMT-LIB/JSON 아티팩트를 생성해 `ConsistencyChecker`와 외부 검증기가 동일 데이터를 공유하도록 직렬화 레이어를 분리합니다.
  3. InterventionSpec에 “do(X=x)” 형태의 형식 개입을 저장하고, Diff 파서가 AST 레벨에서 변수 할당·분기 삽입을 추출하도록 `effect_model.py`와 연동합니다.

### 1.3 일관성 검증 및 수락 정책
- **논문 주장**: PASS/REVIEW/FAIL 세 가지 결정과 0.85/0.70 임계값 기반 점수화를 사용한다고 명시합니다 (`doc/paper/patchscribe.tex:160`, `doc/paper/patchscribe.tex:164`).
- **구현 현실**: `ConsistencyChecker`는 각 차원을 불리언으로만 판단하고 단순 pass/review/fail 라벨을 부여합니다 (`patchscribe/consistency_checker.py:24`). 점수 합산, 가중치, 재시도 한도(최대 다섯 번)도 구현되어 있지 않고, 파이프라인은 consistency.accepted가 False면 같은 사양을 재사용한 채 휴리스틱 피드백만 붙여 재시도합니다 (`patchscribe/pipeline.py:200`).
- **영향**: 논문이 강조한 “사전 보증 임계값”과 “정량화된 근거”가 부재하여 CI 게이트에 그대로 적용할 수 없습니다.
- **갭 해소 가이드라인**:
  1. Coverage/Intervention/Completeness/Alignment 각각에 [0,1] 점수를 계산하는 메트릭 함수를 만들고, 가중 합산 및 PASS/REVIEW/FAIL 임계값을 설정합니다.
  2. Consistency 결과를 반복 프롬프트 설계와 연결해, 실패한 차원별로 InterventionSpec을 자동 수정하도록 피드백 채널을 정형화합니다.
  3. Checker가 SMT나 AST 유사도 결과를 optional evidence로 저장하도록 확장해 Audit 로그에 근거치를 남깁니다.

### 1.4 검증 파이프라인
- **논문 주장**: “machine-assisted consistency validation” 외에도 검증 결과가 CI 대시보드에 게시되며, 부록에서 제시한 루브릭을 활용한 인간 검토를 지원한다고 설명합니다 (`doc/paper/patchscribe.tex:165`, `doc/paper/patchscribe.tex:520`).
- **구현 현실**: `patchscribe/verification.py`는 “트리플 검증 제거됨”이라는 스텁만 반환하고 모든 검사를 무조건 통과 처리합니다 (`patchscribe/verification.py:1`).
- **영향**: symbolic/model-check/fuzzing 결과가 존재하지 않으므로 논문 주장과 달리 자동 검증 근거가 없습니다.
- **갭 해소 가이드라인**:
  1. 취약 코드에 대한 단위 테스트/PoC 실행기를 추가하여 최소한 재현·재패 확인을 자동화합니다.
  2. Solver 기반 형식 검증(예: `z3` 제약)을 Consistency 단계와 별도로 돌려, double-check 로그를 남깁니다.
  3. 실패 시 Reviewer 루브릭(부록)과 연결되는 체크리스트를 자동 출력해 수동 검토 흐름을 복원합니다.

## 2. 평가·분석 차이

### 2.1 평가 방법
- **논문 주장**: 패치 정확도·설명 품질 평가는 4명의 보안 전문가가 수작업으로 수행했다고 적고 있습니다 (`doc/paper/patchscribe.tex:284`, `doc/paper/patchscribe.tex:563`).
- **구현 현실**: 성공 판정과 설명 평가는 GPT-5 기반 싱글 저지로 자동화되어 있으며 (`patchscribe/success_judge.py:1`, `patchscribe/explanation_quality.py:1`, `patchscribe/patch_quality.py:1`), 사람이 관여하지 않습니다.
- **영향**: 논문 수치(예: Likert 4.2점)는 인간 평가 기준과 호환되지 않으며, 리뷰어 기반 신뢰성을 주장할 수 없습니다.
- **갭 해소 가이드라인**:
  1. 기존 LLM 저지 결과를 “초안”으로 간주하고, 최소 표본(예: CVE별 2명) 수동 검토 루프를 추가해 문서의 실험 설계를 재현합니다.
  2. 평가 스크립트(`scripts/evaluate_results.py`)에 사람이 입력할 수 있는 CSV/폼 ingest 경로를 추가하고, 자동/수동 결과를 구분 저장합니다.

### 2.2 실험 지표
- **논문 주장**: Zeroday 42%, ExtractFix 74%, 전체 50%의 C4 정답률을 보고합니다 (`doc/paper/patchscribe.tex:382`, `doc/paper/patchscribe.tex:388`, `doc/paper/patchscribe.tex:397`).
- **구현 현실**: 최신 결과 디렉터리는 Zeroday C4 성공률 19.6% (`results/local/claude-haiku-4-5/20251111-162330/c4_results_analysis.json:7`)에 머물고 ExtractFix C4 역시 8~21% 수준입니다 (`results/local_extractfix/unified/unified_summary.json:7`, `results/local_extractfix/unified/unified_summary.json:55`).
- **영향**: 논문 수치와 코드 실행 결과가 2~4배 이상 괴리되어 재현성을 주장할 수 없습니다.
- **갭 해소 가이드라인**:
  1. 논문과 동일한 모델·프롬프트·재시도 횟수를 config에 고정하고, 결과 파일에 실험 설정 해시를 저장해 추적합니다.
  2. 실제 성공률이 목표치에 도달하지 못하면, 원인(LLM 답변 길이, intervention 품질)을 로그로 남겨 튜닝 루프를 수행하거나 문서 수치를 정정합니다.

### 2.3 성능 계측
- **논문 주장**: 전체 평균 67초, 분석 오버헤드는 0.2초 미만이라고 밝힙니다 (`doc/paper/patchscribe.tex:520`).
- **구현 현실**: 저장된 프로파일에는 대부분의 시간이 0.2초 내외로 기록되어 있어 LLM 호출 시간이 측정되지 않고, 총 소요 시간도 45~60초로 상이합니다 (`results/local/claude-haiku-4-5/20251111-162330/c4_results.json:519`).
- **가이드라인**: LLM 클라이언트 레이어에 트레이싱 훅을 두어 요청·응답 시간을 `PerformanceProfiler`에 전달하고, 동일 포맷(Phase1/Phase2/Total)을 CSV로 export해 문서 수치와 동기화합니다.

## 3. 차이 해소 로드맵 요약
1. **정밀 분석 스택 복원**: LLVM/Clang, absence 패턴, SMT 직렬화까지 Phase 1 전 과정을 하드 의존성으로 격상하고, 실패 시 실험을 중단하도록 합니다.
2. **형식 스펙 개선**: SCM 변수/방정식을 실질적 수식으로 구성하고, Intervention·Diff 해석에 AST/SSA 정보를 포함시켜 ConsistencyChecker가 정량 점수를 계산할 수 있게 합니다.
3. **검증 체인 강화**: Consistency 점수 임계값, 자동 재시도 한도, 수동 리뷰 루브릭, (선택) PoC 실행을 통합해 PASS/REVIEW/FAIL 근거를 남깁니다.
4. **평가 파이프라인 재현**: LLM 저지와 별도로 사람 평가 루프를 도입하거나 논문 수치를 업데이트해 재현성 선언을 일치시킵니다. 실험 결과 파일엔 설정/버전 메타데이터를 반드시 포함합니다.
5. **성능/로그 투명성**: 모든 Phase 타이밍·자원 사용량을 기록하고, 결과 분석 스크립트(`scripts/analyze.py`)가 문서 표·그래프에 필요한 통계를 직접 산출하도록 자동화합니다.

위 작업을 우선순위대로 진행하면, 논문에 기술된 PatchScribe 방법론·평가·분석을 실제 코드베이스와 정합시키거나, 반대로 문서를 현실에 맞게 수정할 수 있습니다.
