# 구현 현황 (방법론 및 분석)

맥락: 현재 코드베이스와 `doc/paper/patchscribe.tex`에 기술된 방법론을 비교한 내용이며, 성능 수치는 의도적으로 제외했습니다.

## 현재 구현된 부분
- 2단계 오케스트레이션이 존재함 (`patchscribe/pipeline.py`): PCG/SCM 생성, 개입 설계, 패치 생성, 설명 생성, 효과 분석, 선택적 일관성 검증, Stage-1 캐싱까지 호출.
- PCG 빌더가 여러 분석기를 모음 (`analysis/static_analysis*.py`, `ast_analysis*.py`, `dynamic_analysis.py`, `symbolic_analysis.py`) + 32개 미싱가드 패턴 라이브러리(`analysis/absence_analysis.py`)와 선택적 LLVM/pycparser/angr 도구를 지원하고, 분석기 사용 현황/폴백·간선/노드 타입 집계·추이 축소 전후 메트릭을 진단으로 수집.
- 주요 CWE 패밀리용 SCM 템플릿 카탈로그(`patchscribe/data/scm_templates.json`)와 템플릿 로드/바인딩(`patchscribe/scm.py`, `scm_templates.py`); 개입 플래너·포멀 스펙 생성기(`intervention.py`, `formal_spec.py`)가 `E_bug`/`E_patch` 산출물과 SMT/JSON 골격을 생성하며, 템플릿 정준 개입을 실제 인터벤션으로 반영.
- C1–C4 조건 및 ablation 실험 스캐폴딩(`spec_builder.py`, `scripts/run_experiment.py`), LLM 패치/설명 생성(`llm.py`, `patch.py`, `explanation.py`), 결과 집계(`evaluation/evaluator.py`, `scripts/evaluate_results.py`)가 AST 유사도와 LLM 기반 저지를 포함.
- 검증기가 SMT 재생, 구조적 가드 검사, 선택적 PoC 실행을 점수화해 최소 신뢰도 기준으로 패스/실패를 결정.

## 논문(오라클) 대비 부족한 부분
- **PCG 구축 충실도**: 여전히 다수 분석이 정규식/휴리스틱(정적/AST/taint/심볼릭) 기반이며, LLVM/pycparser/angr 경로는 의존성이 있을 때만 동작. 정확한 PDG/백워드 슬라이스 융합과 강한 데이터/제어 간선 의미 부여가 미흡하고, 인과 필터링/추이 축소도 논문 알고리즘·커버리지 수준에는 못 미침.
- **SCM + 개입**: 구조 방정식은 기본 “부모 AND” 휴리스틱을 유지하고 외생/내생 구분을 강제하지 않음. 템플릿 정준 개입은 이제 플래너에 반영되지만, 템플릿 기반 반사실/솔버 연계가 제한적이며 키워드 바인딩에 의존.
- **포멀 설명/효과 모델링**: `generate_E_bug`은 직전 부모만 인과 경로로 기록(전체 경로 탐색 없음)하며 SMT/JSON 산출물이 최소 수준. 패치 효과 검출(`effect_model.py`)은 휴리스틱 PCG/미싱가드 재검사 후 시그니처 부재나 미싱가드 해소 여부로 제거를 판단하며 SCM 반사실·솔버 검사와 무관. `E_patch` 생성도 diff 파싱이 조잡하여 논문의 이중 인과 설명과 정합하지 않을 수 있음.
- **일관성 및 검증**: `consistency_checker.py`는 휴리스틱/선택적 Z3에 의존하고 논문이 명시한 임계치(예: Jaccard/위치 정확도/커버리지)를 구현하지 않음. `verification.py`가 SMT/가드/PoC를 결합해 신뢰도를 산출하지만, 논문이 제시한 삼중 검증·일관성 임계치와 동일한 수준은 아님.
- **패치 생성 가이드**: 개입이 `patch.py`에서 옵션 가드 삽입/휴리스틱 변환 이상으로 강제되지 않으며, 프롬프트가 SCM 템플릿 개입이나 솔버 제약을 충분히 소비하지 않아 “이론 주도”가 주로 서술적 수준에 머묾.
- **RQ 계측**:
  - RQ1 효과는 `evaluation/evaluator.py`에서 AST 유사도로 측정하며, 익스플로잇 기반 정확성이나 전문가 리뷰가 아님.
  - RQ2 패치 품질은 LLM 저지(`success_judge.py`, `patch_quality.py`)와 불완전 패치 생성기에 의존하며, 논문에 있는 4인 전문가 평가, PoC 재현, 취약성 제거율 지표가 없음.
  - RQ3 성능 프로파일러(`performance.py`)는 존재하지만 기본 비활성이고 논문의 단계/시간/자원 분해와 연결되지 않음.
  - RQ4 설명 품질은 체크리스트 + 선택적 LLM 저지를 사용하며(`explanation_quality.py`), 매뉴얼 루브릭(`evaluation/manual_rubric.py`)은 스텁이라 전문가 리커트 점수가 생산되지 않음.
- **데이터셋 정합성**: 평가 로더가 `datasets/zeroday_repair`, `extractfix_dataset`에 한정되고, 논문에 보고된 121 CVE·92% 메모리 안전 코퍼스나 PCG 커버리지/정제 통계와 연결되지 않음.

## 오라클에 맞추기 위한 다음 단계 제안
- LLVM/Clang 파싱과 백워드 슬라이싱을 필수로 하고, 견고한 데이터/제어 의존 간선과 감사 가능한 노드/간선 메트릭(미싱가드 포함)을 Algorithm 1 수준으로 구현해 PCG를 강화.
- SCM 템플릿으로 구조 방정식과 정준 개입을 실제로 내보내고 외생/내생 역할을 반영하며, 솔버 기반 최소 개입·반사실 검사를 활용하도록 `InterventionPlanner`를 재구성.
- `E_bug`/`E_patch`가 전체 인과 경로를 탐색하고 더 풍부한 SMT/JSON 산출물을 제공하며, 패치 효과 판단을 시그니처 휴리스틱이 아닌 SCM 변화에 기반하도록 확장.
- 검증 스텁을 논문의 사후 검증 흐름(일관성 임계치, 선택적 PoC/솔버 검사)으로 대체하고, 일관성 점수를 오라클 기준에 정렬.
- RQ1–RQ4 파이프라인을 논문과 동일하게 재구성: 익스플로잇 기반 정확성, 전문가 패치/설명 평가, 실제 패치 품질 지표(SynEq/SemEq/plausible + PoC), 결과 수집 시 성능 프로파일링 활성화.
