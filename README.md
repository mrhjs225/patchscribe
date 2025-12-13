# PatchScribe (PoC) Quick Notes

이 프로젝트는 논문 실험용 PoC입니다. CI/CD 없이 수동 실행/커밋만 관리하는 가벼운 워크플로를 전제로 합니다.

## 필수/선택 의존성
- 기본 실행은 파이썬 의존성만으로 동작하나, 정확한 PCG/SCM 분석을 위해 아래를 권장합니다.
  - `clang`/LLVM 14 (IR 생성·슬라이싱)
  - `pycparser` (정확한 AST)
  - `angr`, `tree-sitter` (선택적 심볼릭/AST 유사도)
- 의존성이 없을 경우 휴리스틱 분석으로 자동 폴백합니다.

## 실행 모드 토글
- 휴리스틱 허용: `PATCHSCRIBE_ALLOW_HEURISTICS=1` (의존성 없을 때 예외 대신 폴백)
- Stage-1 캐시: `PATCHSCRIBE_STAGE1_CACHE=.patchscribe_cache/stage1` (기본값)
- 빠른 실험: `python scripts/run_experiment.py --quick`

## 테스트
- 수동 테스트: `pytest`
  - PCG 진단 메트릭, SCM 정준 개입, PoC 실패 처리 등에 대한 회귀 테스트가 포함되어 있습니다.

## 성능 프로파일링
- 파이프라인 생성 시 `enable_performance_profiling=True` 설정 시 페이즈별 시간/메모리 메트릭을 수집합니다.

## 엄격 모드 힌트
- 정확도를 높이려면:
  - `PATCHSCRIBE_ALLOW_HEURISTICS`를 설정하지 않고 필수 의존성을 설치
  - `PCGBuilderConfig`에서 `use_llvm_slicing=True`, `strict_dependencies=True` 유지
  - `InterventionPlanner`와 일관성 검사 활성화(`enable_consistency_check=True`)

## RQ별 스크립트 요약
- RQ1 (이론 주도 생성 효과): `scripts/run_experiment.py` — `--dataset`, `--models`, `--conditions`로 C1~C4 실험 실행. 빠른 샘플은 `python scripts/run_experiment.py --quick`.
- RQ2 (패치 품질): `scripts/run_experiment.py`에서 불완전 패치 생성(기본 on), 결과를 `scripts/evaluate_results.py`로 재평가하여 SynEq/SemEq/Plausible·설명 점수 산출.
- RQ3 (성능/스케일): 파이프라인 생성 시 `enable_performance_profiling=True`로 실행하면 페이즈별 시간/메모리 로그 수집. 후처리는 `scripts/analyze.py`, `scripts/statistical_analysis.py`, `scripts/failure_analysis.py`.
- RQ4 (설명 품질): `scripts/evaluate_results.py`에서 설명 LLM 저지 및 체크리스트 재계산. 필요 시 `evaluation/manual_rubric.py`의 루브릭 구조를 참고.
- 추가: ablation `scripts/run_ablation_study.py`, 멀티 시드/집계 `scripts/multi_seed_analysis.py`, AST 유사도/통계 분석 `scripts/analyze.py`.
