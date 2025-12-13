"""
PatchScribe experiment cheatsheet (RQ1–RQ4).

이 파일은 실험 실행 명령어만 정리한 참고용 스크립트입니다.
`python run.py`로 실행하면 RQ1~RQ4에 필요한 명령어가 출력됩니다.

실행 기본 흐름:
  1) RQ1: `scripts/run_experiment.py`로 C1~C4 패치/설명 생성
  2) RQ2/RQ4: `scripts/evaluate_results.py`로 SynEq/SemEq/Plausible + 설명 점수 재계산
  3) RQ3/RQ4: `scripts/analyze.py`로 RQ1~RQ4 요약, `--unified` 후 통계/실패 분석
  4) 통계/실패 분석: `scripts/statistical_analysis.py`, `scripts/failure_analysis.py`
환경 변수 기본값:
  OPENAI_MAX_OUTPUT_TOKENS=none
  ANTHROPIC_MAX_OUTPUT_TOKENS=8192
  GEMINI_MAX_OUTPUT_TOKENS=none
  PATCHSCRIBE_JUDGE_TIMEOUT=120  # GPT-5-mini 단일 저지 기준
"""

from __future__ import annotations

import os
from textwrap import dedent


ENV_DEFAULTS = {
    "OPENAI_MAX_OUTPUT_TOKENS": "none",
    "ANTHROPIC_MAX_OUTPUT_TOKENS": "8192",
    "GEMINI_MAX_OUTPUT_TOKENS": "none",
    "PATCHSCRIBE_JUDGE_TIMEOUT": "120",
}

# 준비: 빠른 스모크 테스트 (3개 케이스, C4)
SMOKE_TEST = [
    "python scripts/run_experiment.py --quick --output results/quick_test"
]

# RQ1: 이론 주도 패치/설명 생성 (C1~C4). 동일 output을 재사용해 모델별 디렉터리만 추가됨.
RQ1_COMMANDS = [
    "# Zeroday 전체 C1~C4 (Anthropic)",
    "python scripts/run_experiment.py --dataset zeroday --llm-provider anthropic --models claude-haiku-4-5 --llm-concurrency 100 --parallel-conditions --output results/rq1_zeroday",
    "# Zeroday 전체 C1~C4 (Gemini)",
    "python scripts/run_experiment.py --dataset zeroday --llm-provider gemini --models gemini-2.5-flash --llm-concurrency 200 --parallel-conditions --output results/rq1_zeroday",
    "# Zeroday 전체 C1~C4 (OpenAI)",
    "python scripts/run_experiment.py --dataset zeroday --llm-provider openai --models gpt-5-mini --llm-concurrency 400 --parallel-conditions --output results/rq1_zeroday",
    "# ExtractFix 전체 C1~C4 (Anthropic)",
    "python scripts/run_experiment.py --dataset extractfix --llm-provider anthropic --models claude-haiku-4-5 --llm-concurrency 100 --parallel-conditions --output results/rq1_extractfix",
    "# ExtractFix 전체 C1~C4 (OpenAI)",
    "python scripts/run_experiment.py --dataset extractfix --llm-provider openai --models gpt-5-mini --llm-concurrency 100 --parallel-conditions --output results/rq1_extractfix",
]

# RQ2/RQ4: 패치 품질 + 설명 품질 재평가 (SynEq/SemEq/Plausible, 설명 점수)
RQ2_COMMANDS = [
    "python scripts/evaluate_results.py results/rq1_zeroday --output results/rq2_zeroday",
    "python scripts/evaluate_results.py results/rq1_extractfix --output results/rq2_extractfix",
]

# RQ3: 스케일/성능 분석 + 일관 RQ1~RQ4 요약
RQ3_COMMANDS = [
    "# Zeroday (모델 필터는 공백으로 구분)",
    "python scripts/analyze.py results/rq2_zeroday --all-conditions --models gpt-5-mini claude-haiku-4-5 gemini-2.5-flash",
    "python scripts/analyze.py --unified results/rq2_zeroday --output results/rq2_zeroday/unified",
    "python scripts/statistical_analysis.py --input results/rq2_zeroday/unified --output results/rq3_zeroday_stats.txt",
    "python scripts/failure_analysis.py --input results/rq2_zeroday/unified --output results/rq3_zeroday_failures.md",
    "# ExtractFix",
    "python scripts/analyze.py results/rq2_extractfix --all-conditions --models gpt-5-mini claude-haiku-4-5",
    "python scripts/analyze.py --unified results/rq2_extractfix --output results/rq2_extractfix/unified",
    "python scripts/statistical_analysis.py --input results/rq2_extractfix/unified --output results/rq3_extractfix_stats.txt",
    "python scripts/failure_analysis.py --input results/rq2_extractfix/unified --output results/rq3_extractfix_failures.md",
]

# RQ4: 설명 품질 확인용(이미 RQ2 평가 결과를 재사용)
RQ4_COMMANDS = [
    "# Zeroday 설명 품질/체크리스트/LLM 점수",
    "python scripts/analyze.py results/rq2_zeroday --all-conditions --models gpt-5-mini claude-haiku-4-5 gemini-2.5-flash",
    "# ExtractFix 설명 품질/체크리스트/LLM 점수",
    "python scripts/analyze.py results/rq2_extractfix --all-conditions --models gpt-5-mini claude-haiku-4-5",
]


def apply_env_defaults() -> None:
    """Set recommended env vars once to avoid repetitive prefixing."""
    for key, value in ENV_DEFAULTS.items():
        os.environ.setdefault(key, value)


def print_section(title: str, commands: list[str]) -> None:
    print(f"\n## {title}")
    for cmd in commands:
        prefix = "" if cmd.startswith("#") else "$ "
        print(f"  {prefix}{cmd}")


def main() -> None:
    apply_env_defaults()
    banner = dedent(
        f"""
        PatchScribe RQ1–RQ4 command reference
        (env defaults applied: {', '.join(f"{k}={v}" for k, v in ENV_DEFAULTS.items())})
        """
    ).strip()
    print(banner)

    print_section("Smoke Test", SMOKE_TEST)
    # print_section("RQ1: Theory-Guided Generation (C1–C4)", RQ1_COMMANDS)
    # print_section("RQ2: Patch/Explanation Re-evaluation", RQ2_COMMANDS)
    # print_section("RQ3: Scalability/Performance + Unified Summary", RQ3_COMMANDS)
    # print_section("RQ4: Explanation Quality (reuses RQ2 outputs)", RQ4_COMMANDS)
    # print("\n[Hint] `--models` 인자는 공백으로 구분해야 하며, 동일 output 디렉터리에 여러 모델을 누적 저장할 수 있습니다.")


if __name__ == "__main__":
    main()
