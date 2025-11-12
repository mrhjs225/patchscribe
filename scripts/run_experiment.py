#!/usr/bin/env python3
"""
PatchScribe 통합 실험 스크립트

로컬 및 분산 환경에서 모든 모델과 조건에 대한 실험을 실행합니다.
이 스크립트 하나로 전체 실험 워크플로우를 처리합니다.

사용 예시:
    # 로컬 실험 (3개 케이스로 빠른 테스트)
    python3 scripts/run_experiment.py --quick

    # 로컬 실험 (전체)
    python3 scripts/run_experiment.py --dataset zeroday --limit 10

    # 분산 실험 (Server 0, 4대 서버 중)
    python3 scripts/run_experiment.py --distributed 0 4 20 --dataset zeroday

    # 특정 모델과 조건만
    python3 scripts/run_experiment.py --dataset zeroday --limit 10 \
        --models ollama:llama3.2:1b ollama:llama3.2:3b \
        --conditions c4
"""
import json
import sys
import os
import argparse
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from datetime import datetime
from dataclasses import dataclass

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from patchscribe.llm import (
    DEFAULT_GEMINI_ENDPOINT_TEMPLATE,
    DEFAULT_GEMINI_MODEL as LLM_DEFAULT_GEMINI_MODEL,
    DEFAULT_OLLAMA_ENDPOINT,
    DEFAULT_OPENAI_ENDPOINT,
    PromptOptions,
)


# 전체 실험 대상 모델 리스트 (16개)
DEFAULT_MODELS = [
    "qwen3:14b",
    "qwen3:8b",
    "qwen3:4b",
    "qwen3:1.7b",
    "gemma3:12b",
    "gemma3:4b",
    "gemma3:270m",
    "deepseek-r1:14b",
    "deepseek-r1:8b",
    "deepseek-r1:7b",
    "llama3.2:3b",
    "llama3.2:1b",
    "gpt-oss:20b",
    "gemma3:1b",
    "deepseek-r1:1.5b",
    "qwen3:0.6b",
]

DEFAULT_VLLM_MODEL = "openai/gpt-oss-120b"
DEFAULT_VLLM_ENDPOINT = "http://115.145.135.227:7220/v1/chat/completions"
OPENAI_MODELS = [
    "gpt-5",
    "gpt-5-mini",
    "gpt-5-nano",
    "gpt-4.1-mini",
]
ANTHROPIC_MODELS = [
    "claude-haiku-4-5",
    "claude-sonnet-4-5",
]
GEMINI_MODELS = [
    "gemini-2.5-pro",
    "gemini-2.5-flash",
]

DEFAULT_OPENAI_MODEL = OPENAI_MODELS[1]  # gpt-5-mini
DEFAULT_ANTHROPIC_MODEL = ANTHROPIC_MODELS[0]  # claude-haiku-4-5
DEFAULT_ANTHROPIC_ENDPOINT = "https://api.anthropic.com/v1/messages"
DEFAULT_LLM_MAX_TOKENS = 2048
DEFAULT_GEMINI_MODEL = LLM_DEFAULT_GEMINI_MODEL

CONCURRENCY_ALLOWED_MODELS = {
    'openai': {
        "gpt-5-mini",
        "gpt-4.1-mini",
    },
    'anthropic': {
        "claude-haiku-4-5",
        "claude-3-5-haiku",
    },
    'gemini': {
        "gemini-2.5-flash",
        "gemini-2.0-flash",
    },
}

AUTO_PROVIDER_MAX_TOKENS = {
    'anthropic': 8192,
    'gemini': 8192,
}


def select_default_models(provider: str, *, quick: bool = False) -> List[str]:
    """Return provider-aware default model list."""
    provider = (provider or "ollama").lower()
    if provider == 'ollama':
        return [DEFAULT_MODELS[0]] if quick else list(DEFAULT_MODELS)
    if provider == 'vllm':
        return [DEFAULT_VLLM_MODEL]
    if provider == 'openai':
        return [DEFAULT_OPENAI_MODEL] if quick else list(OPENAI_MODELS)
    if provider == 'anthropic':
        return [DEFAULT_ANTHROPIC_MODEL] if quick else list(ANTHROPIC_MODELS)
    if provider == 'gemini':
        return [DEFAULT_GEMINI_MODEL] if quick else list(GEMINI_MODELS)
    return [DEFAULT_MODELS[0]] if quick else list(DEFAULT_MODELS)


def parse_prompt_components_arg(raw: str | None) -> PromptOptions:
    """Return PromptOptions parsed from CLI input."""
    if not raw or raw.strip().lower() == "all":
        return PromptOptions()
    if raw.strip().lower() == "none":
        return PromptOptions(False, False, False, False)
    tokens = {token.strip().lower() for token in raw.split(",") if token.strip()}
    valid_tokens = {
        "interventions",
        "natural",
        "guidelines",
        "provider_hint",
        "provider",
    }
    invalid = tokens - valid_tokens
    if invalid:
        raise ValueError(f"Unknown prompt component(s): {', '.join(sorted(invalid))}")
    return PromptOptions(
        include_interventions="interventions" in tokens,
        include_natural_context="natural" in tokens,
        include_guidelines="guidelines" in tokens,
        include_provider_hint=bool({"provider_hint", "provider"} & tokens),
    )


def print_llm_settings(llm_config: Dict[str, object]) -> None:
    """Pretty-print LLM runtime settings."""
    provider = llm_config.get('provider', 'ollama')
    endpoint = llm_config.get('endpoint') or 'N/A'
    timeout = llm_config.get('timeout')
    max_tokens = llm_config.get('max_tokens')
    concurrency = llm_config.get('concurrency')
    provider_key = (provider or '').lower()
    model_whitelist = CONCURRENCY_ALLOWED_MODELS.get(provider_key, set())

    print(f"  LLM provider: {provider}")
    print(f"  LLM endpoint: {endpoint}")
    if timeout:
        print(f"  LLM timeout: {timeout}s")
    if max_tokens and provider in {'anthropic', 'gemini'}:
        print(f"  LLM max_tokens: {max_tokens}")
    if concurrency and model_whitelist:
        enabled = ', '.join(sorted(model_whitelist))
        print(f"  LLM concurrency: {concurrency} (enabled for {enabled})")
    if provider_key == 'openai':
        print(f"  Available OpenAI models: {', '.join(OPENAI_MODELS)}")
    elif provider_key == 'anthropic':
        print(f"  Available Claude models: {', '.join(ANTHROPIC_MODELS)}")
    elif provider_key == 'gemini':
        print(f"  Available Gemini models: {', '.join(GEMINI_MODELS)}")


# ============================================================================
# Incomplete Patch Generation for RQ2
# ============================================================================

@dataclass
class IncompletePatch:
    """Represents an intentionally incomplete patch"""
    patch_id: str
    case_id: str
    patched_code: str
    incompleteness_type: str
    description: str
    why_incomplete: str
    should_be_caught_by: List[str]  # List of verification methods that should catch this


class IncompletePatchGenerator:
    """Generates incomplete patches for testing verification methods"""

    def __init__(self, case: Dict):
        self.case = case
        self.case_id = case['id']
        self.source = case['source']
        self.vuln_line = case['vuln_line']
        self.cwe_id = case.get('cwe_id', '')
        self.signature = case.get('signature', '')

    def generate_incomplete_patches(self) -> List[IncompletePatch]:
        """Generate 2-3 incomplete patches based on vulnerability type"""
        patches = []

        # Strategy 1: Specific input check only (misses edge cases)
        patch1 = self._create_specific_input_check()
        if patch1:
            patches.append(patch1)

        # Strategy 2: Partial condition check (misses negatives or other paths)
        patch2 = self._create_partial_condition_check()
        if patch2:
            patches.append(patch2)

        # Strategy 3: Wrong location or incomplete guard
        patch3 = self._create_wrong_location_patch()
        if patch3:
            patches.append(patch3)

        return patches

    def _create_specific_input_check(self) -> Optional[IncompletePatch]:
        """
        Create patch that checks for specific exploit pattern only
        Example: if (len == 256) instead of if (len >= 256)
        """
        lines = self.source.splitlines()
        vuln_idx = self.vuln_line - 1

        if vuln_idx < 0 or vuln_idx >= len(lines):
            return None

        vuln_line_text = lines[vuln_idx]
        indent = self._get_indent(vuln_line_text)

        # Identify vulnerability type and add overly specific check
        if 'strcpy' in vuln_line_text or 'strcat' in vuln_line_text:
            # For buffer overflow: check exact length instead of >=
            guard = f"{indent}if (strlen(input) == 256) return -1;  // Incomplete: only checks exact 256\n"
            incomplete_type = "specific_value_check"
            why = "Checks for equality (==) instead of >= or >, misses other overflow values"
            caught_by = ["V3", "V4"]  # Consistency and triple verification

        elif 'printf' in vuln_line_text and '%' in self.signature:
            # For format string: only check for specific format specifier
            guard = f"{indent}if (strstr(input, \"%s\")) return -1;  // Incomplete: only checks %s\n"
            incomplete_type = "specific_pattern_check"
            why = "Only checks for %s format specifier, misses %n, %x, and other dangerous patterns"
            caught_by = ["V3", "V4"]

        elif 'malloc' in vuln_line_text or 'calloc' in vuln_line_text:
            # For integer overflow: only check positive values
            guard = f"{indent}if (size > INT_MAX) return NULL;  // Incomplete: misses negative overflow\n"
            incomplete_type = "positive_only_check"
            why = "Only checks positive overflow, misses negative values and wraparound"
            caught_by = ["V2", "V3", "V4"]  # Symbolic and consistency

        elif 'scanf' in vuln_line_text or 'gets' in vuln_line_text:
            # For unbounded read: limit to specific size but buffer is smaller
            guard = f"{indent}char limited[128];  // Incomplete: buffer still too small\n"
            incomplete_type = "insufficient_size_limit"
            why = "Adds size limit but the limit is still larger than the buffer size"
            caught_by = ["V2", "V3", "V4"]

        else:
            # Generic: add a check that's always true
            guard = f"{indent}if (1) {{  // Incomplete: tautology, doesn't prevent vulnerability\n"
            guard += f"{indent}    {vuln_line_text.strip()}\n"
            guard += f"{indent}}}\n"
            incomplete_type = "tautology_check"
            why = "Guard condition is always true, provides no actual protection"
            caught_by = ["V2", "V3", "V4"]
            lines[vuln_idx] = ""  # Remove original line

        # Insert guard before vulnerable line
        if 'tautology' not in incomplete_type:
            lines.insert(vuln_idx, guard)

        patched_code = '\n'.join(lines)

        return IncompletePatch(
            patch_id=f"{self.case_id}_incomplete_1",
            case_id=self.case_id,
            patched_code=patched_code,
            incompleteness_type=incomplete_type,
            description="Patch checks for specific exploit input only, misses edge cases",
            why_incomplete=why,
            should_be_caught_by=caught_by
        )

    def _create_partial_condition_check(self) -> Optional[IncompletePatch]:
        """
        Create patch that addresses one path but misses others
        Example: checks input but not when input comes from alternative source
        """
        lines = self.source.splitlines()
        vuln_idx = self.vuln_line - 1

        if vuln_idx < 0 or vuln_idx >= len(lines):
            return None

        vuln_line_text = lines[vuln_idx]
        indent = self._get_indent(vuln_line_text)

        # Add guard that only covers one branch
        if 'strcpy' in vuln_line_text or 'memcpy' in vuln_line_text:
            # Only check if input is from specific source
            guard = f"{indent}// Incomplete: only checks direct input, not processed input\n"
            guard += f"{indent}if (input != NULL && direct_input) {{\n"
            guard += f"{indent}    if (strlen(input) > sizeof(buf)) return -1;\n"
            guard += f"{indent}}}\n"
            incomplete_type = "single_path_check"
            why = "Only guards direct input path, misses processed/indirect input paths"
            caught_by = ["V3", "V4"]

        elif 'malloc' in vuln_line_text:
            # Only check one variable in multiplication
            guard = f"{indent}if (n > 1000) return NULL;  // Incomplete: doesn't check multiplier m\n"
            incomplete_type = "partial_variable_check"
            why = "Checks only one variable in size calculation (n), ignores multiplier (m)"
            caught_by = ["V2", "V3", "V4"]

        else:
            # Generic: add null check but not bounds check
            guard = f"{indent}if (input == NULL) return -1;  // Incomplete: null check only\n"
            incomplete_type = "insufficient_validation"
            why = "Only validates null pointer, doesn't check bounds or other conditions"
            caught_by = ["V3", "V4"]

        lines.insert(vuln_idx, guard)
        patched_code = '\n'.join(lines)

        return IncompletePatch(
            patch_id=f"{self.case_id}_incomplete_2",
            case_id=self.case_id,
            patched_code=patched_code,
            incompleteness_type=incomplete_type,
            description="Patch addresses one causal path but misses others",
            why_incomplete=why,
            should_be_caught_by=caught_by
        )

    def _create_wrong_location_patch(self) -> Optional[IncompletePatch]:
        """
        Create patch at wrong location or with wrong scope
        Example: check after the vulnerable operation instead of before
        """
        lines = self.source.splitlines()
        vuln_idx = self.vuln_line - 1

        if vuln_idx < 0 or vuln_idx >= len(lines):
            return None

        vuln_line_text = lines[vuln_idx]
        indent = self._get_indent(vuln_line_text)

        # Add check AFTER the vulnerable operation (too late)
        post_check = f"{indent}// Incomplete: check is after vulnerable operation\n"
        post_check += f"{indent}if (error_occurred) {{  // Too late - damage already done\n"
        post_check += f"{indent}    return -1;\n"
        post_check += f"{indent}}}\n"

        # Insert after vulnerable line (wrong location)
        lines.insert(vuln_idx + 1, post_check)
        patched_code = '\n'.join(lines)

        return IncompletePatch(
            patch_id=f"{self.case_id}_incomplete_3",
            case_id=self.case_id,
            patched_code=patched_code,
            incompleteness_type="wrong_location",
            description="Patch placed after vulnerable operation instead of before",
            why_incomplete="Validation happens after the vulnerability is exploited, not before",
            should_be_caught_by=["V2", "V3", "V4"]  # Symbolic and consistency should catch
        )

    @staticmethod
    def _get_indent(line: str) -> str:
        """Extract leading whitespace from line"""
        return line[:len(line) - len(line.lstrip())]


# ============================================================================
# Main Experiment Functions
# ============================================================================


def print_header(title: str, width: int = 70):
    """헤더 출력"""
    print("\n" + "=" * width)
    print(f"  {title}")
    print("=" * width)


def calculate_case_allocation(server_id: int, num_servers: int, total_cases: int) -> Tuple[int, int]:
    """각 서버에 할당할 케이스 범위 계산"""
    cases_per_server = total_cases // num_servers
    remainder = total_cases % num_servers

    if server_id < remainder:
        start_index = server_id * (cases_per_server + 1)
        count = cases_per_server + 1
    else:
        start_index = remainder * (cases_per_server + 1) + (server_id - remainder) * cases_per_server
        count = cases_per_server

    return start_index, count


def load_cases(dataset: str, start_index: int = 0, count: int = None) -> List[Dict]:
    """케이스 로드"""
    from patchscribe.dataset import load_cases as load_dataset_cases

    all_cases = load_dataset_cases(dataset)

    if count is None:
        return all_cases[start_index:]
    else:
        return all_cases[start_index:start_index + count]


def get_condition_settings(condition: str) -> Tuple[str, bool]:
    """조건에 맞는 설정 반환"""
    settings = {
        'c1': ('only_natural', False),  # Baseline: Post-hoc natural language
        'c2': ('natural', False),        # Vague hints
        'c3': ('formal', False),         # Pre-hoc formal (no verification)
        'c4': ('formal', True),          # Full PatchScribe (with verification)
    }
    return settings.get(condition, ('formal', True))


def _supports_parallel_conditions(model_spec: str, llm_config: Dict[str, object]) -> bool:
    """특정 모델이 조건 병렬 실행을 안전하게 지원하는지 여부."""
    provider = (llm_config.get('provider') or 'ollama').lower()
    if provider in {'ollama', 'vllm'}:
        return False
    concurrency = llm_config.get('concurrency')
    if not concurrency or concurrency <= 1:
        return False
    model_name = model_spec.split(':', 1)[1] if model_spec.startswith('ollama:') else model_spec
    model_basename = model_name.split('/')[-1] if model_name else model_name
    allowed = CONCURRENCY_ALLOWED_MODELS.get(provider, set())
    return model_basename in allowed


def _model_output_dir(output_dir: Path, model_name: str, run_label: Optional[str]) -> Path:
    base_dir = output_dir / model_name
    if run_label:
        return base_dir / run_label
    return base_dir


def run_single_evaluation(
    cases: List[Dict],
    model_spec: str,
    condition: str,
    output_file: Path,
    *,
    llm_config: Dict[str, object],
    disable_consistency_check: bool = False,
    verbose: bool = True,
    stage1_cache_dir: Optional[Path] = None,
    force_stage1_recompute: bool = False,
    skip_judge_evaluation: bool = False,
    use_majority_voting: bool = False,
    judge_models: List[str] = None,
) -> Dict:
    """단일 모델 × 조건에 대한 평가 실행"""
    from patchscribe.pipeline import PatchScribePipeline
    from patchscribe.evaluation import Evaluator

    # 모델 스펙 파싱
    # 형식: "qwen3:14b" 또는 "ollama:qwen3:14b"
    # 기본 provider는 항상 ollama
    if model_spec.startswith('ollama:'):
        # "ollama:qwen3:14b" -> "qwen3:14b"
        model_name = model_spec[7:]  # "ollama:" 제거
    else:
        # "qwen3:14b" -> "qwen3:14b"
        model_name = model_spec

    provider = (llm_config.get('provider') or 'ollama').lower()
    endpoint = llm_config.get('endpoint')
    timeout = llm_config.get('timeout')
    max_tokens = llm_config.get('max_tokens')
    concurrency = llm_config.get('concurrency')
    prompt_options = llm_config.get('prompt_options')
    model_basename = model_name.split('/')[-1] if model_name else model_name
    concurrency_allowed = (
        provider == 'openai' and model_basename in CONCURRENCY_ALLOWED_MODELS.get('openai', set())
    ) or (
        provider == 'anthropic' and model_basename in CONCURRENCY_ALLOWED_MODELS.get('anthropic', set())
    ) or (
        provider == 'gemini' and model_basename in CONCURRENCY_ALLOWED_MODELS.get('gemini', set())
    )

    # 환경 변수 설정 (provider 별로 동작)
    if provider == 'gemini':
        endpoint = DEFAULT_GEMINI_ENDPOINT_TEMPLATE.format(model=model_name)

    os.environ['PATCHSCRIBE_LLM_PROVIDER'] = provider
    os.environ['PATCHSCRIBE_LLM_MODEL'] = model_name

    if endpoint:
        os.environ['PATCHSCRIBE_LLM_ENDPOINT'] = str(endpoint)
    elif 'PATCHSCRIBE_LLM_ENDPOINT' in os.environ:
        del os.environ['PATCHSCRIBE_LLM_ENDPOINT']

    if timeout is not None:
        os.environ['PATCHSCRIBE_LLM_TIMEOUT'] = str(timeout)
    elif 'PATCHSCRIBE_LLM_TIMEOUT' in os.environ:
        del os.environ['PATCHSCRIBE_LLM_TIMEOUT']

    if max_tokens is not None:
        os.environ['PATCHSCRIBE_LLM_MAX_TOKENS'] = str(max_tokens)
    elif 'PATCHSCRIBE_LLM_MAX_TOKENS' in os.environ:
        del os.environ['PATCHSCRIBE_LLM_MAX_TOKENS']

    # concurrency는 지원되는 모델에서만 사용
    evaluator_kwargs: Dict[str, object] = {}
    if provider in {'ollama', 'vllm'}:
        evaluator_kwargs['max_workers'] = 1
        if concurrency and verbose:
            print("    ⚠️ LLM concurrency is not supported for this provider; running sequentially.")
    elif concurrency and concurrency_allowed:
        evaluator_kwargs['max_workers'] = max(1, int(concurrency))
    else:
        evaluator_kwargs['max_workers'] = 1
        if concurrency and verbose and not concurrency_allowed:
            allowed = ', '.join(sorted(CONCURRENCY_ALLOWED_MODELS.get(provider, set())))
            if allowed:
                print(f"    ⚠️ LLM concurrency ignored (supported models: {allowed}).")
            else:
                print("    ⚠️ LLM concurrency ignored (no supported models for this provider).")

    # 조건별 설정
    strategy, condition_consistency = get_condition_settings(condition)

    # Consistency check: 조건 설정과 CLI 옵션 모두 고려
    final_consistency_check = condition_consistency and not disable_consistency_check

    if verbose:
        print(f"\n>>> Running: {model_name} - Condition {condition}")
        print(f"    Cases: {len(cases)}")
        print(f"    Strategy: {strategy}")
        print(f"    Consistency check: {final_consistency_check}")

    # 파이프라인 설정
    pipeline = PatchScribePipeline(
        strategy=strategy,
        explain_mode='both',
        enable_consistency_check=final_consistency_check,
        enable_performance_profiling=True,
        stage1_cache_dir=stage1_cache_dir,
        force_stage1_recompute=force_stage1_recompute,
        prompt_options=prompt_options,
    )

    # 평가 실행
    evaluator = Evaluator(
        pipeline=pipeline,
        max_workers=evaluator_kwargs.get('max_workers'),
        enable_judge=not skip_judge_evaluation,  # Skip judge if flag is set
        use_majority_voting=use_majority_voting,
        judge_models=judge_models or ['gpt', 'claude', 'gemini'],
    )
    report = evaluator.run(cases)

    # 결과 저장
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(report.as_dict(), f, indent=2)

    success_rate = report.metrics.get('success_rate', 0)
    if verbose:
        print(f"    ✅ Success rate: {success_rate:.1%}")

    return report.as_dict()


def generate_incomplete_patches(cases: List[Dict], output_file: Path, verbose: bool = True) -> Dict:
    """불완전 패치 생성 (RQ2)"""
    if verbose:
        print(f"\nGenerating incomplete patches for {len(cases)} cases...")

    all_patches = {}
    for i, case in enumerate(cases, 1):
        case_id = case['id']
        if verbose and i % 5 == 0:
            print(f"  Progress: {i}/{len(cases)}")

        try:
            generator = IncompletePatchGenerator(case)
            patches = generator.generate_incomplete_patches()

            all_patches[case_id] = [
                {
                    'patch_id': p.patch_id,
                    'case_id': p.case_id,
                    'patched_code': p.patched_code,
                    'incompleteness_type': p.incompleteness_type,
                    'description': p.description,
                    'why_incomplete': p.why_incomplete,
                    'should_be_caught_by': p.should_be_caught_by
                }
                for p in patches
            ]
        except Exception as e:
            if verbose:
                print(f"  ⚠️ Failed for case {case_id}: {e}")
            continue

    # 저장
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(all_patches, f, indent=2)

    total_patches = sum(len(p) for p in all_patches.values())
    if verbose:
        print(f"  ✅ Generated {total_patches} patches for {len(all_patches)} cases")

    return all_patches


def run_experiment(
    dataset: str,
    models: List[str],
    conditions: List[str],
    output_dir: Path,
    llm_config: Dict[str, object],
    start_index: int = 0,
    limit: int = None,
    generate_incomplete: bool = True,
    server_id: int = None,
    verbose: bool = True,
    parallel_conditions: bool = False,
    disable_consistency_check: bool = False,
    stage1_cache_dir: Optional[Path] = None,
    force_stage1_recompute: bool = False,
    precompute_stage1_only: bool = False,
    skip_judge_evaluation: bool = False,
    use_majority_voting: bool = False,
    judge_models: List[str] = None,
):
    """통합 실험 실행

    Args:
        parallel_conditions: True면 모든 (모델, condition) 조합을 병렬 처리
        disable_consistency_check: E_bug/E_patch 일관성 체크 비활성화
        stage1_cache_dir: Stage-1 캐시 경로 (None이면 비활성)
        force_stage1_recompute: 캐시에 있더라도 Stage-1 재계산 여부
        precompute_stage1_only: True면 캐시만 채우고 LLM 호출 없이 종료
    """

    # 케이스 로드
    if verbose:
        print(f"\nLoading cases from dataset: {dataset}")

    cases = load_cases(dataset, start_index, limit)

    if verbose:
        print(f"  Loaded {len(cases)} cases")
        if start_index > 0:
            print(f"  Range: {start_index} to {start_index + len(cases) - 1}")

    if precompute_stage1_only:
        if not stage1_cache_dir:
            raise ValueError("Stage-1 cache directory must be provided for precompute mode.")
        print_header("Stage-1 Precompute Mode")
        _precompute_stage1_batch(
            cases,
            stage1_cache_dir,
            force_stage1_recompute=force_stage1_recompute,
            verbose=verbose,
        )
        print("\n✅ Stage-1 artifacts cached for all assigned cases.")
        return []

    run_label = datetime.now().strftime("%Y%m%d-%H%M%S")
    if verbose:
        print(f"  Run identifier: {run_label}")
        print("  Each model's outputs will be stored in model/<timestamp>/ directories.")

    # 케이스 저장 (분산 실험용)
    if server_id is not None:
        cases_file = output_dir / "assigned_cases.json"
        with open(cases_file, 'w') as f:
            json.dump(cases, f, indent=2)
        if verbose:
            print(f"  Saved assigned cases to: {cases_file}")

    print_header("Running Experiments: All Models × All Conditions")

    # 병렬 처리 모드 선택
    if parallel_conditions:
        results_summary = _run_experiment_parallel(
            cases, models, conditions, output_dir, llm_config,
            server_id, verbose, run_label, disable_consistency_check,
            stage1_cache_dir, force_stage1_recompute,
            skip_judge_evaluation, use_majority_voting, judge_models
        )
    else:
        results_summary = _run_experiment_sequential(
            cases, models, conditions, output_dir, llm_config,
            server_id, verbose, run_label, disable_consistency_check,
            stage1_cache_dir, force_stage1_recompute,
            skip_judge_evaluation, use_majority_voting, judge_models
        )

    # 불완전 패치 생성 (RQ2)
    if generate_incomplete:
        print_header("Generating Incomplete Patches (RQ2)")

        try:
            if server_id is not None:
                incomplete_file = output_dir / f"incomplete_patches_server{server_id}.json"
            else:
                incomplete_file = output_dir / "incomplete_patches.json"

            generate_incomplete_patches(cases, incomplete_file, verbose)

        except Exception as e:
            if verbose:
                print(f"❌ Failed to generate incomplete patches: {e}")
                import traceback
                traceback.print_exc()

    # 실험 완료 요약
    print_header("Experiment Summary")

    print("\nResults by model:")
    for model_result in results_summary:
        print(f"\n  {model_result['model']}:")
        for condition, info in model_result['conditions'].items():
            if 'error' in info:
                print(f"    {condition}: ❌ {info['error'][:50]}...")
            else:
                print(f"    {condition}: {info['success_rate']:.1%} success")

    print(f"\n📁 Results saved to: {output_dir}/")

    # 생성된 주요 파일 목록
    print("\nGenerated files:")
    for model_spec in models:
        model_name = model_spec.split(':', 1)[1] if ':' in model_spec else model_spec
        model_dir = _model_output_dir(output_dir, model_name, run_label)
        if not model_dir.exists():
            model_dir = output_dir / model_name
        if model_dir.exists():
            json_files = list(model_dir.glob("*.json"))
            if json_files:
                try:
                    relative_path = model_dir.relative_to(output_dir)
                except ValueError:
                    relative_path = Path(model_name)
                print(f"  {relative_path}/: {len(json_files)} files")

    # Next steps
    print_header("Next Steps")

    if server_id is not None:
        print("\n분산 실험 - 다음 단계:")
        print("1. 모든 서버에서 실험이 완료될 때까지 대기")
        print("2. 중앙 서버에서 결과 수집:")
        print("   scp -r user@server0:~/patchscribe/results/server0 results/")


def _run_experiment_sequential(
    cases: List[Dict],
    models: List[str],
    conditions: List[str],
    output_dir: Path,
    llm_config: Dict[str, object],
    server_id: int,
    verbose: bool,
    run_label: Optional[str] = None,
    disable_consistency_check: bool = False,
    stage1_cache_dir: Optional[Path] = None,
    force_stage1_recompute: bool = False,
    skip_judge_evaluation: bool = False,
    use_majority_voting: bool = False,
    judge_models: List[str] = None,
) -> List[Dict]:
    """순차 처리 모드 (기존 동작)"""
    results_summary = []

    for model_spec in models:
        model_name = model_spec.split(':', 1)[1] if ':' in model_spec else model_spec

        print(f"\n{'#' * 70}")
        print(f"  MODEL: {model_name}")
        print(f"{'#' * 70}")

        # 모델별 결과 디렉토리
        model_output_dir = _model_output_dir(output_dir, model_name, run_label)
        model_output_dir.mkdir(parents=True, exist_ok=True)

        model_results = {
            'model': model_name,
            'conditions': {}
        }

        # 모든 조건 실행
        for condition in conditions:
            # 결과 파일명
            if server_id is not None:
                result_filename = f"{condition}_server{server_id}_results.json"
            else:
                result_filename = f"{condition}_results.json"

            output_file = model_output_dir / result_filename

            try:
                result = run_single_evaluation(
                    cases,
                    model_spec,
                    condition,
                    output_file,
                    llm_config=llm_config,
                    disable_consistency_check=disable_consistency_check,
                    verbose=verbose,
                    stage1_cache_dir=stage1_cache_dir,
                    force_stage1_recompute=force_stage1_recompute,
                    skip_judge_evaluation=skip_judge_evaluation,
                    use_majority_voting=use_majority_voting,
                    judge_models=judge_models,
                )
                model_results['conditions'][condition] = {
                    'success_rate': result['metrics'].get('success_rate', 0),
                    'output_file': str(output_file)
                }

                if verbose:
                    print(f"    ✅ Condition {condition} completed")

            except KeyboardInterrupt:
                print("\n\n⚠️  Interrupted by user")
                sys.exit(130)
            except Exception as e:
                if verbose:
                    print(f"    ❌ Failed: {e}")
                    import traceback
                    traceback.print_exc()
                model_results['conditions'][condition] = {
                    'success_rate': 0,
                    'error': str(e)
                }
                continue

        results_summary.append(model_results)

        if verbose:
            print(f"\n✅ Model {model_name} completed")

    return results_summary


def _run_experiment_parallel(
    cases: List[Dict],
    models: List[str],
    conditions: List[str],
    output_dir: Path,
    llm_config: Dict[str, object],
    server_id: int,
    verbose: bool,
    run_label: Optional[str] = None,
    disable_consistency_check: bool = False,
    stage1_cache_dir: Optional[Path] = None,
    force_stage1_recompute: bool = False,
    skip_judge_evaluation: bool = False,
    use_majority_voting: bool = False,
    judge_models: List[str] = None,
) -> List[Dict]:
    """병렬 처리 모드: 모든 (모델, condition) 조합을 동시에 처리"""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading

    parallel_tasks = []
    sequential_tasks = []
    sequential_models = set()

    for model_spec in models:
        model_name = model_spec.split(':', 1)[1] if ':' in model_spec else model_spec
        model_output_dir = _model_output_dir(output_dir, model_name, run_label)
        model_output_dir.mkdir(parents=True, exist_ok=True)
        supports_parallel = _supports_parallel_conditions(model_spec, llm_config)
        if not supports_parallel:
            sequential_models.add(model_name)

        for condition in conditions:
            if server_id is not None:
                result_filename = f"{condition}_server{server_id}_results.json"
            else:
                result_filename = f"{condition}_results.json"

            output_file = model_output_dir / result_filename
            task = (model_spec, model_name, condition, output_file)
            if supports_parallel:
                parallel_tasks.append(task)
            else:
                sequential_tasks.append(task)

    total_tasks = len(parallel_tasks) + len(sequential_tasks)
    if verbose:
        print(f"\n🚀 Starting {total_tasks} tasks (parallel where safe)...")
        print(f"   Models: {len(models)}")
        print(f"   Conditions: {len(conditions)}")
        print(f"   Parallel combinations: {len(parallel_tasks)}")
        if sequential_models:
            print(f"   Sequential only: {', '.join(sorted(sequential_models))}")

    # 출력용 Lock
    print_lock = threading.Lock()

    def run_task(task_info):
        """단일 (모델, condition) 실행"""
        model_spec, model_name, condition, output_file = task_info

        try:
            with print_lock:
                print(f"  ▶ Starting: {model_name} - {condition}")

            result = run_single_evaluation(
                cases,
                model_spec,
                condition,
                output_file,
                llm_config=llm_config,
                disable_consistency_check=disable_consistency_check,
                verbose=False,  # 병렬 실행시 개별 verbose 끔
                stage1_cache_dir=stage1_cache_dir,
                force_stage1_recompute=force_stage1_recompute,
                skip_judge_evaluation=skip_judge_evaluation,
                use_majority_voting=use_majority_voting,
                judge_models=judge_models,
            )

            with print_lock:
                success_rate = result['metrics'].get('success_rate', 0)
                print(f"  ✅ Completed: {model_name} - {condition} ({success_rate:.1%})")

            return (model_name, condition, {
                'success_rate': success_rate,
                'output_file': str(output_file)
            }, None)

        except KeyboardInterrupt:
            raise
        except Exception as e:
            with print_lock:
                print(f"  ❌ Failed: {model_name} - {condition}: {str(e)[:50]}")

            return (model_name, condition, {
                'success_rate': 0,
                'error': str(e)
            }, e)

    results_dict = {}

    def record_result(model_name: str, condition: str, result_info: Dict[str, object]) -> None:
        if model_name not in results_dict:
            results_dict[model_name] = {'model': model_name, 'conditions': {}}
        results_dict[model_name]['conditions'][condition] = result_info

    # sequential runs (no safe shared parallelism)
    if sequential_tasks:
        if verbose:
            print("\n⚠️  Executing sequentially for non-concurrent models...")
        for task in sequential_tasks:
            model_name, condition, result_info, error = run_task(task)
            record_result(model_name, condition, result_info)

    # 병렬 실행 (안전한 모델만)
    if parallel_tasks:
        try:
            with ThreadPoolExecutor(max_workers=len(parallel_tasks)) as executor:
                futures = {executor.submit(run_task, task): task for task in parallel_tasks}

                for future in as_completed(futures):
                    try:
                        model_name, condition, result_info, error = future.result()
                        record_result(model_name, condition, result_info)

                    except KeyboardInterrupt:
                        print("\n\n⚠️  Interrupted by user")
                        executor.shutdown(wait=False, cancel_futures=True)
                        sys.exit(130)
                    except Exception as e:
                        if verbose:
                            print(f"  ❌ Unexpected error: {e}")
                            import traceback
                            traceback.print_exc()

        except KeyboardInterrupt:
            print("\n\n⚠️  Interrupted by user")
            sys.exit(130)

    # 결과를 모델 순서대로 정렬
    results_summary = [results_dict[model_spec.split(':', 1)[1] if ':' in model_spec else model_spec]
                       for model_spec in models if (model_spec.split(':', 1)[1] if ':' in model_spec else model_spec) in results_dict]

    return results_summary


def main():
    parser = argparse.ArgumentParser(
        description='PatchScribe 통합 실험 스크립트',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
실행 모드:

1. 빠른 테스트 (3개 케이스):
   python3 scripts/run_experiment.py --quick

2. 로컬 실험 (전체):
   python3 scripts/run_experiment.py --dataset zeroday --limit 10

3. 분산 실험 (4대 서버):
   # Server 0:
   python3 scripts/run_experiment.py --distributed 0 4 20 --dataset zeroday

   # Server 1:
   python3 scripts/run_experiment.py --distributed 1 4 20 --dataset zeroday

4. 특정 모델만:
   python3 scripts/run_experiment.py --dataset zeroday --limit 10 \
       --models qwen3:14b gemma3:12b

5. 특정 모델과 조건만:
   python3 scripts/run_experiment.py --dataset zeroday --limit 10 \
       --models llama3.2:1b \
       --conditions c4

모델 이름 형식:
  - 기본 형식: qwen3:14b, gemma3:12b, deepseek-r1:7b
  - provider(ollama)는 자동 설정됨

전체 실험 대상 모델 (16개):
  qwen3:14b, qwen3:8b, qwen3:4b, qwen3:1.7b,
  gemma3:12b, gemma3:4b, gemma3:270m, gemma3:1b,
  deepseek-r1:14b, deepseek-r1:8b, deepseek-r1:7b, deepseek-r1:1.5b,
  llama3.2:3b, llama3.2:1b, gpt-oss:20b, qwen3:0.6b

기본값:
  - Models: 위 16개 모델 전체
  - Conditions: c1, c2, c3, c4
  - Dataset: zeroday
        """
    )

    # Mode selection
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        '--quick',
        action='store_true',
        help='빠른 테스트 모드 (3개 케이스, C4만)'
    )
    mode_group.add_argument(
        '--distributed',
        nargs=3,
        metavar=('SERVER_ID', 'NUM_SERVERS', 'TOTAL_CASES'),
        help='분산 실험 모드 (예: --distributed 0 4 20)'
    )

    # Data selection
    parser.add_argument(
        '--dataset',
        default='zeroday',
        choices=['zeroday', 'extractfix', 'vulnfix'],
        help='데이터셋 (기본값: zeroday)'
    )
    parser.add_argument(
        '--limit',
        type=int,
        help='처리할 케이스 수'
    )
    parser.add_argument(
        '--offset',
        type=int,
        default=0,
        help='시작 케이스 오프셋 (기본값: 0)'
    )

    # Experiment configuration
    parser.add_argument(
        '--models',
        nargs='+',
        help=f'실험할 모델 리스트 (기본값: {", ".join(DEFAULT_MODELS)})'
    )
    parser.add_argument(
        '--conditions',
        nargs='+',
        choices=['c1', 'c2', 'c3', 'c4'],
        help='실험할 조건 (기본값: c1 c2 c3 c4)'
    )
    parser.add_argument(
        '--skip-incomplete-patches',
        action='store_true',
        help='불완전 패치 생성 건너뛰기'
    )

    # Verification configuration
    parser.add_argument(
        '--disable-consistency-check',
        action='store_true',
        help='E_bug/E_patch 일관성 체크 비활성화. 기본값: 활성화'
    )

    # Judge configuration
    parser.add_argument(
        '--skip-judge-evaluation',
        action='store_true',
        help='Skip all judge evaluation (success + explanation). Only generate patches and explanations. Useful for separating experiment from evaluation.'
    )
    parser.add_argument(
        '--use-majority-voting',
        action='store_true',
        help='Use 3 LLM judges (GPT, Claude, Gemini) with majority voting for success evaluation'
    )
    parser.add_argument(
        '--judge-models',
        nargs='+',
        choices=['gpt', 'claude', 'gemini'],
        default=['gpt', 'claude', 'gemini'],
        help='Judge models to use for majority voting (default: gpt claude gemini)'
    )

    # LLM configuration
    parser.add_argument(
        '--llm-provider',
        choices=['ollama', 'vllm', 'openai', 'anthropic', 'gemini'],
        default='ollama',
        help='패치 생성을 위한 LLM 제공자 선택 (기본값: ollama)'
    )
    parser.add_argument(
        '--llm-endpoint',
        help='LLM 엔드포인트 URL (미지정 시 제공자별 기본값 사용)'
    )
    parser.add_argument(
        '--llm-timeout',
        type=int,
        help='LLM HTTP 요청 타임아웃 (초 단위, 기본값: 300)'
    )
    parser.add_argument(
        '--llm-max-tokens',
        type=int,
        help='LLM max_tokens 설정 (Anthropic/Gemini 호출 시 권장, 기본값: 2048)'
    )
    parser.add_argument(
        '--llm-concurrency',
        type=int,
        help='LLM 동시 요청 수 (OpenAI, Claude, Gemini 지원 모델에만 적용)'
    )
    parser.add_argument(
        '--prompt-components',
        default='all',
        help="유지할 프롬프트 구성요소 지정 (interventions,natural,guidelines,provider_hint|all|none)."
    )
    parser.add_argument(
        '--parallel-conditions',
        action='store_true',
        help='모든 (모델, condition) 조합을 병렬로 처리 (기본값: 순차 처리)'
    )
    parser.add_argument(
        '--stage1-cache-dir',
        default='results/cache/stage1',
        help='Stage-1 캐시 디렉토리 (빈 문자열로 비활성화)'
    )
    parser.add_argument(
        '--precompute-stage1',
        action='store_true',
        help='LLM 호출 전 Stage-1 캐시만 생성하고 종료'
    )
    parser.add_argument(
        '--refresh-stage1-cache',
        action='store_true',
        help='기존 Stage-1 캐시를 무시하고 재계산'
    )

    # Output
    parser.add_argument(
        '--output',
        type=Path,
        help='출력 디렉토리 (기본값: results/)'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='최소 출력 모드'
    )

    args = parser.parse_args()

    stage1_cache_dir = args.stage1_cache_dir.strip() if args.stage1_cache_dir else ""
    if stage1_cache_dir.lower() in {"", "none", "null"}:
        normalized_stage1_cache = None
    else:
        normalized_stage1_cache = Path(stage1_cache_dir).expanduser()

    llm_config = {
        'provider': args.llm_provider,
        'endpoint': args.llm_endpoint,
        'timeout': args.llm_timeout,
        'max_tokens': args.llm_max_tokens if args.llm_max_tokens is not None else None,
        'concurrency': args.llm_concurrency if args.llm_concurrency is not None else None,
    }
    try:
        prompt_options = parse_prompt_components_arg(args.prompt_components)
    except ValueError as exc:
        parser.error(str(exc))

    llm_config['prompt_options'] = prompt_options

    if not llm_config['endpoint']:
        if args.llm_provider == 'ollama':
            llm_config['endpoint'] = DEFAULT_OLLAMA_ENDPOINT
        elif args.llm_provider == 'vllm':
            llm_config['endpoint'] = DEFAULT_VLLM_ENDPOINT
        elif args.llm_provider == 'openai':
            llm_config['endpoint'] = DEFAULT_OPENAI_ENDPOINT
        elif args.llm_provider == 'anthropic':
            llm_config['endpoint'] = DEFAULT_ANTHROPIC_ENDPOINT
        elif args.llm_provider == 'gemini':
            model_for_endpoint = None
            if args.models and len(args.models) == 1:
                model_for_endpoint = args.models[0].split(':', 1)[-1]
            llm_config['endpoint'] = DEFAULT_GEMINI_ENDPOINT_TEMPLATE.format(
                model=model_for_endpoint or DEFAULT_GEMINI_MODEL
            )

    if llm_config['max_tokens'] is None:
        auto_tokens = AUTO_PROVIDER_MAX_TOKENS.get(args.llm_provider.lower())
        if auto_tokens:
            llm_config['max_tokens'] = auto_tokens

    # Configure based on mode
    if args.quick:
        # Quick test mode
        models = args.models if args.models else select_default_models(args.llm_provider, quick=True)
        conditions = args.conditions if args.conditions else ['c4']
        limit = 3
        offset = 0
        output_dir = args.output if args.output else Path('results/quick_test')
        server_id = None

        print_header("Quick Test Mode")
        print_llm_settings(llm_config)
        print(f"  Testing 3 cases with {models[0]}, condition C4")

    elif args.distributed:
        # Distributed mode
        server_id = int(args.distributed[0])
        num_servers = int(args.distributed[1])
        total_cases = int(args.distributed[2])

        models = args.models if args.models else select_default_models(args.llm_provider)
        conditions = args.conditions if args.conditions else ['c1', 'c2', 'c3', 'c4']

        # Calculate case allocation
        offset, limit = calculate_case_allocation(server_id, num_servers, total_cases)

        output_dir = args.output if args.output else Path(f'results/server{server_id}')

        print_header(f"Distributed Mode - Server {server_id}")
        print_llm_settings(llm_config)
        print(f"  Total servers: {num_servers}")
        print(f"  Total cases: {total_cases}")
        print(f"  This server: cases {offset} to {offset + limit - 1} ({limit} cases)")

    else:
        # Local mode
        models = args.models if args.models else select_default_models(args.llm_provider)
        conditions = args.conditions if args.conditions else ['c1', 'c2', 'c3', 'c4']
        limit = args.limit
        offset = args.offset
        output_dir = args.output if args.output else Path('results/local')
        server_id = None

        print_header("Local Experiment Mode")
        print_llm_settings(llm_config)
        if limit:
            print(f"  Processing {limit} cases")
        else:
            print(f"  Processing all cases from dataset")

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Run experiment
    try:
        run_experiment(
            dataset=args.dataset,
            models=models,
            conditions=conditions,
            output_dir=output_dir,
            llm_config=llm_config,
            start_index=offset,
            limit=limit,
            generate_incomplete=not args.skip_incomplete_patches,
            server_id=server_id,
            verbose=not args.quiet,
            parallel_conditions=args.parallel_conditions,
            disable_consistency_check=args.disable_consistency_check,
            stage1_cache_dir=normalized_stage1_cache,
            force_stage1_recompute=args.refresh_stage1_cache,
            precompute_stage1_only=args.precompute_stage1,
            skip_judge_evaluation=args.skip_judge_evaluation,
            use_majority_voting=args.use_majority_voting,
            judge_models=args.judge_models,
        )

        if args.precompute_stage1:
            print("\n✅ Stage-1 caching completed successfully!\n")
        else:
            print("\n✅ Experiment completed successfully!\n")

    except KeyboardInterrupt:
        print("\n\n⚠️  Experiment interrupted by user\n")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Experiment failed: {e}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def _precompute_stage1_batch(
    cases: List[Dict],
    stage1_cache_dir: Path,
    *,
    force_stage1_recompute: bool = False,
    verbose: bool = True,
) -> None:
    """Cache Stage-1 artifacts for all cases without invoking any LLMs."""
    from patchscribe.pipeline import PatchScribePipeline

    if verbose:
        print(f"\nCaching Stage-1 artifacts into: {stage1_cache_dir}")

    pipeline = PatchScribePipeline(
        strategy='formal',
        explain_mode='template',
        enable_consistency_check=False,
        enable_performance_profiling=False,
        stage1_cache_dir=stage1_cache_dir,
        force_stage1_recompute=force_stage1_recompute,
    )
    total = len(cases)
    for idx, case in enumerate(cases, 1):
        pipeline.precompute_stage1(case)
        if verbose:
            identifier = case.get('id') or case.get('case_id') or f"case_{idx}"
            print(f"  [{idx}/{total}] cached {identifier}")


if __name__ == '__main__':
    main()
