"""
LLM integration utilities for guided patch synthesis.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple, TYPE_CHECKING
from urllib.parse import urljoin

if TYPE_CHECKING:
    from .spec_builder import SpecificationLevel

try:  # pragma: no cover - optional dependency
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover - networkless fallback
    requests = None
    HTTPAdapter = None
    Retry = None


class LLMUnavailable(RuntimeError):
    """Raised when an LLM call is requested but configuration is missing."""


DEFAULT_OLLAMA_ENDPOINT = "http://127.0.0.1:11434/api/chat"
DEFAULT_OLLAMA_MODEL = "llama3.2:1b"

DEFAULT_VLLM_ENDPOINT = "http://115.145.135.227:7220/v1/chat/completions"
DEFAULT_VLLM_MODEL = "openai/gpt-oss-120b"
DEFAULT_ANTHROPIC_ENDPOINT = "https://api.anthropic.com/v1/messages"
DEFAULT_ANTHROPIC_MODEL = "claude-haiku-4-5"
DEFAULT_ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_LLM_MAX_TOKENS = 8192
DEFAULT_GEMINI_ENDPOINT_TEMPLATE = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)
DEFAULT_GEMINI_MODEL = "gemini-2.5-pro"

# Judge model configuration (single judge: gpt-5-mini)
DEFAULT_JUDGE_MODEL = "gpt-5-mini"
DEFAULT_OPENAI_ENDPOINT = "https://api.openai.com/v1/chat/completions"
DEFAULT_OPENAI_COMPLETION_MODEL = DEFAULT_JUDGE_MODEL


@dataclass
class LLMConfig:
    provider: str = "ollama"
    endpoint: str | None = None
    api_key: str | None = None
    model: str | None = None
    timeout: int = 300
    max_tokens: int | None = None

    def __post_init__(self) -> None:
        if not self.model:
            if self.provider == "ollama":
                self.model = DEFAULT_OLLAMA_MODEL
            elif self.provider == "vllm":
                self.model = DEFAULT_VLLM_MODEL
            elif self.provider == "openai":
                self.model = DEFAULT_OPENAI_COMPLETION_MODEL
            elif self.provider == "anthropic":
                self.model = DEFAULT_ANTHROPIC_MODEL
            elif self.provider == "gemini":
                self.model = DEFAULT_GEMINI_MODEL

        if not self.endpoint:
            if self.provider == "ollama":
                self.endpoint = DEFAULT_OLLAMA_ENDPOINT
            elif self.provider == "openai":
                self.endpoint = DEFAULT_OPENAI_ENDPOINT
            elif self.provider == "vllm":
                self.endpoint = DEFAULT_VLLM_ENDPOINT
            elif self.provider == "anthropic":
                self.endpoint = DEFAULT_ANTHROPIC_ENDPOINT
            elif self.provider == "gemini":
                self.endpoint = DEFAULT_GEMINI_ENDPOINT_TEMPLATE.format(
                    model=self.model or DEFAULT_GEMINI_MODEL
                )

        if self.provider == "anthropic" and self.max_tokens is None:
            self.max_tokens = DEFAULT_LLM_MAX_TOKENS

    @classmethod
    def from_env(cls, *, for_judge: bool = False, judge_model: str = None) -> "LLMConfig":
        """Create LLM config from environment variables.

        Args:
            for_judge: If True, returns config for judge LLM (gpt-5-mini).
                       If False, returns config for main LLM generation.
            judge_model: Deprecated. Always uses gpt-5-mini for judge.
        """
        if for_judge:
            # Always use gpt-5-mini for judge
            return cls(
                provider="openai",
                endpoint=DEFAULT_OPENAI_ENDPOINT,
                api_key=os.environ.get("OPENAI_API_KEY"),
                model=DEFAULT_JUDGE_MODEL,
                timeout=int(os.environ.get("PATCHSCRIBE_JUDGE_TIMEOUT", "120")),
                max_tokens=None,
            )

        provider = (os.environ.get("PATCHSCRIBE_LLM_PROVIDER") or "ollama").lower()
        endpoint = os.environ.get("PATCHSCRIBE_LLM_ENDPOINT")
        model = os.environ.get("PATCHSCRIBE_LLM_MODEL")
        timeout = int(os.environ.get("PATCHSCRIBE_LLM_TIMEOUT", "300"))
        max_tokens_env = os.environ.get("PATCHSCRIBE_LLM_MAX_TOKENS")
        max_tokens = int(max_tokens_env) if max_tokens_env else None

        if provider == "ollama":
            model = model or DEFAULT_OLLAMA_MODEL
            api_key = os.environ.get("PATCHSCRIBE_LLM_API_KEY")
        elif provider == "vllm":
            model = model or DEFAULT_VLLM_MODEL
            api_key = os.environ.get("PATCHSCRIBE_LLM_API_KEY")
        elif provider == "openai":
            model = model or DEFAULT_OPENAI_COMPLETION_MODEL
            api_key = os.environ.get("OPENAI_API_KEY")
            if max_tokens is None:
                openai_max_env = os.environ.get("OPENAI_MAX_OUTPUT_TOKENS")
                if openai_max_env and openai_max_env.lower() != "none":
                    max_tokens = int(openai_max_env)
        elif provider == "anthropic":
            model = model or DEFAULT_ANTHROPIC_MODEL
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if max_tokens is None:
                anthropic_max_env = os.environ.get("ANTHROPIC_MAX_OUTPUT_TOKENS")
                if anthropic_max_env and anthropic_max_env.lower() != "none":
                    max_tokens = int(anthropic_max_env)
                else:
                    max_tokens = DEFAULT_LLM_MAX_TOKENS
        elif provider == "gemini":
            model = model or DEFAULT_GEMINI_MODEL
            if not endpoint:
                endpoint = DEFAULT_GEMINI_ENDPOINT_TEMPLATE.format(model=model)
            api_key = os.environ.get("GEMINI_API_KEY")
            if max_tokens is None:
                gemini_max_env = os.environ.get("GEMINI_MAX_OUTPUT_TOKENS")
                if gemini_max_env and gemini_max_env.lower() != "none":
                    max_tokens = int(gemini_max_env)
        else:
            provider = "ollama"
            model = model or DEFAULT_OLLAMA_MODEL
            api_key = os.environ.get("PATCHSCRIBE_LLM_API_KEY")

        return cls(
            provider=provider,
            endpoint=endpoint,
            api_key=api_key,
            model=model,
            timeout=timeout,
            max_tokens=max_tokens,
        )


@dataclass(frozen=True)
class PromptOptions:
    """Controls which informational blocks are injected into patch prompts."""

    include_interventions: bool = True
    include_natural_context: bool = True
    include_guidelines: bool = True
    include_provider_hint: bool = True


class LLMClient:
    """Thin HTTP client for chat-style completion APIs used in the PoC."""

    _OLLAMA_MODEL_CACHE: Dict[tuple[str | None, str], str] = {}

    def __init__(self, config: LLMConfig | None = None) -> None:
        self.config = config or LLMConfig.from_env()
        if self.config.provider == "ollama":
            self.config.model = self._normalize_ollama_model(self.config.model)

        # Initialize session with connection pooling
        self._session = self._create_session() if requests is not None else None

    def _create_session(self):
        """Create a requests session with connection pooling and retry logic"""
        if requests is None:
            return None

        session = requests.Session()

        # Configure retry strategy
        if Retry is not None:
            retry_strategy = Retry(
                total=3,  # Maximum number of retries
                backoff_factor=1,  # Wait 1, 2, 4 seconds between retries
                status_forcelist=[429, 500, 502, 503, 504],  # Retry on these status codes
                allowed_methods=["POST", "GET"],  # Allow retry on POST and GET
            )
        else:
            retry_strategy = None

        # Configure connection pooling
        if HTTPAdapter is not None:
            adapter = HTTPAdapter(
                pool_connections=10,  # Number of connection pools to cache
                pool_maxsize=20,  # Maximum connections to save in pool
                max_retries=retry_strategy,
            )
            session.mount("http://", adapter)
            session.mount("https://", adapter)

        return session

    def __del__(self) -> None:
        """Clean up session on deletion"""
        if hasattr(self, '_session') and self._session is not None:
            try:
                self._session.close()
            except Exception:
                pass

    def available(self) -> bool:
        if requests is None or not self.config.endpoint:
            return False
        if self.config.provider == "openai":
            return bool(self.config.api_key)
        if self.config.provider == "anthropic":
            return bool(self.config.api_key)
        if self.config.provider == "gemini":
            return bool(self.config.api_key)
        return True

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        provider = self.config.provider

        if provider == "anthropic":
            if not self.config.api_key:
                raise LLMUnavailable("ANTHROPIC_API_KEY is required for Anthropic provider")
            headers["x-api-key"] = self.config.api_key
            headers["anthropic-version"] = os.environ.get(
                "PATCHSCRIBE_ANTHROPIC_VERSION",
                DEFAULT_ANTHROPIC_VERSION,
            )
            beta = os.environ.get("PATCHSCRIBE_ANTHROPIC_BETA")
            if beta:
                headers["anthropic-beta"] = beta
            return headers

        if provider == "gemini":
            if not self.config.api_key:
                raise LLMUnavailable("GEMINI_API_KEY is required for Gemini provider")
            headers["x-goog-api-key"] = self.config.api_key
            headers.setdefault("x-goog-api-client", "patchscribe/llm")
            return headers

        if self.config.api_key and provider != "ollama":
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    def generate_patch(
        self,
        original_code: str,
        vulnerability_signature: str,
        interventions: Iterable[Dict[str, str]],
        *,
        spec_level: Optional["SpecificationLevel"] = None,  # NEW: Unified prompt
        strategy: str = "formal",  # Deprecated, kept for compatibility
        natural_context: str | None = None,  # Deprecated
        prompt_options: PromptOptions | None = None,
    ) -> Optional[str]:
        """Return full patched code text or None if unavailable."""
        if not self.available():
            return None
        provider_hint = self._provider_hint()
        prompt = self._build_prompt(
            original_code,
            vulnerability_signature,
            interventions,
            strategy=strategy,
            natural_context=natural_context,
            provider_hint=provider_hint,
            prompt_options=prompt_options,
            spec_level=spec_level,  # NEW: Pass spec_level
        )
        content = self._post_chat(
            [
                {"role": "system", "content": self._system_prompt()},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
        )
        patched = self._extract_code(content)
        return patched or content

    def generate_explanation(self, prompt: str) -> Optional[str]:
        if not self.available():
            return None
        content = self._post_chat(
            [
                {"role": "system", "content": self._explanation_system_prompt()},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        return content.strip()

    def score_explanation(self, prompt: str, *, judge_model: str = None) -> Optional[str]:
        """Score explanation quality using gpt-5-mini.

        Args:
            prompt: Evaluation prompt
            judge_model: Deprecated. Always uses gpt-5-mini.
        """
        # Create judge client (always gpt-5-mini)
        judge_config = LLMConfig.from_env(for_judge=True)
        judge_client = LLMClient(judge_config)

        if not judge_client.available():
            return None

        content = judge_client._post_chat(
            [
                {"role": "system", "content": self._judge_system_prompt()},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
        )
        return content.strip()

    @staticmethod
    def batch_score_explanations(prompts: List[str], *, max_workers: int = 5, judge_model: str = None) -> List[Optional[str]]:
        """Score multiple explanations in parallel using gpt-5-mini.

        Args:
            prompts: List of evaluation prompts
            max_workers: Maximum number of concurrent requests (default: 5)
            judge_model: Deprecated. Always uses gpt-5-mini.

        Returns:
            List of scores in the same order as prompts
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # Create judge client (always gpt-5-mini)
        judge_config = LLMConfig.from_env(for_judge=True)
        judge_client = LLMClient(judge_config)

        if not judge_client.available():
            return [None] * len(prompts)

        results = [None] * len(prompts)

        def score_single(index: int, prompt: str) -> Tuple[int, Optional[str]]:
            """Score a single prompt and return with its index"""
            try:
                content = judge_client._post_chat(
                    [
                        {"role": "system", "content": judge_client._judge_system_prompt()},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.0,
                )
                return index, content.strip()
            except Exception as e:
                print(f"Warning: Failed to score explanation {index} with gpt-5-mini: {e}")
                return index, None

        # Execute in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(score_single, i, prompt)
                for i, prompt in enumerate(prompts)
            ]

            for future in as_completed(futures):
                index, score = future.result()
                results[index] = score

        return results

    def score_patch(self, prompt: str, *, judge_model: str = None) -> Optional[str]:
        """Score patch quality using gpt-5-mini.

        Args:
            prompt: Evaluation prompt
            judge_model: Deprecated. Always uses gpt-5-mini.
        """
        # Create judge client (always gpt-5-mini)
        judge_config = LLMConfig.from_env(for_judge=True)
        judge_client = LLMClient(judge_config)

        if not judge_client.available():
            return None

        content = judge_client._post_chat(
            [
                {"role": "system", "content": self._patch_judge_system_prompt()},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
        )
        return content.strip()

    @staticmethod
    def batch_score_patches(prompts: List[str], *, max_workers: int = 5, judge_model: str = None) -> List[Optional[str]]:
        """Score multiple patches in parallel using gpt-5-mini.

        Args:
            prompts: List of patch evaluation prompts
            max_workers: Maximum number of concurrent requests (default: 5)
            judge_model: Deprecated. Always uses gpt-5-mini.

        Returns:
            List of scores in the same order as prompts
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # Create judge client (always gpt-5-mini)
        judge_config = LLMConfig.from_env(for_judge=True)
        judge_client = LLMClient(judge_config)

        if not judge_client.available():
            return [None] * len(prompts)

        results = [None] * len(prompts)

        def score_single(index: int, prompt: str) -> Tuple[int, Optional[str]]:
            """Score a single patch prompt and return with its index"""
            try:
                content = judge_client._post_chat(
                    [
                        {"role": "system", "content": judge_client._patch_judge_system_prompt()},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.0,
                )
                return index, content.strip()
            except Exception as e:
                print(f"Warning: Failed to score patch {index} with gpt-5-mini: {e}")
                return index, None

        # Execute in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(score_single, i, prompt)
                for i, prompt in enumerate(prompts)
            ]

            for future in as_completed(futures):
                index, score = future.result()
                results[index] = score

        return results

    def _post_chat(self, messages: List[Dict[str, str]], *, temperature: float) -> str:
        payload = self._build_payload(messages, temperature=temperature)

        # Use session if available, otherwise fall back to requests module
        http_client = self._session if self._session is not None else requests

        try:
            response = http_client.post(
                self.config.endpoint,
                headers=self._headers(),
                json=payload,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
        except Exception as exc:  # pragma: no cover
            raise LLMUnavailable(str(exc)) from exc
        data = response.json()
        content = self._extract_content(data)
        if not content:
            raise LLMUnavailable("LLM response missing content")
        return content

    def _normalize_ollama_model(self, model: str) -> str:
        if not model or requests is None:
            return model
        tags_url = self._ollama_tags_url()
        if not tags_url:
            return model
        target = model.lower()
        cache_key = (tags_url, target)
        cached = self._OLLAMA_MODEL_CACHE.get(cache_key)
        if cached is not None:
            return cached

        # Use session if available, otherwise fall back to requests module
        http_client = self._session if hasattr(self, '_session') and self._session is not None else requests

        normalized = model
        try:
            response = http_client.get(tags_url, timeout=min(self.config.timeout, 10))
            response.raise_for_status()
            data = response.json()
        except Exception:
            self._OLLAMA_MODEL_CACHE[cache_key] = normalized
            return normalized
        models = data.get("models") or []
        found = False
        for item in models:
            if not isinstance(item, dict):
                continue
            for key in ("name", "model"):
                candidate = item.get(key)
                if isinstance(candidate, str) and candidate.lower() == target:
                    normalized = candidate
                    found = True
                    break
            if found:
                break
        self._OLLAMA_MODEL_CACHE[cache_key] = normalized
        return normalized

    def _ollama_tags_url(self) -> Optional[str]:
        if not self.config.endpoint:
            return None
        base = self.config.endpoint.rstrip("/") + "/"
        return urljoin(base, "../tags")

    @staticmethod
    def _coerce_message_text(content: object) -> str:
        if content is None:
            return ""
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: List[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    text = item.get("text")
                    if isinstance(text, str):
                        parts.append(text)
                else:
                    parts.append(str(item))
            return "\n".join(parts)
        if isinstance(content, dict):
            text = content.get("text")
            if isinstance(text, str):
                return text
        return str(content)

    def _build_payload(self, messages: List[Dict[str, str]], *, temperature: float) -> Dict[str, object]:
        provider = self.config.provider

        if provider == "ollama":
            payload: Dict[str, object] = {
                "model": self.config.model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": temperature},
            }
        elif provider == "anthropic":
            system_prompt: Optional[str] = None
            converted: List[Dict[str, object]] = []

            for message in messages:
                role = message.get("role", "user")
                text = self._coerce_message_text(message.get("content"))

                if role == "system":
                    system_prompt = text if system_prompt is None else f"{system_prompt}\n\n{text}"
                    continue

                anth_role = role if role in {"user", "assistant"} else "user"
                converted.append(
                    {
                        "role": anth_role,
                        "content": [{"type": "text", "text": text}],
                    }
                )

            if not converted:
                raise LLMUnavailable("Anthropic API requires at least one user/assistant message")

            payload = {
                "model": self.config.model,
                "messages": converted,
                "temperature": temperature,
                "max_tokens": self.config.max_tokens or DEFAULT_LLM_MAX_TOKENS,
            }
            if system_prompt:
                payload["system"] = system_prompt
        elif provider == "gemini":
            contents: List[Dict[str, object]] = []
            system_prompts: List[str] = []

            for message in messages:
                role = message.get("role", "user")
                text = self._coerce_message_text(message.get("content")).strip()
                if not text:
                    continue

                if role == "system":
                    system_prompts.append(text)
                    continue

                if role == "assistant":
                    gemini_role = "model"
                elif role == "user":
                    gemini_role = "user"
                else:
                    gemini_role = "user"

                contents.append(
                    {
                        "role": gemini_role,
                        "parts": [{"text": text}],
                    }
                )

            if not contents:
                raise LLMUnavailable("Gemini API requires at least one user or assistant message")

            generation_config: Dict[str, object] = {"temperature": temperature}
            if self.config.max_tokens is not None:
                generation_config["maxOutputTokens"] = self.config.max_tokens

            payload = {
                "contents": contents,
                "generationConfig": generation_config,
            }

            if system_prompts:
                payload["systemInstruction"] = {
                    "parts": [{"text": "\n\n".join(system_prompts)}],
                }

            # Note: Gemini API receives model in the endpoint URL, not in payload
        elif provider == "openai":
            payload = {
                "model": self.config.model,
                "messages": messages,
            }
            if self.config.max_tokens is not None:
                payload["max_tokens"] = self.config.max_tokens
        else:
            payload = {
                "model": self.config.model,
                "messages": messages,
                "temperature": temperature,
            }
            if self.config.max_tokens is not None:
                payload["max_tokens"] = self.config.max_tokens
        return payload

    def _extract_content(self, data: Dict[str, object]) -> Optional[str]:
        if self.config.provider == "ollama":
            message = data.get("message") or {}
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str):
                    return content
            return None
        if self.config.provider == "anthropic":
            content = data.get("content")
            if isinstance(content, list):
                texts: List[str] = []
                for block in content:
                    if isinstance(block, dict):
                        if block.get("type") == "text" and isinstance(block.get("text"), str):
                            texts.append(block["text"])
                if texts:
                    return "\n".join(texts).strip()
            return None
        if self.config.provider == "gemini":
            candidates = data.get("candidates")
            if isinstance(candidates, list):
                collected: List[tuple[Optional[float], str]] = []
                for candidate in candidates:
                    content = candidate.get("content") if isinstance(candidate, dict) else None
                    if not isinstance(content, dict):
                        continue
                    parts = content.get("parts")
                    if not isinstance(parts, list):
                        continue
                    texts: List[str] = []
                    for part in parts:
                        if isinstance(part, dict):
                            text = part.get("text")
                            if isinstance(text, str):
                                texts.append(text)
                    if texts:
                        score = candidate.get("candidateScore")
                        score_val = float(score) if isinstance(score, (float, int)) else None
                        collected.append((score_val, "\n".join(texts).strip()))
                if collected:
                    collected.sort(key=lambda item: (item[0] is None, -(item[0] or 0.0)))
                    return collected[0][1]
            return None
        choices = data.get("choices") or []
        if not isinstance(choices, list) or not choices:
            return None
        first = choices[0] or {}
        if not isinstance(first, dict):
            return None
        message = first.get("message") or {}
        if not isinstance(message, dict):
            return None
        content = message.get("content")
        return content if isinstance(content, str) else None

    @staticmethod
    def _system_prompt() -> str:
        return "You are an expert security engineer specializing in vulnerability analysis and secure code patching."

    @staticmethod
    def _explanation_system_prompt() -> str:
        return (
            "You are a security engineer who writes concise, technically accurate explanations "
            "for vulnerability fixes. Respond in Markdown and avoid speculative statements."
        )

    @staticmethod
    def _judge_system_prompt() -> str:
        return (
            "You are a strict security reviewer who only outputs valid JSON objects with scoring metrics."
        )

    @staticmethod
    def _patch_judge_system_prompt() -> str:
        return (
            "You are a senior application security reviewer. Respond ONLY with JSON including "
            '"safety", "completeness", "regression_risk", "explanation_alignment" (floats 0-5), '
            'a short "verdict", and optional "reason".'
        )

    def _provider_hint(self) -> Optional[str]:
        provider = (self.config.provider or "").lower()
        if provider == "gemini":
            return (
                "- Your response must contain only pure C code; do not use Markdown code blocks.\n"
                "- Maintain function signatures, indentation, and comment styles while adding only necessary guards.\n"
                "- Prioritize adding defensive logic that uses variable/pointer names from the vulnerable signature.\n"
                "- Do not include incomplete text such as TODO, placeholders, or '...'."
            )
        if provider == "claude-haiku-4-5":
            return (
                "- The patch should preserve existing flow while making only minimal necessary changes.\n"
                "- When adding NULL/range checks, maintain existing error handling paths (return codes, logs)."
            )
        return None

    @staticmethod
    def _build_unified_prompt(
        original_code: str,
        vulnerability_signature: str,
        spec_level: Optional["SpecificationLevel"] = None,
    ) -> str:
        """
        Build unified prompt structure for all conditions.

        This is the NEW prompt building method that uses SpecificationLevel
        to provide consistent structure across all experimental conditions.

        Args:
            original_code: The vulnerable C function
            vulnerability_signature: Vulnerability signature string
            spec_level: Specification at appropriate detail level (None for C1)

        Returns:
            Formatted prompt string
        """
        # Header section (same for all conditions)
        prompt = "# Security Patch Generation\n\n"
        prompt += "## Role\n"
        prompt += "You are an expert in fixing security vulnerabilities in C programs.\n\n"

        # Vulnerable code section (same for all conditions)
        prompt += "## Vulnerable Code\n"
        prompt += "```c\n"
        prompt += original_code.strip()
        prompt += "\n```\n\n"
        prompt += f"**Vulnerability Signature**: `{vulnerability_signature}`\n\n"

        # Specification section (condition-dependent)
        if spec_level:
            prompt += spec_level.content + "\n\n"

        # Output requirements (same for all conditions)
        prompt += "## Output\n"
        prompt += "Please provide the following two items:\n\n"
        prompt += "1. **Fixed C Code**:\n"
        prompt += "   - Minimal changes that eliminate the vulnerability\n"
        prompt += "   - Pure C code only, without comments or markdown code blocks\n"
        prompt += "   - Preserve the function signature and existing behavior\n\n"
        prompt += "2. **Explanation**:\n"
        prompt += "   - Root cause: What caused the vulnerability (under what conditions does the problem occur)\n"
        prompt += "   - Fix mechanism: How the patch fixes the vulnerability (what changes work and how)\n"
        prompt += "   - Causal reasoning: Why this change solves the problem\n"

        return prompt

    @staticmethod
    def _build_prompt(
        original_code: str,
        vulnerability_signature: str,
        interventions: Iterable[Dict[str, str]],
        *,
        strategy: str = "formal",
        natural_context: str | None = None,
        provider_hint: str | None = None,
        prompt_options: PromptOptions | None = None,
        spec_level: Optional["SpecificationLevel"] = None,
    ) -> str:
        """
        Build prompt for patch generation.

        NOTE: This method now supports both old and new prompt styles.
        If spec_level is provided, it uses the new unified prompt structure.
        Otherwise, it falls back to the legacy prompt building logic.
        """
        # NEW: Use unified prompt if spec_level is provided
        if spec_level is not None:
            return LLMClient._build_unified_prompt(
                original_code, vulnerability_signature, spec_level
            )

        # LEGACY: Old prompt building logic (for backward compatibility)
        # TODO: This legacy path should be deprecated. All calls should use spec_level.
        options = prompt_options or PromptOptions()
        spec_lines = [
            "- target_line: {target_line}\n  enforce: {enforce}\n  rationale: {rationale}".format(**item)
            for item in interventions
        ]
        spec_block = "\n".join(spec_lines) if spec_lines else "(no interventions)"
        header = (
            "Original C function:\n"
            + "```c\n"
            + original_code.strip()
            + "\n```\n\n"
            + f"Vulnerability signature: `{vulnerability_signature}`\n"
        )
        if strategy == "minimal":
            body = (
                "No additional analysis is available. Produce a secure patch that fixes the "
                "vulnerability indicated by the signature while preserving functionality. "
                "Return only the patched C code without commentary."
            )
        elif strategy == "natural":
            natural_block = natural_context if (options.include_natural_context and natural_context) else None
            if natural_block:
                body = (
                    "You are given a causal explanation of the bug. Use it to produce a minimal patch.\n\n"
                    "Causal explanation:\n"
                    f"{natural_block}\n\n"
                    "Return only the patched C code without commentary."
                )
            else:
                body = (
                    "Produce a minimal patch that removes the vulnerability indicated by the signature "
                    "while preserving functionality. Return only the patched C code without commentary."
                )
        elif strategy == "only_natural":
            natural_block = natural_context if (options.include_natural_context and natural_context) else None
            if natural_block:
                body = (
                    "You are given a natural-language description of the issue and desired behaviour. "
                    "Rely on that description to adjust the function and remove the vulnerability while keeping other behaviour unchanged.\n\n"
                    "Natural description:\n"
                    f"{natural_block}\n\n"
                    "Return only the patched C code without commentary."
                )
            else:
                body = (
                    "Use the vulnerable signature and surrounding code to infer the required fix. "
                    "Return only the patched C code without commentary."
                )
        else:  # formal
            extra = ""
            if options.include_natural_context and natural_context:
                extra = "\n\nNatural causal summary:\n" + natural_context
            intervention_section = ""
            if options.include_interventions and spec_lines:
                intervention_section = "Intervention specification (YAML):\n" + spec_block
            elif options.include_interventions and not spec_lines:
                intervention_section = ""
            body_parts = []
            if intervention_section:
                body_parts.append(intervention_section)
            if extra:
                body_parts.append(extra.strip())
            body_parts.append(
                "Produce a patched version of the function that eliminates the vulnerability while keeping behaviour otherwise identical. Return only the patched C code without commentary."
            )
            body = "\n\n".join(part for part in body_parts if part)
        guideline_block = (
            "\n\nPatch guidelines:\n"
            "- Maintain function signature and return paths, adding guard/validation logic as needed.\n"
            "- Add boundary/NULL checks by directly referencing buffer/pointer/size variables from the vulnerability signature.\n"
            "- Preserve existing error handling (logs, return codes), following the same conventions in new checks."
        )
        if options.include_guidelines:
            body += guideline_block
        if provider_hint and options.include_provider_hint:
            body += "\n\nProvider-specific instructions:\n" + provider_hint
        return header + body

    @staticmethod
    def _extract_code(content: str) -> Optional[str]:
        lines = content.strip().splitlines()
        if not lines:
            return None
        if lines[0].startswith("```"):
            end_index = None
            for idx, line in enumerate(lines[1:], start=1):
                if line.startswith("```"):
                    end_index = idx
                    break
            if end_index is None:
                return "\n".join(lines[1:])
            return "\n".join(lines[1:end_index])
        return content.strip()

    @staticmethod
    def build_explanation_judge_prompt(
        ebug_text: str,
        epatch_text: str,
        vulnerability_signature: str,
        original_code: str,
        patched_code: str,
    ) -> str:
        """Build prompt for judging explanation quality (E_bug and E_patch).

        Evaluates from a developer perspective: "Does this explanation help a developer
        understand the patch and apply similar fixes in the future?"

        Returns a prompt that asks the judge to evaluate:
        - Vulnerability Understanding: Can a developer understand WHY the code is vulnerable?
        - Patch Understanding: Can a developer understand HOW the patch works?
        - Causal Connection: Can a developer understand WHY this patch solves the problem?
        - Actionability: Can a developer apply this knowledge to similar situations?
        """
        return f"""You are evaluating vulnerability explanations from a **developer's perspective**.
The goal is to assess whether these explanations would help a developer:
1. Understand WHY the original code is vulnerable
2. Understand HOW the patch fixes it
3. Apply similar fixes to prevent similar bugs in the future

**Vulnerability Signature:** {vulnerability_signature}

**Original Code:**
```c
{original_code.strip()}
```

**Patched Code:**
```c
{patched_code.strip()}
```

**Bug Explanation (E_bug):**
{ebug_text.strip()}

**Patch Explanation (E_patch):**
{epatch_text.strip()}

---

Evaluate both explanations on the following dimensions (1-5 scale, where 5 is best):

### 1. Vulnerability Understanding (1-5)
**Question:** Can a developer understand WHY the original code is vulnerable?

**Criteria:**
- **Trigger Conditions** (1.5 pts): Does it explain under what conditions (inputs, states) the vulnerability occurs?
  - ✅ EXCELLENT: "when user input > buffer size (256 bytes)" or "when idev is NULL"
  - ❌ WEAK: "when invalid input is provided"
  - Must be **specific and testable**
- **Vulnerable Location** (2.0 pts): Does it precisely identify the vulnerable code location (function, line numbers)?
  - ✅ EXCELLENT: "Line 9: idev->cnf.disable_ipv6 dereference without prior NULL check"
  - ✅ GOOD: "idev dereference in addrconf_disable_ipv6()"
  - ❌ WEAK: "the function has a vulnerability"
  - **Must include**: Function name, line number, or variable name
- **Root Cause** (1.5 pts): Does it explain the underlying programming error?
  - ✅ EXCELLENT: "Missing NULL check allows pointer dereference when lookup fails"
  - ✅ GOOD: "No bounds check before strcpy"
  - ❌ WEAK: "improper validation" or "insecure code"
  - **Post-hoc explanations** often use generic terms → lower score

**Scoring:**
- 5: All three criteria with specific, concrete details
- 4: Two criteria with concrete details, one partial
- 3: Two criteria partially clear OR one excellent + one vague
- 2: Only one criterion with concrete details (others vague)
- 1: All criteria vague, generic, or incorrect

**RED FLAGS (reduce to 1-2):**
- Uses only CWE classification without explaining the actual bug
- Says "vulnerability exists" without explaining why
- No concrete code locations or conditions

---

### 2. Patch Understanding (1-5)
**Question:** Can a developer understand HOW the patch works and what it covers?

**Criteria:**
- **Code Change Coverage** (2.0 pts): Does it describe **ALL** code changes made by the patch?
  - ✅ EXCELLENT (2.0 pts): "Patch adds 3 changes: (1) Line 10: `if (!buf) return -ENOMEM;` (2) Line 15: `if (len >= sizeof(buf)) len = sizeof(buf)-1;` (3) Line 20: `buf[len] = '\0';`"
  - ✅ GOOD (1.5 pts): "Patch adds NULL check at Line 10 and size validation at Line 15"
  - ⚠️ PARTIAL (0.5-1.0 pts): "Patch adds a check" (which check? how many? where?)
  - ❌ WEAK (0 pts): "The patch fixes the code"

  **CRITICAL**: If the patch makes N changes but explanation only describes < N changes → score ≤ 1.5

  **MUST include**: Line numbers or locations + What was added/modified/deleted

- **Mechanism** (2.0 pts): Does it explain HOW each change prevents the vulnerability?
  - ✅ EXCELLENT (2.0 pts): "The `if (!idev)` check at Line 8 causes early return with error code, preventing execution from reaching the dereference `idev->cnf` at Line 12. Control flow: error path exits before vulnerable operation."
  - ✅ GOOD (1.5 pts): "NULL check prevents reaching the dereference"
  - ⚠️ PARTIAL (0.5 pts): "Check prevents the bug"
  - Must explain control flow OR data flow changes

- **Completeness Analysis** (1.0 pt): Does it assess whether the patch is complete or partial?
  - ✅ EXCELLENT (1.0 pt): "Patch fully addresses the vulnerability by adding checks at all 3 user input paths (lines 10, 15, 20). No other unguarded uses of user data exist in this function."
  - ✅ GOOD (0.7 pt): "Patch handles the main path but potential edge case at Line 25 remains"
  - ⚠️ PARTIAL (0.3 pt): Mentions "patch fixes the issue" without analysis
  - ❌ NONE (0 pt): No discussion of completeness

  **Explanations with causal analysis** can better assess completeness by checking if all causal paths are blocked.
  **Post-hoc explanations** typically cannot assess this → if unclear, score ≤ 0.5

**Scoring Guidelines:**
- **5.0**: All code changes identified + Clear mechanism for each + Completeness analysis
- **4.0-4.5**: All code changes + Clear mechanism; completeness partially discussed
- **3.0-3.5**: Most code changes + Mechanism; no completeness discussion
- **2.0-2.5**: Some code changes OR mechanism (not both); no completeness
- **1.0-1.5**: Vague patch description with minimal details
- **0.5**: "Patch fixes it" with no specifics

**MANDATORY PENALTIES:**
- ⛔ **Missing code changes** (describes 1 out of 3 changes) → maximum score 2.5
- ⛔ **No line numbers or locations** → maximum score 3.0
- ⛔ **No mechanism explanation** → maximum score 2.5
- ⛔ **No completeness discussion** → maximum score 4.0

**RED FLAGS:**
- Lists code changes as dry inventory without explaining their purpose
- No discussion of whether patch fully resolves the vulnerability
- Describes patch in isolation without connecting to vulnerability

---

### 3. Causal Connection (1-5)
**Question:** Can a developer understand WHY this patch solves the vulnerability?

**This is the MOST IMPORTANT dimension**. Strong causal explanations require explicit code-level reasoning with concrete paths showing the vulnerability's propagation BEFORE analyzing the patch.

**Criteria:**
- **Concrete Causal Path** (2.5 pts): Does it trace the vulnerability through **specific code locations with variable names and line numbers**?
  - ✅ EXCELLENT (2.5 pts): "At line 45, unchecked index `i` is used in `array[i]`. If `i >= array_size` (from line 40 input), this causes OOB access at line 45. The vulnerability path: Line 40 (user input) → Line 42 (no validation) → Line 45 (OOB write)"
  - ✅ GOOD (1.5-2.0 pts): "`strcpy(buf, user_input)` at Line 10 has no bounds check. If `user_input` length > 256 (buf size), overflow occurs."
  - ⚠️ PARTIAL (0.5-1.0 pts): "Buffer overflow occurs when input is large" (missing line numbers, variable names)
  - ❌ WEAK (0 pts): "The vulnerability occurs due to missing validation" (pure abstraction, no code details)

  **CRITICAL**: **Post-hoc explanations** that only describe the patch's effect (e.g., "NULL check prevents crash") WITHOUT analyzing the original vulnerability path → **maximum 0.8 pt**

  **MUST include for score > 1.5:**
  1. Specific variable names (e.g., `idev`, `buf`, `strlen(src)`)
  2. Line numbers or function names (e.g., "Line 45", "in addrconf_disable_ipv6()")
  3. The propagation sequence (A → B → C)

- **Intervention Mechanism** (1.5 pts): Does it explain HOW the patch breaks the causal path and WHY this location is chosen?
  - ✅ EXCELLENT (1.5 pts): "The patch adds `if (i >= size) return -1;` at Line 44, BEFORE the array access at Line 45. This blocks the causal path by preventing untrusted `i` from reaching the vulnerable array indexing operation. This location is optimal because it's the last point before the vulnerability occurs."
  - ⚠️ PARTIAL (0.5 pts): "Patch adds size check to prevent overflow" (no location, no mechanism)
  - ❌ WEAK (0 pts): "Patch fixes the issue by validating input"

  **MUST explain**: Which specific step in the causal path is blocked + Why this intervention point is effective

- **Counterfactual Reasoning** (1.0 pt): Does it contrast behavior with/without the patch using concrete examples?
  - ✅ EXCELLENT: "Without patch: `i=300` (from input) → `array[300]` → OOB write. With patch: `i=300` → `if (i >= 256)` → early return → no OOB."
  - ⚠️ PARTIAL: "Patch prevents overflow by checking size"

**Scoring Guidelines:**
- **5.0**: Complete causal path (variables + lines + sequence) + Intervention mechanism with location + Counterfactual
- **4.0-4.5**: Complete causal path + Clear intervention mechanism (counterfactual optional)
- **3.0-3.5**: Partial causal path (some code details) + Basic intervention explanation
- **2.0-2.5**: High-level causal claim with minimal code details (typical of simple post-hoc explanations)
- **1.0-1.5**: Only CWE classification or "fix prevents X" without any code-level path
- **0.5**: Incorrect or meaningless causal reasoning

**MANDATORY PENALTIES (apply these strictly):**
- ⛔ **No variable names or line numbers** → maximum score 1.5
- ⛔ **Post-hoc only** (describes patch effect, not original vulnerability propagation) → maximum score 1.0
- ⛔ **No intervention mechanism** (doesn't explain which causal step is blocked) → maximum score 2.0
- ⛔ **Generic terms only** ("improper validation", "insecure code") without specifics → maximum score 1.0
- ⛔ **Missing propagation sequence** (doesn't show A → B → C flow) → maximum score 2.0

**Examples of scoring:**

**Score 4.5-5.0:**
"The vulnerability path: Line 120 receives `user_len` from input → Line 125 uses `memcpy(dst, src, user_len)` without checking `user_len <= dst_size` → If `user_len > 256`, Line 125 writes beyond `dst` boundary.

The patch adds `if (user_len > sizeof(dst)) return -EINVAL;` at Line 123, BEFORE the memcpy. This blocks the path by rejecting oversized lengths before they reach the vulnerable operation. Without patch: user_len=500 → memcpy(dst, src, 500) → 244-byte overflow. With patch: user_len=500 → early return → no overflow."

**Score 0.8-1.0 (typical post-hoc):**
"Buffer overflow happens due to insufficient validation. The patch adds a NULL check which prevents the crash."
(Reason: No variable names, no line numbers, describes patch effect only, doesn't explain original causal path - MAXIMUM 1.0 due to post-hoc penalty)

---

### 4. Actionability (1-5)
**Question:** Can a developer apply this knowledge to prevent similar bugs?

**Criteria:**
- **Pattern Recognition** (2.0 pts): Does it identify a generalizable pattern or principle?
  - Example: "Functions returning ERR_PTR must be checked with IS_ERR()"
  - Example: "Always validate pointer returns before dereferencing"
- **Similar Vulnerability Detection** (1.5 pts): Does it suggest how to find similar bugs elsewhere?
  - Example: "Check other uses of lookup_one_len_unlocked() in this codebase"
  - Example: "Search for pointer dereferences without NULL checks"
- **Prevention Guidelines** (1.5 pts): Does it provide advice for avoiding this class of bugs in the future?
  - Example: "Always check function documentation for error return conventions"
  - Example: "Use static analysis to detect missing NULL checks"

**Scoring:**
- 5: All three criteria present with concrete, actionable advice
- 4: Pattern + Prevention Guidelines clear
- 3: Pattern recognition clear; others partial or missing
- 2: Vague pattern recognition only
- 1: No actionable insights provided

---

### Important Notes:
- **Penalize vague language**: "proper validation", "careful handling" without specifics → lower scores
- **Reward specificity**: Exact line numbers, code snippets, concrete conditions → higher scores
- **Penalize incorrect CWE classification**: If explanation misidentifies the vulnerability type (e.g., calls CWE-401 a NULL dereference), reduce Vulnerability Understanding score
- **Developer practicality over academic formality**: A concise, clear explanation beats a verbose, formal one

---

Respond with ONLY a JSON object in this exact format:
{{
  "vulnerability_understanding": <float 1-5>,
  "patch_understanding": <float 1-5>,
  "causal_connection": <float 1-5>,
  "actionability": <float 1-5>,
  "vulnerability_understanding_reasoning": "<specific reasons for score>",
  "patch_understanding_reasoning": "<specific reasons for score>",
  "causal_connection_reasoning": "<specific reasons for score>",
  "actionability_reasoning": "<specific reasons for score>"
}}"""
