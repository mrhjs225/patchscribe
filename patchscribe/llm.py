"""
LLM integration utilities for guided patch synthesis.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin

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
DEFAULT_LLM_MAX_TOKENS = 2048
DEFAULT_GEMINI_ENDPOINT_TEMPLATE = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)
DEFAULT_GEMINI_MODEL = "gemini-2.5-pro"

# Judge model configuration (fixed to OpenAI GPT-5-mini)
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
    def from_env(cls, *, for_judge: bool = False) -> "LLMConfig":
        """Create LLM config from environment variables.

        Args:
            for_judge: If True, returns config for OpenAI GPT-5-mini judge.
                       If False, returns config for main LLM generation.
        """
        if for_judge:
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
        elif provider == "anthropic":
            model = model or DEFAULT_ANTHROPIC_MODEL
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if max_tokens is None:
                max_tokens = DEFAULT_LLM_MAX_TOKENS
        elif provider == "gemini":
            model = model or DEFAULT_GEMINI_MODEL
            if not endpoint:
                endpoint = DEFAULT_GEMINI_ENDPOINT_TEMPLATE.format(model=model)
            api_key = os.environ.get("GEMINI_API_KEY")
            if max_tokens is None:
                max_tokens = DEFAULT_LLM_MAX_TOKENS
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
        strategy: str = "formal",
        natural_context: str | None = None,
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

    def score_explanation(self, prompt: str) -> Optional[str]:
        """Score explanation quality using gpt-5 judge.

        This method always uses OpenAI gpt-5, regardless of the
        main LLM configuration used for generation.
        """
        # Create separate judge client with OpenAI gpt-5
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
    def batch_score_explanations(prompts: List[str], *, max_workers: int = 5) -> List[Optional[str]]:
        """Score multiple explanations in parallel using gpt-5 judge.

        Args:
            prompts: List of evaluation prompts
            max_workers: Maximum number of concurrent requests (default: 5)

        Returns:
            List of scores in the same order as prompts
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # Create judge client once
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
                print(f"Warning: Failed to score explanation {index}: {e}")
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

    def score_patch(self, prompt: str) -> Optional[str]:
        """Score patch quality using gpt-5 judge.

        This method always uses OpenAI gpt-5, regardless of the
        main LLM configuration used for generation.
        """
        # Create separate judge client with OpenAI gpt-5
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
    def batch_score_patches(prompts: List[str], *, max_workers: int = 5) -> List[Optional[str]]:
        """Score multiple patches in parallel using gpt-5 judge.

        Args:
            prompts: List of patch evaluation prompts
            max_workers: Maximum number of concurrent requests (default: 5)

        Returns:
            List of scores in the same order as prompts
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # Create judge client once
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
                print(f"Warning: Failed to score patch {index}: {e}")
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
        return "You are a helpful assistant."

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
                "- 답변은 반드시 순수한 C 코드만 포함해야 하며 Markdown 코드블록을 사용하지 마세요.\n"
                "- 함수 시그니처, 인덴트, 주석 스타일을 유지하면서 필요한 가드만 추가하세요.\n"
                "- 취약 지문(시그니처)에 등장하는 변수/포인터 이름을 그대로 사용하는 방어 로직을 우선적으로 추가하세요.\n"
                "- TODO, placeholder, '...' 등의 불완전한 텍스트를 포함하지 마세요."
            )
        if provider == "claude-haiku-4-5":
            return (
                "- 패치는 기존 흐름을 보존하면서 필요한 최소 변경만 수행하세요.\n"
                "- NULL/범위 검사를 추가할 때는 기존 오류 처리 경로(리턴 코드, 로그)를 유지합니다."
            )
        return None

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
    ) -> str:
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
            "- 함수 시그니처와 반환 경로를 유지하고, 필요한 경우 가드/검증 로직을 추가하세요.\n"
            "- 취약 지문에 등장한 버퍼/포인터/사이즈 변수를 그대로 참조하여 경계·NULL 검사를 넣으세요.\n"
            "- 기존 오류 처리(로그, 리턴코드)를 삭제하지 말고, 새 검사에서도 동일 규약을 따르세요."
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

        Returns a prompt that asks the judge to evaluate:
        - Accuracy: Technical correctness of the explanation
        - Completeness: Coverage of key vulnerability aspects
        - Clarity: Understandability and structure
        - Causality: Quality of causal reasoning
        """
        return f"""Evaluate the quality of the following vulnerability explanations.

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

Evaluate both explanations on the following dimensions (1-5 scale, where 5 is best):

1. **Accuracy**: Are the explanations technically correct? Do they accurately describe the vulnerability and fix?
2. **Completeness**: Do they cover all key aspects (root cause, attack vector, mitigation)?
3. **Clarity**: Are they clear, well-structured, and understandable?
4. **Causality**: Do they provide good causal reasoning about why the bug exists and how the patch fixes it?

Respond with ONLY a JSON object in this exact format:
{{
  "accuracy": <float 1-5>,
  "completeness": <float 1-5>,
  "clarity": <float 1-5>,
  "causality": <float 1-5>,
  "reasoning": "<brief explanation of scores>"
}}"""
