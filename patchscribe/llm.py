"""
LLM integration utilities for guided patch synthesis.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional
from urllib.parse import urljoin

try:  # pragma: no cover - optional dependency
    import requests
except Exception:  # pragma: no cover - networkless fallback
    requests = None


class LLMUnavailable(RuntimeError):
    """Raised when an LLM call is requested but configuration is missing."""


DEFAULT_ENDPOINT = "http://115.145.135.227:7220/v1/chat/completions"
DEFAULT_OLLAMA_ENDPOINT = "http://127.0.0.1:11434/api/chat"


@dataclass
class LLMConfig:
    provider: str = "openai"
    endpoint: str | None = None
    api_key: str | None = None
    model: str = "openai/gpt-oss-120b"
    timeout: int = 60

    def __post_init__(self) -> None:
        if not self.endpoint:
            if self.provider == "ollama":
                self.endpoint = DEFAULT_OLLAMA_ENDPOINT
            else:
                self.endpoint = DEFAULT_ENDPOINT

    @classmethod
    def from_env(cls) -> "LLMConfig":
        provider = os.environ.get("PATCHSCRIBE_LLM_PROVIDER", "openai").lower()
        endpoint = os.environ.get("PATCHSCRIBE_LLM_ENDPOINT")
        model = os.environ.get("PATCHSCRIBE_LLM_MODEL")
        if not model:
            model = "llama3.2:1b" if provider == "ollama" else "openai/gpt-oss-120b"
        return cls(
            provider=provider,
            endpoint=endpoint,
            api_key=os.environ.get("PATCHSCRIBE_LLM_API_KEY"),
            model=model,
            timeout=int(os.environ.get("PATCHSCRIBE_LLM_TIMEOUT", "60")),
        )


class LLMClient:
    """Thin HTTP client for chat-style completion APIs used in the PoC."""

    def __init__(self, config: LLMConfig | None = None) -> None:
        self.config = config or LLMConfig.from_env()
        if self.config.provider == "ollama":
            self.config.model = self._normalize_ollama_model(self.config.model)

    def available(self) -> bool:
        return bool(self.config.endpoint and requests is not None)

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key and self.config.provider != "ollama":
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
    ) -> Optional[str]:
        """Return full patched code text or None if unavailable."""
        if not self.available():
            return None
        prompt = self._build_prompt(
            original_code,
            vulnerability_signature,
            interventions,
            strategy=strategy,
            natural_context=natural_context,
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
        if not self.available():
            return None
        content = self._post_chat(
            [
                {"role": "system", "content": self._judge_system_prompt()},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
        )
        return content.strip()

    def _post_chat(self, messages: List[Dict[str, str]], *, temperature: float) -> str:
        payload = self._build_payload(messages, temperature=temperature)
        try:
            response = requests.post(
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
        try:
            response = requests.get(tags_url, timeout=min(self.config.timeout, 10))
            response.raise_for_status()
            data = response.json()
        except Exception:
            return model
        models = data.get("models") or []
        target = model.lower()
        for item in models:
            if not isinstance(item, dict):
                continue
            for key in ("name", "model"):
                candidate = item.get(key)
                if isinstance(candidate, str) and candidate.lower() == target:
                    return candidate
        return model

    def _ollama_tags_url(self) -> Optional[str]:
        if not self.config.endpoint:
            return None
        base = self.config.endpoint.rstrip("/") + "/"
        return urljoin(base, "../tags")

    def _build_payload(self, messages: List[Dict[str, str]], *, temperature: float) -> Dict[str, object]:
        if self.config.provider == "ollama":
            payload: Dict[str, object] = {
                "model": self.config.model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": temperature},
            }
        else:
            payload = {
                "model": self.config.model,
                "messages": messages,
                "temperature": temperature,
            }
        return payload

    def _extract_content(self, data: Dict[str, object]) -> Optional[str]:
        if self.config.provider == "ollama":
            message = data.get("message") or {}
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str):
                    return content
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
    def _build_prompt(
        original_code: str,
        vulnerability_signature: str,
        interventions: Iterable[Dict[str, str]],
        *,
        strategy: str = "formal",
        natural_context: str | None = None,
    ) -> str:
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
            natural_block = natural_context or "No causal explanation provided. Focus on preventing the described failure."
            body = (
                "You are given a causal explanation of the bug. Use it to produce a minimal patch.\n\n"
                "Causal explanation:\n"
                f"{natural_block}\n\n"
                "Return only the patched C code without commentary."
            )
        elif strategy == "only_natural":
            natural_block = natural_context or "A natural-language summary is unavailable; reason about the likely misuse from the signature."
            body = (
                "You are given a natural-language description of the issue and desired behaviour. "
                "Rely on that description to adjust the function and remove the vulnerability while keeping other behaviour unchanged.\n\n"
                "Natural description:\n"
                f"{natural_block}\n\n"
                "Return only the patched C code without commentary."
            )
        else:  # formal
            extra = ""
            if natural_context:
                extra = "\n\nNatural causal summary:\n" + natural_context
            body = (
                "Intervention specification (YAML):\n"
                + spec_block
                + extra
                + "\n\nProduce a patched version of the function that eliminates the vulnerability while keeping behaviour otherwise identical. Return only the patched C code without commentary."
            )
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
