"""
LLM-based patch success judge replicating manual SynEq/SemEq/Plausible evaluation.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, Optional

from .llm import LLMClient, LLMConfig, LLMUnavailable


@dataclass
class PatchSuccessVerdict:
    syntactic_equivalent: bool
    semantic_equivalent: bool
    plausible: bool
    reason: str = ""
    raw_response: Optional[str] = None
    judge_votes: Optional[Dict[str, Dict[str, bool]]] = None
    voting_method: Optional[str] = None

    @property
    def is_success(self) -> bool:
        return self.syntactic_equivalent or self.semantic_equivalent or self.plausible

    def as_dict(self) -> Dict[str, object]:
        result = {
            "syn_eq": self.syntactic_equivalent,
            "sem_eq": self.semantic_equivalent,
            "plausible": self.plausible,
            "reason": self.reason,
            "raw": self.raw_response,
        }
        if self.judge_votes is not None:
            result["judge_votes"] = self.judge_votes
        if self.voting_method is not None:
            result["voting_method"] = self.voting_method
        return result


class PatchSuccessJudge:
    """
    Determines whether a generated patch satisfies SynEq, SemEq, or Plausible criteria.
    Falls back to deterministic checks before consulting the LLM judge.
    Uses gpt-5-mini as the single judge.
    """

    def __init__(self) -> None:
        """Initialize judge with gpt-5-mini."""
        # Create LLM client for gpt-5-mini
        judge_config = LLMConfig.from_env(for_judge=True, judge_model="gpt")
        self.judge = LLMClient(judge_config)

    def evaluate(
        self,
        *,
        original_code: str,
        patched_code: str,
        ground_truth: Optional[str] = None,
        vulnerability_signature: Optional[str] = None,
        description: Optional[str] = None,
    ) -> PatchSuccessVerdict:
        patched_norm = _normalize_code(patched_code)
        if not patched_norm:
            return PatchSuccessVerdict(False, False, False, reason="Generated patch is empty.")

        syn_eq = _matches_ground_truth(patched_norm, ground_truth)
        if syn_eq:
            return PatchSuccessVerdict(
                syntactic_equivalent=True,
                semantic_equivalent=False,
                plausible=False,
                reason="Patched code exactly matches provided ground truth.",
            )

        # Check if judge is available
        if not self.judge.available():
            return PatchSuccessVerdict(False, False, False, reason="Judge unavailable.")

        prompt = self._build_prompt(
            original_code=original_code,
            patched_code=patched_code,
            ground_truth=ground_truth,
            vulnerability_signature=vulnerability_signature,
            description=description,
        )

        # Call the judge
        try:
            response = self.judge._post_chat(
                [
                    {"role": "system", "content": self._system_prompt()},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
            )
            payload = self._parse_json_response(response)

            if payload is None:
                return PatchSuccessVerdict(
                    False, False, False,
                    reason="Non-JSON response",
                    raw_response=response
                )

            sem_eq = _as_bool(payload.get("semantic_equivalent") or payload.get("sem_eq"))
            plausible = _as_bool(payload.get("plausible"))
            reason = payload.get("reason") or payload.get("analysis") or payload.get("notes") or ""

            return PatchSuccessVerdict(
                syntactic_equivalent=False,
                semantic_equivalent=sem_eq,
                plausible=plausible,
                reason=reason.strip(),
                raw_response=response,
                judge_votes=None,
                voting_method="single",
            )

        except LLMUnavailable as exc:
            return PatchSuccessVerdict(
                False, False, False,
                reason=f"Judge unavailable: {exc}"
            )

    @staticmethod
    def _build_prompt(
        *,
        original_code: str,
        patched_code: str,
        ground_truth: Optional[str],
        vulnerability_signature: Optional[str],
        description: Optional[str],
    ) -> str:
        payload = {
            "task": "classify_patch_success",
            "definitions": {
                "SynEq": "Generated patch text is identical to the ground truth patch.",
                "SemEq": (
                    "Patch differs syntactically but enforces the same behavior as the ground truth, "
                    "fully removing the vulnerability."
                ),
                "Plausible": (
                    "Patch may have different behavior but still eliminates the vulnerability without breaking "
                    "the intended functionality of the original program."
                ),
            },
            "instructions": (
                "Decide whether the generated patch qualifies as SemEq and/or Plausible (SynEq is already determined). "
                "Focus on whether the vulnerability is addressed and whether normal functionality remains intact. "
                "Respond ONLY with JSON containing boolean fields semantic_equivalent, plausible, and a short reason."
            ),
            "context": {
                "vulnerability_signature": vulnerability_signature,
                "description": description,
            },
            "code": {
                "original_vulnerable": original_code,
                "generated_patch": patched_code,
                "ground_truth_patch": ground_truth,
            },
        }
        return json.dumps(payload, ensure_ascii=False)

    @staticmethod
    def _parse_json_response(response: str) -> Optional[Dict[str, object]]:
        response = response.strip()
        if not response:
            return None
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # Some judges wrap JSON in commentary; extract the last object.
        buf = ""
        depth = 0
        candidates = []
        for ch in response:
            if ch == "{":
                depth += 1
            if depth:
                buf += ch
            if ch == "}":
                depth -= 1
                if depth == 0 and buf:
                    candidates.append(buf)
                    buf = ""
        for snippet in reversed(candidates):
            snippet = snippet.strip()
            if not snippet:
                continue
            try:
                return json.loads(snippet)
            except json.JSONDecodeError:
                continue
        return None

    @staticmethod
    def _system_prompt() -> str:
        return (
            "You replace a human evaluation panel for security patches. "
            "Use the provided definitions to decide if a generated patch is SemEq or Plausible. "
            "Respond strictly with JSON: {\"semantic_equivalent\": bool, \"plausible\": bool, \"reason\": \"...\"}."
        )

def _normalize_code(code: Optional[str]) -> str:
    if not code:
        return ""
    return "\n".join(line.rstrip() for line in code.strip().splitlines())


def _matches_ground_truth(patched_norm: str, ground_truth: Optional[str]) -> bool:
    if not ground_truth:
        return False
    return patched_norm == _normalize_code(ground_truth)


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if not normalized:
            return False
        if normalized in {"true", "yes", "y", "1", "pass"}:
            return True
        if normalized in {"false", "no", "n", "0", "fail"}:
            return False
    return False
