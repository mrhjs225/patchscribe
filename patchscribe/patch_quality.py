"""
GPT-based patch quality evaluation utilities.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Dict, Optional

from .llm import LLMClient, LLMUnavailable
from .formal_spec import FormalBugExplanation, FormalPatchExplanation
from .patch import PatchResult
from .consistency_checker import ConsistencyResult

TEXTUAL_SCORE_HINTS: Dict[str, float] = {
    # Common qualitative descriptors some LLMs return instead of numeric scores.
    "safe": 5.0,
    "unsafe": 0.0,
    "secure": 5.0,
    "insecure": 0.0,
    "complete": 5.0,
    "incomplete": 1.0,
    "high": 4.0,
    "medium": 3.0,
    "low": 2.0,
    "pass": 5.0,
    "fail": 0.0,
}


@dataclass
class PatchQualityEvaluation:
    scores: Dict[str, float]
    verdict: str
    raw: Optional[str] = None

    def as_dict(self) -> Dict[str, object]:
        return {
            "scores": self.scores,
            "verdict": self.verdict,
            "raw": self.raw,
        }


class PatchQualityEvaluator:
    """
    Uses a GPT judge to score patch quality (safety, completeness, regression risk, explanation alignment).
    """

    def __init__(self, llm_client: LLMClient | None = None) -> None:
        self.llm = llm_client or LLMClient()

    def evaluate(
        self,
        patch: PatchResult,
        E_bug: FormalBugExplanation | None,
        E_patch: FormalPatchExplanation | None,
        consistency: ConsistencyResult | None,
    ) -> PatchQualityEvaluation:
        if not self.llm.available():
            return PatchQualityEvaluation(scores={}, verdict="LLM unavailable")

        prompt = self._build_prompt(patch, E_bug, E_patch, consistency)
        try:
            response = self.llm.score_patch(prompt)
        except LLMUnavailable:
            return PatchQualityEvaluation(scores={}, verdict="LLM unavailable")
        if not response:
            return PatchQualityEvaluation(scores={}, verdict="Empty LLM response")

        payload = self._parse_json_response(response)
        if payload is None:
            return PatchQualityEvaluation(scores={}, verdict="LLM returned non-JSON", raw=response)

        scores = {
            "safety": self._extract_score(payload, "safety"),
            "completeness": self._extract_score(payload, "completeness"),
            "regression_risk": self._extract_score(payload, "regression_risk"),
            "explanation_alignment": self._extract_score(payload, "explanation_alignment"),
        }
        verdict = payload.get("verdict", "")
        return PatchQualityEvaluation(scores=scores, verdict=verdict, raw=response)

    @staticmethod
    def _parse_json_response(response: str) -> Dict[str, object] | None:
        """
        LLM responses occasionally contain extra commentary or multiple JSON blobs.
        We attempt to extract the last valid JSON object.
        """
        candidates = []
        buf = ""
        brace_stack = []
        for ch in response:
            if ch == "{":
                brace_stack.append("{")
            if brace_stack:
                buf += ch
            if ch == "}":
                if brace_stack:
                    brace_stack.pop()
                if not brace_stack and buf:
                    candidates.append(buf)
                    buf = ""
        # try candidates from the end, common case latest is correct
        for snippet in reversed(candidates or [response]):
            snippet = snippet.strip()
            if not snippet:
                continue
            try:
                return json.loads(snippet)
            except json.JSONDecodeError:
                continue
        return None

    @staticmethod
    def _extract_score(payload: Dict[str, object], key: str) -> float:
        """
        LLMs occasionally nest scores inside helper objects such as {"score": 4.0, "reason": "..."}.
        This normalizes the value back into a float so downstream consumers do not crash.
        """
        value: object = payload.get(key)
        if value is None:
            scores_section = payload.get("scores")
            if isinstance(scores_section, dict):
                value = scores_section.get(key)

        if isinstance(value, dict):
            for nested_key in ("score", "value", "rating"):
                nested_value = value.get(nested_key)
                if nested_value is not None:
                    value = nested_value
                    break

        if isinstance(value, (int, float)):
            return float(value)

        if isinstance(value, str):
            normalized = value.strip().lower()
            if not normalized:
                return 0.0

            if normalized in TEXTUAL_SCORE_HINTS:
                return TEXTUAL_SCORE_HINTS[normalized]

            match = re.search(r"[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?", normalized)
            if match:
                try:
                    return float(match.group())
                except ValueError:
                    pass
            return 0.0

        return 0.0

    def _build_prompt(
        self,
        patch: PatchResult,
        E_bug: FormalBugExplanation | None,
        E_patch: FormalPatchExplanation | None,
        consistency: ConsistencyResult | None,
    ) -> str:
        eb_summary = E_bug.as_dict() if E_bug else {}
        ep_summary = E_patch.as_dict() if E_patch else {}
        consistency_dict = consistency.as_dict() if consistency else {}

        return json.dumps(
            {
                "task": "score_security_patch",
                "instructions": (
                    "Evaluate the provided patch for safety, completeness, regression risk, and how well it aligns "
                    "with the supplied E_bug/E_patch explanations. Scores must be floats 0-5. Provide an overall verdict."
                ),
                "patch": {
                    "method": patch.method,
                    "diff": patch.diff,
                    "notes": patch.notes,
                },
                "E_bug": eb_summary,
                "E_patch": ep_summary,
                "consistency": consistency_dict,
            },
            ensure_ascii=False,
        )
