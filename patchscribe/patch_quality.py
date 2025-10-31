"""
GPT-based patch quality evaluation utilities.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, Optional

from .llm import LLMClient, LLMUnavailable
from .formal_spec import FormalBugExplanation, FormalPatchExplanation
from .patch import PatchResult
from .verification import VerificationResult


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
        verification: VerificationResult | None,
    ) -> PatchQualityEvaluation:
        if not self.llm.available():
            return PatchQualityEvaluation(scores={}, verdict="LLM unavailable")

        prompt = self._build_prompt(patch, E_bug, E_patch, verification)
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
            "safety": float(payload.get("safety", 0.0)),
            "completeness": float(payload.get("completeness", 0.0)),
            "regression_risk": float(payload.get("regression_risk", 0.0)),
            "explanation_alignment": float(payload.get("explanation_alignment", 0.0)),
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

    def _build_prompt(
        self,
        patch: PatchResult,
        E_bug: FormalBugExplanation | None,
        E_patch: FormalPatchExplanation | None,
        verification: VerificationResult | None,
    ) -> str:
        eb_summary = E_bug.as_dict() if E_bug else {}
        ep_summary = E_patch.as_dict() if E_patch else {}
        verification_dict = verification.as_dict() if verification else {}

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
                "verification": verification_dict,
            },
            ensure_ascii=False,
        )
