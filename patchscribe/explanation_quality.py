"""
Explanation quality instrumentation for checklist coverage and optional LLM judging.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from .explanation import ExplanationBundle
from .llm import LLMClient, LLMUnavailable


@dataclass
class ExplanationEvaluation:
    checklist_coverage: float
    checklist_hits: Dict[str, bool]
    missing_items: List[str]
    llm_scores: Optional[Dict[str, float]] = None
    llm_raw: Optional[str] = None


class ExplanationEvaluator:
    """
    Assess explanation quality along two axes:
    1. Checklist coverage – verifies essential elements are present.
    2. Optional LLM judge – asks a private endpoint to score accuracy/clarity/causality.
    """

    def __init__(self, llm_client: LLMClient | None = None) -> None:
        self.llm_client = llm_client or LLMClient()

    def evaluate(
        self,
        bundle: ExplanationBundle,
        *,
        case: Dict[str, object],
        use_llm: bool = True,
    ) -> ExplanationEvaluation:
        text = bundle.natural_llm or bundle.natural_template or ""
        checklist = self._compute_checklist(bundle, case, text)
        coverage = sum(checklist.values()) / len(checklist) if checklist else 0.0
        missing = [name for name, ok in checklist.items() if not ok]

        llm_scores: Optional[Dict[str, float]] = None
        raw_response: Optional[str] = None
        if use_llm and self.llm_client.available() and text.strip():
            try:
                llm_scores, raw_response = self._judge_with_llm(text, case)
            except LLMUnavailable:
                llm_scores = None

        return ExplanationEvaluation(
            checklist_coverage=coverage,
            checklist_hits=checklist,
            missing_items=missing,
            llm_scores=llm_scores,
            llm_raw=raw_response,
        )

    def _compute_checklist(
        self,
        bundle: ExplanationBundle,
        case: Dict[str, object],
        text: str,
    ) -> Dict[str, bool]:
        vuln_line = case.get("vuln_line")
        cwe_id = case.get("cwe_id")
        signature = case.get("signature", "")
        checklist: Dict[str, bool] = {
            "mentions_location": bool(vuln_line and f"line {vuln_line}" in text),
            "mentions_cwe": bool(cwe_id and str(cwe_id) in text),
            "mentions_signature": bool(signature and signature in text),
            "describes_fix": bool(re.search(r"How the patch|패치가", text)),
            "describes_reason": bool(re.search(r"Why this works|왜", text)),
        }
        # Prompt context should surface causal chain; ensure at least one predecessor mentioned.
        causal_context = bundle.prompt_context or ""
        if "Causal chain" in causal_context:
            required_terms = [
                line.split("- ", 1)[1]
                for line in causal_context.splitlines()
                if line.strip().startswith("- ") and "Causal chain" not in line
            ]
            if required_terms:
                checklist["mentions_causal_parent"] = any(
                    term and term in text for term in required_terms
                )
            else:
                checklist["mentions_causal_parent"] = False
        else:
            checklist["mentions_causal_parent"] = bool(
                re.search(r"Root cause|원인", text)
            )
        return checklist

    def _judge_with_llm(
        self,
        explanation: str,
        case: Dict[str, object],
    ) -> tuple[Dict[str, float], str]:
        prompt = self._llm_judge_prompt(explanation, case)
        response = self.llm_client.score_explanation(prompt)
        if not response:
            raise LLMUnavailable("LLM judge returned empty response")
        try:
            parsed = json.loads(response)
        except json.JSONDecodeError:
            raise LLMUnavailable("LLM judge did not return JSON") from None
        scores = {
            "accuracy": float(parsed.get("accuracy", 0.0)),
            "clarity": float(parsed.get("clarity", 0.0)),
            "causality": float(parsed.get("causality", 0.0)),
        }
        return scores, response

    @staticmethod
    def _llm_judge_prompt(explanation: str, case: Dict[str, object]) -> str:
        vuln_line = case.get("vuln_line")
        signature = case.get("signature", "(unknown signature)")
        cwe_id = case.get("cwe_id", "(unknown CWE)")
        metadata = json.dumps(
            {
                "vuln_line": vuln_line,
                "signature": signature,
                "cwe_id": cwe_id,
            },
            ensure_ascii=False,
        )
        instructions = (
            "당신은 보안 패치 설명을 평가하는 심판 모델입니다. "
            "입력으로 주어지는 JSON 메타데이터와 설명 텍스트를 참고하여 "
            "정확성(accuracy), 명료성(clarity), 인과 정합성(causality)을 1~5 실수 점수로 평가하고 "
            "다음 형식의 JSON만 출력하세요:\n"
            '{"accuracy": <float>, "clarity": <float>, "causality": <float>, "reason": "<short korean summary>"}'
        )
        return (
            instructions
            + "\n\n"
            + f"메타데이터: {metadata}\n"
            + f"설명 텍스트:\n{explanation}"
        )
