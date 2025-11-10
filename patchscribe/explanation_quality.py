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
            "completeness": float(parsed.get("completeness", 0.0)),
            "clarity": float(parsed.get("clarity", 0.0)),
            "causality": float(parsed.get("causality", 0.0)),
        }
        return scores, response

    @staticmethod
    def _llm_judge_prompt(explanation: str, case: Dict[str, object]) -> str:
        """Generate judge prompt for evaluating developer-facing explanations"""
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

        rubric = """
## Evaluation Rubric for Developer-Facing Security Patch Explanations

You are evaluating explanations intended for SOFTWARE DEVELOPERS, not formal verification systems.
Good explanations use NATURAL LANGUAGE while demonstrating CAUSAL REASONING.

### Accuracy (1-5)
- Does the explanation correctly identify the root cause?
- Are the code details (line numbers, variable names) accurate?
- Does it correctly describe what the patch changes?

**5.0**: Perfect accuracy in all technical details
**4.0**: Accurate with minor imprecisions
**3.0**: Generally correct but missing some details
**2.0**: Contains significant errors
**1.0**: Mostly incorrect

### Completeness (1-5)
- Does it explain WHAT the vulnerability is?
- Does it explain WHY the vulnerability occurs?
- Does it explain HOW the patch fixes it?
- Does it mention any side effects or edge cases?

**5.0**: Comprehensive coverage of all aspects
**4.0**: Covers main aspects well
**3.0**: Covers basics but missing important elements
**2.0**: Incomplete coverage
**1.0**: Extremely incomplete

### Clarity (1-5) - WEIGHT: 30%
- Is it written in clear, natural language?
- Would a developer easily understand it?
- Is it well-structured and easy to follow?
- Does it avoid unnecessary jargon or formal notation?

**5.0**: Exceptionally clear and easy to read
**4.0**: Clear and well-organized
**3.0**: Understandable but could be clearer
**2.0**: Confusing or poorly structured
**1.0**: Very difficult to understand

### Causality (1-5) - WEIGHT: 40% - MOST IMPORTANT
This measures the DEPTH OF CAUSAL REASONING, not the use of formal notation.

**5.0 - Deep Causal Understanding**:
- Explains the CAUSAL CHAIN from preconditions to vulnerability
- Shows understanding of WHY certain conditions enable the bug
- Explains HOW the patch BREAKS the causal chain
- Demonstrates systematic reasoning about cause-effect relationships
- Uses phrases like: "because", "this enables", "which leads to", "by preventing"

**4.0 - Strong Causal Reasoning**:
- Clear explanation of cause and effect
- Shows understanding of causal flow
- Explains the mechanism of the fix

**3.0 - Basic Causal Reasoning**:
- Identifies causes and effects
- Some explanation of relationships
- May be superficial

**2.0 - Weak Causality**:
- Mostly descriptive ("the code does X")
- Vague causal claims
- Doesn't explain mechanisms

**1.0 - No Meaningful Causality**:
- Only describes what changed
- No causal reasoning

## Critical Evaluation Criteria

**DO reward:**
- Clear natural language explanations of causal mechanisms
- Systematic reasoning showing understanding of vulnerability conditions
- Explanations that show how patch prevents the causal path

**DO NOT reward:**
- Use of formal notation (V_p1, equations) - these reduce clarity
- Technical jargon without explanation
- Complex language when simple would work

**DO NOT penalize:**
- Lack of formal notation (we want natural language!)
- Simple language (clarity is a virtue)

## Example Evaluations

### EXCELLENT (Accuracy: 5.0, Completeness: 5.0, Clarity: 5.0, Causality: 5.0)
"The vulnerability occurs at line 43 where the code dereferences the 'authkey'
pointer without checking if it's NULL. This happens because the validation at
line 40 only checks if authkey is non-zero as an integer, not as a pointer.
When authkey is NULL (0x0), it passes the integer check but causes a NULL
dereference. The patch fixes this by explicitly checking 'if (!authkey)' before
the dereference, which prevents the unsafe code path from executing."

Why excellent:
- Clear cause-effect chain: validation bug → passes check → NULL deref
- Explains WHY the bug occurs (integer vs pointer check)
- Shows HOW patch breaks causal chain
- Natural language, easy to read
- Technically accurate

### POOR (Accuracy: 3.0, Completeness: 2.0, Clarity: 3.0, Causality: 2.0)
"The code had a NULL pointer bug. The patch adds a NULL check. This fixes
the vulnerability by making sure the pointer is not NULL before use."

Why poor:
- No explanation of WHY bug occurs
- Doesn't explain the causal mechanism
- Missing important details (line numbers, context)
- Superficial causality
"""

        instructions = (
            "You are evaluating a security patch explanation intended for developers.\n"
            "Use the rubric below to score on a 1-5 scale.\n"
            "Output ONLY valid JSON:\n"
            '{"accuracy": <float>, "completeness": <float>, "clarity": <float>, '
            '"causality": <float>, "reason": "<brief explanation of scores>"}\n\n'
        )

        return (
            instructions + rubric + "\n\n"
            + f"Case Metadata: {metadata}\n\n"
            + f"Explanation to Evaluate:\n{explanation}"
        )

    def _build_judge_prompt(self, explanation: str, case: Dict[str, object]) -> str:
        """Public wrapper for building judge prompts (used by batch_judge script)"""
        return self._llm_judge_prompt(explanation, case)

    def _parse_llm_scores(self, response: str) -> Dict[str, float]:
        """Parse LLM judge response into scores (used by batch_judge script)"""
        try:
            parsed = json.loads(response)
            return {
                "accuracy": float(parsed.get("accuracy", 0.0)),
                "completeness": float(parsed.get("completeness", 0.0)),
                "clarity": float(parsed.get("clarity", 0.0)),
                "causality": float(parsed.get("causality", 0.0)),
            }
        except (json.JSONDecodeError, ValueError, TypeError):
            return {}
