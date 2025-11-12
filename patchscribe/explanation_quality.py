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
            "describes_fix": bool(re.search(r"How the patch|patch", text)),
            "describes_reason": bool(re.search(r"Why this works|why", text)),
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
                re.search(r"Root cause|cause", text)
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
## Evaluation Rubric for Security Patch Explanations

You are an expert evaluating security patch explanations. Score each criterion on a 1-5 scale.

### Accuracy - Weight 30%
Does it accurately identify and explain the technical root cause of the vulnerability?

**Checklist**:
- Matches the CWE type?
- Mentions specific variables/conditions?
- Technically correct?
- Correct code location (line numbers)?

**5 points**: Accurately identifies technical root cause. Matches CWE type. Specifies detailed conditions.
**4 points**: Main cause correct. Some details missing.
**3 points**: Basic cause correct but lacks depth.
**2 points**: Partially correct. Important elements missing.
**1 point**: Misidentifies cause or provides irrelevant information.

### Completeness - Weight 25%
Does it explain all patch changes and specify the purpose of each change?

**Checklist**:
- Explains added code?
- Explains changed logic?
- Explains reason for each change?
- Mentions side effects or edge cases?

**5 points**: Explains all patch changes. Specifies purpose of each change.
**4 points**: Covers most major changes.
**3 points**: Explains core changes but some missing.
**2 points**: Covers less than half of changes.
**1 point**: Minimal explanation.

### Causality - Weight 40% - **MOST IMPORTANT**
Does it explain clear causal relationships? Does it explain "why" rather than just describing "what"?

**Checklist**:
- Explains "why" it's vulnerable?
- Explains "how" the patch fixes it?
- Is the causal chain logical?
- Includes counterfactual analysis? (e.g., "Without the patch...")

**5 points**: Clear causal chain. "Condition X → Vulnerability Y → Effect Z" format. Includes counterfactual reasoning ("Without the patch...").
  Example: "When pointer is NULL → dereference occurs → crash. Patch adds NULL check to block this path"
**4 points**: Clear causality. Explains "why". No counterfactual.
  Example: "If pointer is NULL, dereference causes crash. Patch adds NULL check"
**3 points**: Basic causal connection. "A causes B" level.
  Example: "NULL pointer causes crash"
**2 points**: Weak causality. Mostly describes "what".
  Example: "Pointer can be NULL"
**1 point**: No causality. Simple enumeration.
  Example: "Code was changed"

### Clarity - Weight 5%
Is it clearly written? Is it easy to understand?

**5 points**: Very clear. Well-structured. Understandable even for non-experts.
**4 points**: Clear. Easy to understand.
**3 points**: Understandable but room for improvement.
**2 points**: Confusing or lacks structure.
**1 point**: Incomprehensible.

## Evaluation Examples

### Good Explanation (Accuracy: 5.0, Completeness: 5.0, Clarity: 5.0, Causality: 5.0)
"The vulnerability occurs at line 43, where the 'authkey' pointer is dereferenced without a NULL check.
The validation at line 40 only checks if authkey is non-zero as an integer, not whether it's NULL as a pointer.
When authkey is NULL (0x0), the integer check passes but dereferencing causes a crash.
The patch explicitly adds an 'if (!authkey)' check before dereferencing to prevent execution of this unsafe code path."

Why it's good:
- Clear causal chain: validation bug → check passes → NULL dereference
- Explains why the bug occurs (integer vs pointer check)
- Explains how patch breaks the causal chain
- Natural language, easy to read
- Technically accurate

### Poor Explanation (Accuracy: 3.0, Completeness: 2.0, Clarity: 3.0, Causality: 2.0)
"The code had a NULL pointer bug. The patch adds a NULL check.
This fixes the vulnerability by checking if the pointer is not NULL before using it."

Why it's poor:
- No explanation of why the bug occurs
- No explanation of causal mechanism
- Missing important details (line numbers, context)
- Superficial causality

---

Respond in JSON format:
{
  "accuracy": <1.0-5.0>,
  "accuracy_reasoning": "<brief explanation>",
  "completeness": <1.0-5.0>,
  "completeness_reasoning": "<brief explanation>",
  "causality": <1.0-5.0>,
  "causality_reasoning": "<brief explanation>",
  "clarity": <1.0-5.0>,
  "clarity_reasoning": "<brief explanation>"
}
"""

        instructions = (
            "You are an expert evaluating security patch explanations.\n"
            "Use the rubric below to assign scores on a 1-5 scale.\n"
            "Refer to the checklist when evaluating each criterion.\n"
            "Output only valid JSON. Do not include any other text.\n\n"
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
