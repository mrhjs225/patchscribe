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
## Evaluation Rubric for Security Patch Explanations

당신은 보안 설명을 평가하는 전문가입니다. 다음 기준으로 1-5점을 부여하세요.

### Accuracy (정확성) - 가중치 30%
취약점의 기술적 원인을 정확하게 식별하고 설명하는가?

**평가 시 확인사항**:
✓ CWE 유형과 일치하는가?
✓ 구체적 변수/조건을 언급하는가?
✓ 기술적으로 정확한가?
✓ 코드 위치(줄 번호 등)가 정확한가?

**5점**: 취약점의 기술적 원인을 정확히 식별. CWE 유형과 일치. 세부 조건 명시.
**4점**: 주요 원인 정확. 세부사항 일부 누락.
**3점**: 기본 원인은 맞으나 깊이 부족.
**2점**: 부분적으로만 맞음. 중요한 요소 누락.
**1점**: 원인을 잘못 식별하거나 관련 없는 내용.

### Completeness (완전성) - 가중치 25%
패치의 모든 변경사항을 설명하고 각 변경의 목적을 명시하는가?

**평가 시 확인사항**:
✓ 추가된 코드를 설명하는가?
✓ 변경된 로직을 설명하는가?
✓ 각 변경의 이유를 설명하는가?
✓ 부작용이나 엣지 케이스를 언급하는가?

**5점**: 패치의 모든 변경사항을 설명. 각 변경의 목적 명시.
**4점**: 주요 변경사항 대부분 다룸.
**3점**: 핵심 변경은 설명했으나 일부 누락.
**2점**: 변경사항의 절반 미만만 다룸.
**1점**: 거의 설명하지 않음.

### Causality (인과성) - 가중치 40% - **가장 중요**
명확한 인과 관계를 설명하는가? 단순 기술이 아닌 "왜"를 설명하는가?

**평가 시 확인사항**:
✓ "왜" 취약한지 설명하는가?
✓ "어떻게" 패치가 수정하는지 설명하는가?
✓ 인과 체인이 논리적인가?
✓ 반사실적 분석이 있는가? (예: "만약 패치가 없다면...")

**5점**: 명확한 인과 체인. "조건 X → 취약점 Y → 결과 Z" 형식. 반사실 추론 포함("만약 패치가 없다면...").
  예시: "포인터가 NULL일 때 → 역참조 발생 → 크래시. 패치는 NULL 검사를 추가하여 이 경로를 차단"
**4점**: 명확한 인과 관계. "왜"를 설명. 반사실은 없음.
  예시: "포인터가 NULL이면 역참조에서 크래시. 패치는 NULL 검사 추가"
**3점**: 기본적 인과 연결. "A 때문에 B" 수준.
  예시: "NULL 포인터 때문에 크래시"
**2점**: 약한 인과성. 주로 "무엇"만 설명.
  예시: "포인터가 NULL일 수 있음"
**1점**: 인과 관계 없음. 단순 나열.
  예시: "코드가 변경됨"

### Clarity (명료성) - 가중치 5%
명료하게 기술되었는가? 이해하기 쉬운가?

**5점**: 매우 명료. 잘 구조화. 전문가가 아니어도 이해 가능.
**4점**: 명료함. 이해하기 쉬움.
**3점**: 이해 가능하나 개선 여지 있음.
**2점**: 혼란스럽거나 구조 없음.
**1점**: 이해 불가능.

## 평가 예시

### 우수한 설명 (Accuracy: 5.0, Completeness: 5.0, Clarity: 5.0, Causality: 5.0)
"취약점은 43번 줄에서 발생합니다. 'authkey' 포인터를 NULL 검사 없이 역참조합니다.
40번 줄의 검증은 authkey가 정수로서 0이 아닌지만 확인하고 포인터로서 NULL인지는
확인하지 않습니다. authkey가 NULL(0x0)일 때, 정수 검사는 통과하지만 역참조에서
크래시가 발생합니다. 패치는 역참조 전에 'if (!authkey)' 검사를 명시적으로 추가하여
이 안전하지 않은 코드 경로의 실행을 방지합니다."

우수한 이유:
- 명확한 인과 체인: 검증 버그 → 검사 통과 → NULL 역참조
- 왜 버그가 발생하는지 설명 (정수 vs 포인터 검사)
- 패치가 어떻게 인과 체인을 끊는지 설명
- 자연스러운 언어, 읽기 쉬움
- 기술적으로 정확함

### 부족한 설명 (Accuracy: 3.0, Completeness: 2.0, Clarity: 3.0, Causality: 2.0)
"코드에 NULL 포인터 버그가 있었습니다. 패치는 NULL 검사를 추가합니다.
이것은 포인터를 사용하기 전에 NULL이 아닌지 확인하여 취약점을 수정합니다."

부족한 이유:
- 왜 버그가 발생하는지 설명 없음
- 인과 메커니즘 설명 없음
- 중요한 세부사항 누락 (줄 번호, 컨텍스트)
- 표면적 인과성

---

JSON 형식으로 응답하세요:
{
  "accuracy": <1.0-5.0>,
  "accuracy_reasoning": "<간단한 이유>",
  "completeness": <1.0-5.0>,
  "completeness_reasoning": "<간단한 이유>",
  "causality": <1.0-5.0>,
  "causality_reasoning": "<간단한 이유>",
  "clarity": <1.0-5.0>,
  "clarity_reasoning": "<간단한 이유>"
}
"""

        instructions = (
            "당신은 보안 패치 설명을 평가하는 전문가입니다.\n"
            "아래 루브릭을 사용하여 1-5점 척도로 점수를 부여하세요.\n"
            "평가 시 체크리스트를 참고하여 각 항목을 확인하세요.\n"
            "반드시 유효한 JSON만 출력하세요. 다른 텍스트는 포함하지 마세요.\n\n"
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
