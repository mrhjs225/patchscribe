"""
Actionable Specification Generator

This module transforms formal PCG/SCM specifications into actionable,
LLM-friendly instructions. The goal is to make formal specifications
practically useful for patch generation by converting them into clear,
executable guidance.

Theory: Task Decomposition & Procedural Guidance (Anderson, 1983; Sweller, 1988)
- Complex formal specifications → Concrete procedural steps
- Maintains formal rigor while improving LLM comprehension
"""
from __future__ import annotations

from typing import Dict, List, Optional
from dataclasses import dataclass

from .intervention import Intervention, InterventionSpec
from .formal_spec import CausalPath, FormalBugExplanation


@dataclass
class ActionableInstruction:
    """A single actionable instruction derived from formal spec"""
    line_number: int
    action_type: str  # "add_check", "sanitize", "validate", "guard"
    description: str  # Human-readable, concrete instruction
    rationale: str  # Why this action addresses the vulnerability
    code_hint: str = ""  # Optional code-level hint


class ActionableSpecGenerator:
    """
    Converts formal interventions into actionable instructions for LLMs.

    Key principle: Transform declarative formal specs (YAML) into
    procedural instructions (natural language with technical precision).
    """

    def __init__(self):
        # Mapping of intervention patterns to actionable descriptions
        self._action_templates = self._initialize_templates()

    def _initialize_templates(self) -> Dict[str, Dict[str, str]]:
        """Initialize action templates for different intervention types"""
        return {
            "boundary_check": {
                "description": "배열/버퍼 접근 전에 경계 검사를 추가하세요",
                "description_with_location": "줄 {line} 근처에서 배열/버퍼 접근 전에 경계 검사를 추가하세요",
                "guideline": "배열 인덱스가 사용되기 전에 검증이 필요합니다 (줄 {line} 근처 참고)",
                "rationale": "경계를 벗어난 접근을 방지하여 버퍼 오버플로우를 차단합니다",
                "code_hint": "조건: {variable} < {bound} 또는 {variable} >= 0 && {variable} < {bound}"
            },
            "null_check": {
                "description": "포인터 사용 전에 NULL 검사를 추가하세요",
                "description_with_location": "줄 {line} 근처에서 포인터 사용 전에 NULL 검사를 추가하세요",
                "guideline": "포인터 역참조 전에 NULL 검사가 필요합니다 (줄 {line} 근처 참고)",
                "rationale": "NULL 포인터 역참조를 방지합니다",
                "code_hint": "조건: {variable} != NULL"
            },
            "length_check": {
                "description": "버퍼 쓰기 전에 충분한 공간이 있는지 확인하세요",
                "description_with_location": "줄 {line} 근처에서 버퍼 크기를 확인하세요",
                "guideline": "버퍼 쓰기 작업 전에 크기 검증이 필요합니다 (줄 {line} 근처 참고)",
                "rationale": "버퍼 오버플로우를 방지하기 위해 쓰기 전에 충분한 공간이 있는지 확인합니다",
                "code_hint": "조건: available_space >= required_space"
            },
            "sanitize": {
                "description": "입력값을 검증하고 정제하세요",
                "description_with_location": "줄 {line} 근처에서 입력값을 검증하고 정제하세요",
                "guideline": "외부 입력이 사용되기 전에 검증이 필요합니다 (줄 {line} 근처 참고)",
                "rationale": "유효하지 않거나 악의적인 입력을 차단합니다",
                "code_hint": "유효하지 않은 값은 거부하거나 안전한 기본값으로 대체하세요"
            },
            "range_check": {
                "description": "값이 유효한 범위 내에 있는지 확인하세요",
                "description_with_location": "줄 {line} 근처에서 값이 유효한 범위 내에 있는지 확인하세요",
                "guideline": "값이 사용되기 전에 범위 검증이 필요합니다 (줄 {line} 근처 참고)",
                "rationale": "범위를 벗어난 값 사용을 방지합니다",
                "code_hint": "조건: min_value <= {variable} <= max_value"
            },
            "overflow_check": {
                "description": "정수 오버플로우 가능성을 확인하세요",
                "description_with_location": "줄 {line} 근처에서 정수 오버플로우 가능성을 확인하세요",
                "guideline": "산술 연산 전에 오버플로우 검사가 필요합니다 (줄 {line} 근처 참고)",
                "rationale": "산술 연산 결과가 타입의 범위를 벗어나지 않도록 합니다",
                "code_hint": "연산 전에 결과값이 MAX/MIN을 초과하지 않는지 확인하세요"
            },
            "size_validation": {
                "description": "크기 인자가 음수가 아닌지 확인하세요",
                "description_with_location": "줄 {line} 근처에서 크기 인자가 음수가 아닌지 확인하세요",
                "guideline": "크기 값이 사용되기 전에 유효성 검증이 필요합니다 (줄 {line} 근처 참고)",
                "rationale": "음수 크기 값으로 인한 예상치 못한 동작을 방지합니다",
                "code_hint": "조건: size >= 0"
            },
            "guard": {
                "description": "안전 조건을 만족하지 않으면 조기 반환하세요",
                "description_with_location": "줄 {line} 근처에서 안전 조건을 만족하지 않으면 조기 반환하세요",
                "guideline": "위험한 코드 경로 진입 전에 안전 검사가 필요합니다 (줄 {line} 근처 참고)",
                "rationale": "위험한 코드 경로의 실행을 방지합니다",
                "code_hint": "if (unsafe_condition) {{ return error_code; }}"
            }
        }

    def translate_intervention(
        self,
        intervention: Intervention,
        use_abstract_guideline: bool = False
    ) -> ActionableInstruction:
        """
        Convert a single Intervention to an ActionableInstruction.

        Args:
            intervention: Formal intervention from PCG/SCM analysis
            use_abstract_guideline: If True, use abstract guidelines instead of
                                   specific locations (for C3). If False, use
                                   concrete locations (for C4).

        Returns:
            ActionableInstruction with concrete, executable guidance
        """
        # Extract action type from enforce string or semantic_action
        action_type = self._infer_action_type(intervention)

        # Get template
        template = self._action_templates.get(action_type, self._action_templates["guard"])

        # Extract variables and constraints from enforcement
        variables = self._extract_variables(intervention)
        constraints = self._extract_constraints(intervention)

        # Choose description format based on abstraction level
        if use_abstract_guideline:
            # C3: Abstract guideline (location as hint only)
            description_template = template.get("guideline", template["description"])
        else:
            # C4: Concrete location (location as requirement)
            description_template = template.get("description_with_location", template["description"])

        # Format description
        description = description_template.format(
            line=intervention.target_line,
            variable=variables.get("target", "변수"),
            bound=variables.get("bound", "배열 크기")
        )

        # Format rationale
        rationale = intervention.rationale if intervention.rationale else template["rationale"]

        # Format code hint
        code_hint = template["code_hint"].format(
            variable=variables.get("target", "var"),
            bound=variables.get("bound", "limit")
        )

        return ActionableInstruction(
            line_number=intervention.target_line,
            action_type=action_type,
            description=description,
            rationale=rationale,
            code_hint=code_hint
        )

    def _infer_action_type(self, intervention: Intervention) -> str:
        """Infer action type from intervention properties"""
        enforce = intervention.enforce.lower()
        semantic = intervention.semantic_action.lower()

        # Check semantic_action first (more specific)
        if "null" in semantic:
            return "null_check"
        elif "boundary" in semantic or "bound" in semantic:
            return "boundary_check"
        elif "length" in semantic or "size" in semantic:
            return "length_check"
        elif "sanitize" in semantic or "validate" in semantic:
            return "sanitize"
        elif "range" in semantic:
            return "range_check"
        elif "overflow" in semantic:
            return "overflow_check"

        # Fall back to enforce string
        if "null" in enforce:
            return "null_check"
        elif "oob" in enforce or "bound" in enforce or "index" in enforce:
            return "boundary_check"
        elif "size" in enforce or "len" in enforce:
            return "length_check"
        elif "overflow" in enforce:
            return "overflow_check"

        # Default
        return "guard"

    def _extract_variables(self, intervention: Intervention) -> Dict[str, str]:
        """Extract variable names from intervention"""
        variables = {}

        # Get variable name if available
        if intervention.variable_name:
            variables["target"] = intervention.variable_name

        # Try to extract from enforce string
        enforce = intervention.enforce
        if "NOT" in enforce:
            # Pattern: "ENFORCE NOT var_name"
            parts = enforce.split()
            if len(parts) >= 3:
                variables["target"] = parts[2]

        return variables

    def _extract_constraints(self, intervention: Intervention) -> Dict[str, str]:
        """Extract constraint expressions from intervention"""
        constraints = {}

        # Parse from enforce or semantic_action
        # This is a simple parser; can be extended

        return constraints

    def translate_causal_path(self, path: CausalPath) -> str:
        """
        Convert a causal path to natural language explanation.

        Args:
            path: CausalPath from E_bug

        Returns:
            Human-readable explanation of the vulnerability path
        """
        if not path.nodes:
            return path.description

        # Build structured representation
        explanation_parts = []

        # Format 1: Visual flow diagram
        explanation_parts.append("**인과 흐름 다이어그램:**")
        flow = " → ".join([self._humanize_node(node) for node in path.nodes])
        explanation_parts.append(f"  {flow}\n")

        # Format 2: Detailed step-by-step
        explanation_parts.append("**단계별 분석:**")
        for i, node in enumerate(path.nodes, 1):
            humanized = self._humanize_node(node)
            explanation_parts.append(f"  {i}. {humanized}")

            # Add technical details if available
            if hasattr(path, 'node_details') and node in path.node_details:
                details = path.node_details[node]
                if details.get('location'):
                    explanation_parts.append(f"     - 위치: {details['location']}")
                if details.get('variable'):
                    explanation_parts.append(f"     - 변수: {details['variable']}")

        # Format 3: Summary and implications
        explanation_parts.append(f"\n**설명:** {path.description}")
        explanation_parts.append("\n**패치 요구사항:** 위 인과 경로 중 최소 한 단계를 차단하여 취약점 발현을 방지해야 합니다.")

        return "\n".join(explanation_parts)

    def _humanize_node(self, node_id: str) -> str:
        """Convert technical node ID to human-readable description"""
        # Mapping of common technical terms to Korean
        humanization_map = {
            "unchecked_input": "검증되지 않은 입력",
            "buffer_overflow": "버퍼 오버플로우",
            "null_deref": "NULL 포인터 역참조",
            "oob_access": "배열 경계 초과 접근",
            "oob_write": "경계 밖 쓰기",
            "oob_read": "경계 밖 읽기",
            "memory_corruption": "메모리 손상",
            "use_after_free": "해제 후 사용",
            "double_free": "이중 해제",
            "integer_overflow": "정수 오버플로우",
            "format_string": "포맷 스트링 취약점",
            "injection": "인젝션 공격",
            "unvalidated": "검증 안됨",
            "untrusted": "신뢰할 수 없는",
            "tainted": "오염된",
            "unchecked": "확인 안됨",
        }

        # Try exact match first
        if node_id in humanization_map:
            return humanization_map[node_id]

        # Try partial matches
        for key, value in humanization_map.items():
            if key in node_id.lower():
                return value

        # If no match, return cleaned version
        return node_id.replace("_", " ").title()

    def generate_intervention_analysis(self, interventions: List[Intervention]) -> str:
        """
        Generate detailed analysis of intervention points and rationale.

        Args:
            interventions: List of interventions to analyze

        Returns:
            Detailed explanation of why these interventions are chosen
        """
        if not interventions:
            return "명시적인 수정 지침이 없습니다."

        analysis_parts = []
        analysis_parts.append("**개입 지점 분석:**\n")

        for i, intv in enumerate(interventions, 1):
            action_type = self._infer_action_type(intv)
            type_names = {
                "boundary_check": "경계 검사", "null_check": "NULL 검사",
                "length_check": "길이 검사", "sanitize": "입력 검증",
                "range_check": "범위 검사", "overflow_check": "오버플로우 검사",
                "size_validation": "크기 검증", "guard": "안전 가드"
            }
            action_name = type_names.get(action_type, action_type)

            analysis_parts.append(f"{i}. **개입 위치**: 줄 {intv.target_line} 근처")
            analysis_parts.append(f"   - **개입 유형**: {action_name}")
            analysis_parts.append(f"   - **이유**: {intv.rationale if intv.rationale else '인과 경로를 차단하기 위함'}")
            analysis_parts.append(f"   - **최소 개입 원칙**: 이 지점은 취약점 경로를 차단하는 가장 효과적인 위치입니다.\n")

        return "\n".join(analysis_parts)

    def generate_intervention_summary(self, interventions: List[Intervention]) -> str:
        """
        Generate a high-level summary of all interventions.

        Args:
            interventions: List of interventions to summarize

        Returns:
            Concise summary of what needs to be done
        """
        if not interventions:
            return "명시적인 수정 지침이 없습니다."

        # Count intervention types
        type_counts = {}
        for intv in interventions:
            action_type = self._infer_action_type(intv)
            type_counts[action_type] = type_counts.get(action_type, 0) + 1

        # Generate summary
        summary_parts = []

        type_names = {
            "boundary_check": "경계 검사",
            "null_check": "NULL 검사",
            "length_check": "길이 검사",
            "sanitize": "입력 검증",
            "range_check": "범위 검사",
            "overflow_check": "오버플로우 검사",
            "size_validation": "크기 검증",
            "guard": "안전 가드"
        }

        for action_type, count in type_counts.items():
            name = type_names.get(action_type, action_type)
            summary_parts.append(f"{name} {count}개")

        summary = "필요한 수정: " + ", ".join(summary_parts)
        return summary


def translate_intervention_spec(spec: InterventionSpec) -> List[ActionableInstruction]:
    """
    Convenience function to translate an entire InterventionSpec.

    Args:
        spec: InterventionSpec from pipeline

    Returns:
        List of actionable instructions
    """
    generator = ActionableSpecGenerator()
    return [generator.translate_intervention(intv) for intv in spec.interventions]
