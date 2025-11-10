"""
Specification Builder for Condition-based Experiments

This module generates specifications at different detail levels (C1-C4)
to support systematic evaluation of how information granularity affects
patch generation quality.

Theory: Information Gradation (Kalyuga et al., 2003)
- Progressive disclosure of information improves learning and performance
- Each condition provides incrementally more specific guidance
"""
from __future__ import annotations

from typing import Dict, List, Optional
from dataclasses import dataclass

from .actionable_spec import ActionableSpecGenerator, ActionableInstruction
from .intervention import InterventionSpec
from .formal_spec import FormalBugExplanation


@dataclass
class SpecificationLevel:
    """Represents a specification at a particular detail level"""
    level: str  # 'c1', 'c2', 'c3', 'c4'
    has_cwe_info: bool
    has_safety_property: bool
    has_target_locations: bool
    has_actionable_instructions: bool
    has_causal_analysis: bool
    content: str  # The formatted specification text


class SpecificationBuilder:
    """
    Builds specifications at different levels of detail for experimental conditions.

    Condition levels:
    - C1: No specification (baseline)
    - C2: High-level abstract (CWE + safety property)
    - C3: Targeted (+ specific locations and action types)
    - C4: Complete (+ causal analysis and detailed instructions)
    """

    def __init__(self):
        self.action_generator = ActionableSpecGenerator()

    def build_for_condition(
        self,
        condition: str,
        cwe: str,
        cwe_description: str,
        safety_property: str,
        intervention_spec: Optional[InterventionSpec] = None,
        ebug: Optional[FormalBugExplanation] = None,
        natural_context: Optional[str] = None,
    ) -> Optional[SpecificationLevel]:
        """
        Build specification for a given condition.

        Args:
            condition: One of 'c1', 'c2', 'c3', 'c4'
            cwe: CWE identifier (e.g., 'CWE-787')
            cwe_description: Human-readable CWE description
            safety_property: Required safety property
            intervention_spec: Intervention specification (for C3/C4)
            ebug: Formal bug explanation (for C4)
            natural_context: Natural language context (for C2)

        Returns:
            SpecificationLevel or None (for C1)
        """
        condition = condition.lower()

        if condition == 'c1':
            return self._build_c1()
        elif condition == 'c2':
            return self._build_c2(cwe, cwe_description, safety_property, natural_context)
        elif condition == 'c3':
            return self._build_c3(
                cwe, cwe_description, safety_property, intervention_spec, natural_context
            )
        elif condition == 'c4':
            return self._build_c4(
                cwe, cwe_description, safety_property, intervention_spec, ebug, natural_context
            )
        else:
            raise ValueError(f"Unknown condition: {condition}")

    def _build_c1(self) -> None:
        """C1: No specification (baseline)"""
        return None

    def _build_c2(
        self,
        cwe: str,
        cwe_description: str,
        safety_property: str,
        natural_context: Optional[str]
    ) -> SpecificationLevel:
        """
        C2: Abstract specification (high-level only)

        Provides:
        - CWE type
        - Safety property
        - Optional natural language hint
        """
        content_parts = ["## 보안 요구사항\n"]

        content_parts.append(f"**취약점 유형**: {cwe}")
        if cwe_description:
            content_parts.append(f"  - 설명: {cwe_description}")

        content_parts.append(f"\n**필요한 보호**: {safety_property}")

        if natural_context:
            content_parts.append(f"\n**참고 정보**:\n{natural_context}")

        content = "\n".join(content_parts)

        return SpecificationLevel(
            level='c2',
            has_cwe_info=True,
            has_safety_property=True,
            has_target_locations=False,
            has_actionable_instructions=False,
            has_causal_analysis=False,
            content=content
        )

    def _build_c3(
        self,
        cwe: str,
        cwe_description: str,
        safety_property: str,
        intervention_spec: Optional[InterventionSpec],
        natural_context: Optional[str]
    ) -> SpecificationLevel:
        """
        C3: Targeted specification

        Provides:
        - CWE type
        - Safety property
        - Specific target locations
        - Actionable instructions (what to do, where)
        """
        content_parts = ["## 보안 요구사항\n"]

        content_parts.append(f"**취약점 유형**: {cwe}")
        if cwe_description:
            content_parts.append(f"  - 설명: {cwe_description}")

        content_parts.append(f"\n**필요한 보호**: {safety_property}")

        # Add actionable instructions
        if intervention_spec and intervention_spec.interventions:
            content_parts.append("\n## 수정 지시사항\n")
            content_parts.append("다음 변경사항을 코드에 적용하세요:\n")

            instructions = []
            for intervention in intervention_spec.interventions:
                action = self.action_generator.translate_intervention(intervention)
                instructions.append(self._format_instruction(action, include_rationale=False))

            content_parts.append("\n".join(instructions))

            # Add summary
            summary = self.action_generator.generate_intervention_summary(
                intervention_spec.interventions
            )
            content_parts.append(f"\n**요약**: {summary}")

        # Optional natural context
        if natural_context:
            content_parts.append(f"\n## 참고 정보\n{natural_context}")

        content = "\n".join(content_parts)

        return SpecificationLevel(
            level='c3',
            has_cwe_info=True,
            has_safety_property=True,
            has_target_locations=True,
            has_actionable_instructions=True,
            has_causal_analysis=False,
            content=content
        )

    def _build_c4(
        self,
        cwe: str,
        cwe_description: str,
        safety_property: str,
        intervention_spec: Optional[InterventionSpec],
        ebug: Optional[FormalBugExplanation],
        natural_context: Optional[str]
    ) -> SpecificationLevel:
        """
        C4: Complete specification

        Provides:
        - CWE type
        - Safety property
        - Causal path analysis (from E_bug)
        - Detailed actionable instructions with rationale
        - Consistency requirements
        """
        content_parts = []

        # Causal analysis first (most important for C4)
        if ebug and ebug.causal_paths:
            content_parts.append("## 취약점 인과 분석\n")

            for path in ebug.causal_paths:
                path_explanation = self.action_generator.translate_causal_path(path)
                content_parts.append(path_explanation)
                content_parts.append("")  # blank line

        # Security requirements
        content_parts.append("## 보안 요구사항\n")
        content_parts.append(f"**취약점 유형**: {cwe}")
        if cwe_description:
            content_parts.append(f"  - 설명: {cwe_description}")

        content_parts.append(f"\n**필요한 보호**: {safety_property}")

        # Detailed actionable instructions
        if intervention_spec and intervention_spec.interventions:
            content_parts.append("\n## 수정 지시사항\n")
            content_parts.append("다음 변경사항을 코드에 정확히 적용하세요:\n")

            instructions = []
            for intervention in intervention_spec.interventions:
                action = self.action_generator.translate_intervention(intervention)
                instructions.append(self._format_instruction(action, include_rationale=True))

            content_parts.append("\n".join(instructions))

            # Add summary
            summary = self.action_generator.generate_intervention_summary(
                intervention_spec.interventions
            )
            content_parts.append(f"\n**요약**: {summary}")

            # Consistency requirements
            content_parts.append("\n## 일관성 요구사항\n")
            content_parts.append(
                "패치는 위에서 설명한 취약점 인과 경로를 차단해야 하며, "
                "모든 지시사항을 구현해야 합니다."
            )

        # Optional natural context
        if natural_context:
            content_parts.append(f"\n## 추가 참고 정보\n{natural_context}")

        content = "\n".join(content_parts)

        return SpecificationLevel(
            level='c4',
            has_cwe_info=True,
            has_safety_property=True,
            has_target_locations=True,
            has_actionable_instructions=True,
            has_causal_analysis=True,
            content=content
        )

    def _format_instruction(
        self,
        action: ActionableInstruction,
        include_rationale: bool = False
    ) -> str:
        """Format an actionable instruction for display"""
        parts = [f"• **{action.description}**"]

        if include_rationale and action.rationale:
            parts.append(f"  - 이유: {action.rationale}")

        if action.code_hint:
            parts.append(f"  - 코드 힌트: `{action.code_hint}`")

        return "\n".join(parts)


def build_specification_for_condition(
    condition: str,
    vuln_case: Dict[str, object],
    intervention_spec: Optional[InterventionSpec] = None,
    ebug: Optional[FormalBugExplanation] = None,
    natural_context: Optional[str] = None,
) -> Optional[SpecificationLevel]:
    """
    Convenience function to build specification from vulnerability case.

    Args:
        condition: Experimental condition ('c1', 'c2', 'c3', 'c4')
        vuln_case: Vulnerability case dictionary
        intervention_spec: Intervention specification
        ebug: Formal bug explanation
        natural_context: Natural language context

    Returns:
        SpecificationLevel or None (for C1)
    """
    builder = SpecificationBuilder()

    # Extract CWE information
    cwe = vuln_case.get("cwe", "CWE-Unknown")
    cwe_name = vuln_case.get("cwe_name", "")
    cwe_description = f"{cwe_name}" if cwe_name else "보안 취약점"

    # Safety property (can be inferred from CWE or provided)
    safety_property = _infer_safety_property(cwe, cwe_name)

    return builder.build_for_condition(
        condition=condition,
        cwe=cwe,
        cwe_description=cwe_description,
        safety_property=safety_property,
        intervention_spec=intervention_spec,
        ebug=ebug,
        natural_context=natural_context,
    )


def _infer_safety_property(cwe: str, cwe_name: str) -> str:
    """Infer safety property from CWE"""
    # Common CWE mappings
    safety_properties = {
        "CWE-787": "모든 버퍼 쓰기는 할당된 경계 내에서 이루어져야 합니다",
        "CWE-125": "모든 버퍼 읽기는 할당된 경계 내에서 이루어져야 합니다",
        "CWE-476": "모든 포인터는 역참조 전에 NULL이 아님을 확인해야 합니다",
        "CWE-416": "메모리는 해제 후 접근되어서는 안 됩니다",
        "CWE-415": "메모리는 한 번만 해제되어야 합니다",
        "CWE-190": "정수 연산은 오버플로우를 방지해야 합니다",
        "CWE-191": "정수 연산은 언더플로우를 방지해야 합니다",
        "CWE-119": "버퍼 경계는 항상 존중되어야 합니다",
        "CWE-20": "모든 외부 입력은 검증되어야 합니다",
        "CWE-79": "출력은 XSS 공격을 방지하도록 이스케이프되어야 합니다",
        "CWE-89": "SQL 쿼리는 인젝션 공격을 방지해야 합니다",
    }

    # Try exact match
    if cwe in safety_properties:
        return safety_properties[cwe]

    # Try partial matching by CWE name
    name_lower = cwe_name.lower()
    if "buffer" in name_lower and "overflow" in name_lower:
        return "버퍼 경계는 항상 존중되어야 합니다"
    elif "null" in name_lower:
        return "포인터는 역참조 전에 NULL 검사가 필요합니다"
    elif "overflow" in name_lower:
        return "산술 연산은 오버플로우를 방지해야 합니다"
    elif "use after" in name_lower:
        return "메모리는 해제 후 접근되어서는 안 됩니다"

    # Default
    return "코드는 안전한 실행을 보장해야 합니다"
