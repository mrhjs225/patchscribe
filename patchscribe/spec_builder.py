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
        C2: Abstract specification with enhanced scenario description

        Provides:
        - CWE type with detailed description
        - Safety property
        - Natural language vulnerability scenario
        - High-level mitigation direction

        Strengthened to better differentiate from C1 by providing
        concrete vulnerability scenarios and mitigation hints.
        """
        content_parts = ["## 보안 요구사항\n"]

        content_parts.append(f"**취약점 유형**: {cwe}")
        if cwe_description:
            content_parts.append(f"  - 설명: {cwe_description}")

        content_parts.append(f"\n**필요한 보호**: {safety_property}")

        # Enhanced natural language guidance
        if natural_context:
            content_parts.append(f"\n## 취약점 발생 시나리오\n{natural_context}")
            content_parts.append(f"\n**수정 방향**: 위 시나리오를 차단하는 검증 또는 가드를 추가하세요.")
        else:
            # Fallback: Provide generic but helpful guidance
            content_parts.append(f"\n**수정 방향**: {safety_property}를 보장하는 검증 메커니즘을 추가하세요.")

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
        C3: Targeted specification with abstract guidelines

        Provides:
        - CWE type
        - Safety property
        - Abstract security goals (what to achieve)
        - Location hints (not strict requirements)
        - Actionable instructions focused on "what" rather than "where"

        Key difference from C4: Location information is provided as guidance,
        not as a strict requirement. This gives the model flexibility in
        implementation while still providing helpful context.
        """
        content_parts = ["## 보안 요구사항\n"]

        content_parts.append(f"**취약점 유형**: {cwe}")
        if cwe_description:
            content_parts.append(f"  - 설명: {cwe_description}")

        content_parts.append(f"\n**필요한 보호**: {safety_property}")

        # Add actionable instructions (with abstract guidelines)
        if intervention_spec and intervention_spec.interventions:
            content_parts.append("\n## 수정 지시사항\n")
            content_parts.append("다음 보안 목표를 달성하도록 코드를 수정하세요:\n")
            content_parts.append("(위치 정보는 참고용이며, 가장 적절한 구현 방법을 선택하세요)\n")

            instructions = []
            for intervention in intervention_spec.interventions:
                # Use abstract guideline for C3
                action = self.action_generator.translate_intervention(
                    intervention,
                    use_abstract_guideline=True
                )
                instructions.append(self._format_instruction(action, include_rationale=False))

            content_parts.append("\n".join(instructions))

            # Add summary
            summary = self.action_generator.generate_intervention_summary(
                intervention_spec.interventions
            )
            content_parts.append(f"\n**요약**: {summary}")

            # Add implementation note
            content_parts.append("\n**구현 참고사항**:")
            content_parts.append("• 위치는 가이드라인이며, 코드 구조에 맞게 최적의 위치를 선택하세요")
            content_parts.append("• 여러 구현 방법이 가능한 경우, 가장 안전하고 간단한 방법을 선택하세요")

        # Optional natural context
        if natural_context:
            content_parts.append(f"\n## 참고 정보\n{natural_context}")

        content = "\n".join(content_parts)

        return SpecificationLevel(
            level='c3',
            has_cwe_info=True,
            has_safety_property=True,
            has_target_locations=True,  # Has location hints, not strict requirements
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
        C4: Complete specification with enhanced causal reasoning

        Provides:
        - Causal path analysis (PRIMARY - most important, shown first)
        - Intervention point analysis with explicit connection to causal paths
        - Streamlined implementation guidance (single format)
        - Consistency requirements linking back to causal analysis

        Theory: Cognitive Load Theory (Sweller, 1988)
        - Present critical causal information FIRST to establish mental model
        - Single coherent format to avoid choice overload
        """
        content_parts = []

        # === SECTION 1: Causal Analysis (TOP PRIORITY) ===
        if ebug and ebug.causal_paths:
            content_parts.append("# 1. 취약점 인과 분석\n")
            content_parts.append("다음 인과 경로를 통해 취약점이 발현됩니다:\n")

            for path in ebug.causal_paths:
                path_explanation = self.action_generator.translate_causal_path(path)
                content_parts.append(path_explanation)
                content_parts.append("")  # blank line

        # === SECTION 2: Intervention Point Analysis ===
        if intervention_spec and intervention_spec.interventions:
            content_parts.append("# 2. 개입 지점 및 근거\n")
            content_parts.append("**왜 이 지점에서 수정하는가:**\n")
            content_parts.append("- 위 인과 경로의 핵심 단계를 차단하기 위함")
            content_parts.append("- 최소 개입 원칙: 가장 효과적이고 부작용이 적은 위치 선택\n")

            intervention_analysis = self.action_generator.generate_intervention_analysis(
                intervention_spec.interventions
            )
            content_parts.append(intervention_analysis)

        # === SECTION 3: Implementation Guide (Single Unified Format) ===
        if intervention_spec and intervention_spec.interventions:
            content_parts.append("# 3. 패치 구현 방법\n")
            content_parts.append("각 개입을 다음과 같이 구현하세요:\n")

            instructions = []
            for i, intervention in enumerate(intervention_spec.interventions, 1):
                action = self.action_generator.translate_intervention(intervention)

                # Unified format with causal connection
                instruction_parts = [f"\n### 개입 {i}"]
                instruction_parts.append(f"**수행할 작업**: {action.description}")
                instruction_parts.append(f"**이유**: {action.rationale}")
                instruction_parts.append(f"**인과 차단**: 섹션 1의 인과 경로 중 해당 단계를 차단")
                if action.code_hint:
                    instruction_parts.append(f"**코드 힌트**: `{action.code_hint}`")

                instructions.append("\n".join(instruction_parts))

            content_parts.append("\n".join(instructions))

        # === SECTION 4: Security Requirements (moved after implementation) ===
        content_parts.append("\n# 4. 보안 요구사항\n")
        content_parts.append(f"**취약점 유형**: {cwe}")
        if cwe_description:
            content_parts.append(f"  - 설명: {cwe_description}")
        content_parts.append(f"\n**필요한 보호**: {safety_property}")

        # === SECTION 5: Consistency Requirements ===
        content_parts.append("\n# 5. 일관성 검증\n")
        content_parts.append("패치 작성 후 다음을 확인하세요:\n")
        content_parts.append("✓ **섹션 1의 인과 경로가 차단**되었는가?")
        content_parts.append("✓ **섹션 2의 개입 지점** 중 하나 이상이 구현되었는가?")
        content_parts.append("✓ **최소 개입 원칙**을 따랐는가? (불필요한 변경 최소화)")
        content_parts.append("✓ 기존 기능에 **부작용이 없는가**?")

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
