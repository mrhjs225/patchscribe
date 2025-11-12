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
        content_parts = ["## Security Requirements\n"]

        content_parts.append(f"**Vulnerability Type**: {cwe}")
        if cwe_description:
            content_parts.append(f"  - Description: {cwe_description}")

        content_parts.append(f"\n**Required Protection**: {safety_property}")

        # Enhanced natural language guidance
        if natural_context:
            content_parts.append(f"\n## Vulnerability Scenario\n{natural_context}")
            content_parts.append(f"\n**Fix Direction**: Add validation or guards that block the above scenario.")
        else:
            # Fallback: Provide generic but helpful guidance
            content_parts.append(f"\n**Fix Direction**: Add validation mechanisms that ensure {safety_property}.")

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
        content_parts = ["## Security Requirements\n"]

        content_parts.append(f"**Vulnerability Type**: {cwe}")
        if cwe_description:
            content_parts.append(f"  - Description: {cwe_description}")

        content_parts.append(f"\n**Required Protection**: {safety_property}")

        # Add actionable instructions (with abstract guidelines)
        if intervention_spec and intervention_spec.interventions:
            content_parts.append("\n## Fix Instructions\n")
            content_parts.append("Modify the code to achieve the following security goals:\n")
            content_parts.append("(Location information is for reference only; choose the most appropriate implementation method)\n")

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
            content_parts.append(f"\n**Summary**: {summary}")

            # Add implementation note
            content_parts.append("\n**Implementation Notes**:")
            content_parts.append("• Locations are guidelines; select the optimal position based on code structure")
            content_parts.append("• When multiple implementation methods are possible, choose the safest and simplest approach")

        # Optional natural context
        if natural_context:
            content_parts.append(f"\n## Additional Context\n{natural_context}")

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
            content_parts.append("# 1. Vulnerability Causal Analysis\n")
            content_parts.append("The vulnerability manifests through the following causal paths:\n")

            for path in ebug.causal_paths:
                path_explanation = self.action_generator.translate_causal_path(path)
                content_parts.append(path_explanation)
                content_parts.append("")  # blank line

        # === SECTION 2: Intervention Point Analysis ===
        if intervention_spec and intervention_spec.interventions:
            content_parts.append("# 2. Intervention Points and Rationale\n")
            content_parts.append("**Why fix at these points:**\n")
            content_parts.append("- To block key steps in the causal paths above")
            content_parts.append("- Minimal intervention principle: select the most effective position with minimal side effects\n")

            intervention_analysis = self.action_generator.generate_intervention_analysis(
                intervention_spec.interventions
            )
            content_parts.append(intervention_analysis)

        # === SECTION 3: Implementation Guide (Single Unified Format) ===
        if intervention_spec and intervention_spec.interventions:
            content_parts.append("# 3. Patch Implementation Method\n")
            content_parts.append("Implement each intervention as follows:\n")

            instructions = []
            for i, intervention in enumerate(intervention_spec.interventions, 1):
                action = self.action_generator.translate_intervention(intervention)

                # Unified format with causal connection
                instruction_parts = [f"\n### Intervention {i}"]
                instruction_parts.append(f"**Action**: {action.description}")
                instruction_parts.append(f"**Reason**: {action.rationale}")
                instruction_parts.append(f"**Causal Blocking**: Blocks the corresponding step in Section 1's causal path")
                if action.code_hint:
                    instruction_parts.append(f"**Code Hint**: `{action.code_hint}`")

                instructions.append("\n".join(instruction_parts))

            content_parts.append("\n".join(instructions))

        # === SECTION 4: Security Requirements (moved after implementation) ===
        content_parts.append("\n# 4. Security Requirements\n")
        content_parts.append(f"**Vulnerability Type**: {cwe}")
        if cwe_description:
            content_parts.append(f"  - Description: {cwe_description}")
        content_parts.append(f"\n**Required Protection**: {safety_property}")

        # === SECTION 5: Consistency Requirements ===
        content_parts.append("\n# 5. Consistency Verification\n")
        content_parts.append("After writing the patch, verify the following:\n")
        content_parts.append("✓ Are **Section 1's causal paths blocked**?")
        content_parts.append("✓ Is at least one of **Section 2's intervention points** implemented?")
        content_parts.append("✓ Does it follow the **minimal intervention principle**? (minimize unnecessary changes)")
        content_parts.append("✓ Are there **no side effects** on existing functionality?")

        # Optional natural context
        if natural_context:
            content_parts.append(f"\n## Additional Reference Information\n{natural_context}")

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
            parts.append(f"  - Rationale: {action.rationale}")

        if action.code_hint:
            parts.append(f"  - Code Hint: `{action.code_hint}`")

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
    cwe_description = f"{cwe_name}" if cwe_name else "Security Vulnerability"

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
        "CWE-787": "All buffer writes must occur within allocated bounds",
        "CWE-125": "All buffer reads must occur within allocated bounds",
        "CWE-476": "All pointers must be verified as non-NULL before dereferencing",
        "CWE-416": "Memory must not be accessed after being freed",
        "CWE-415": "Memory must be freed only once",
        "CWE-190": "Integer operations must prevent overflow",
        "CWE-191": "Integer operations must prevent underflow",
        "CWE-119": "Buffer boundaries must always be respected",
        "CWE-20": "All external inputs must be validated",
        "CWE-79": "Output must be escaped to prevent XSS attacks",
        "CWE-89": "SQL queries must prevent injection attacks",
    }

    # Try exact match
    if cwe in safety_properties:
        return safety_properties[cwe]

    # Try partial matching by CWE name
    name_lower = cwe_name.lower()
    if "buffer" in name_lower and "overflow" in name_lower:
        return "Buffer boundaries must always be respected"
    elif "null" in name_lower:
        return "Pointers require NULL checks before dereferencing"
    elif "overflow" in name_lower:
        return "Arithmetic operations must prevent overflow"
    elif "use after" in name_lower:
        return "Memory must not be accessed after being freed"

    # Default
    return "Code must ensure safe execution"
