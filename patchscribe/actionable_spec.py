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
                "description": "Add boundary check before array/buffer access",
                "description_with_location": "Add boundary check before array/buffer access near line {line}",
                "guideline": "Validate that array/buffer index does not exceed bounds (vulnerable operation is near line {line})",
                "rationale": "Prevents out-of-bounds access to block buffer overflow",
                "code_hint": "Condition: {variable} < {bound} or {variable} >= 0 && {variable} < {bound}"
            },
            "null_check": {
                "description": "Add NULL check before pointer use",
                "description_with_location": "Add NULL check before pointer use near line {line}",
                "guideline": "Ensure pointer is non-NULL before dereferencing (vulnerable dereference is near line {line})",
                "rationale": "Prevents NULL pointer dereference",
                "code_hint": "Condition: {variable} != NULL"
            },
            "length_check": {
                "description": "Verify sufficient space before buffer write",
                "description_with_location": "Verify buffer size near line {line}",
                "guideline": "Validate that buffer write does not exceed allocated size (vulnerable write is near line {line})",
                "rationale": "Ensures sufficient space before write to prevent buffer overflow",
                "code_hint": "Condition: available_space >= required_space"
            },
            "sanitize": {
                "description": "Validate and sanitize input values",
                "description_with_location": "Validate and sanitize input near line {line}",
                "guideline": "Validate that external input contains only safe values (vulnerable input use is near line {line})",
                "rationale": "Blocks invalid or malicious input",
                "code_hint": "Reject invalid values or replace with safe defaults"
            },
            "range_check": {
                "description": "Verify value is within valid range",
                "description_with_location": "Verify value is within valid range near line {line}",
                "guideline": "Validate that value does not exceed allowed range (vulnerable use is near line {line})",
                "rationale": "Prevents use of out-of-range values",
                "code_hint": "Condition: min_value <= {variable} <= max_value"
            },
            "overflow_check": {
                "description": "Check for potential integer overflow",
                "description_with_location": "Check for integer overflow near line {line}",
                "guideline": "Validate that arithmetic result does not exceed type bounds (vulnerable operation is near line {line})",
                "rationale": "Ensures arithmetic results stay within type bounds",
                "code_hint": "Verify result does not exceed MAX/MIN before operation"
            },
            "size_validation": {
                "description": "Verify size argument is non-negative",
                "description_with_location": "Verify size argument is non-negative near line {line}",
                "guideline": "Validate that size value is in valid range (>= 0) (vulnerable use is near line {line})",
                "rationale": "Prevents unexpected behavior from negative size values",
                "code_hint": "Condition: size >= 0"
            },
            "guard": {
                "description": "Add early return if safety condition fails",
                "description_with_location": "Add early return if safety condition fails near line {line}",
                "guideline": "Check safety condition before entering dangerous code path (dangerous path is near line {line})",
                "rationale": "Prevents execution of dangerous code paths",
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
            variable=variables.get("target", "variable"),
            bound=variables.get("bound", "array_size")
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
        explanation_parts.append("**Causal Flow Diagram:**")
        flow = " → ".join([self._humanize_node(node) for node in path.nodes])
        explanation_parts.append(f"  {flow}\n")

        # Format 2: Detailed step-by-step
        explanation_parts.append("**Step-by-Step Analysis:**")
        for i, node in enumerate(path.nodes, 1):
            humanized = self._humanize_node(node)
            explanation_parts.append(f"  {i}. {humanized}")

            # Add technical details if available
            if hasattr(path, 'node_details') and node in path.node_details:
                details = path.node_details[node]
                if details.get('location'):
                    explanation_parts.append(f"     - Location: {details['location']}")
                if details.get('variable'):
                    explanation_parts.append(f"     - Variable: {details['variable']}")

        # Format 3: Summary and implications
        explanation_parts.append(f"\n**Explanation:** {path.description}")
        explanation_parts.append("\n**Patch Requirement:** At least one step in the above causal path must be blocked to prevent vulnerability manifestation.")

        return "\n".join(explanation_parts)

    def _humanize_node(self, node_id: str) -> str:
        """Convert technical node ID to human-readable description"""
        # Mapping of common technical terms to English
        humanization_map = {
            "unchecked_input": "Unchecked Input",
            "buffer_overflow": "Buffer Overflow",
            "null_deref": "NULL Pointer Dereference",
            "oob_access": "Out-of-Bounds Access",
            "oob_write": "Out-of-Bounds Write",
            "oob_read": "Out-of-Bounds Read",
            "memory_corruption": "Memory Corruption",
            "use_after_free": "Use After Free",
            "double_free": "Double Free",
            "integer_overflow": "Integer Overflow",
            "format_string": "Format String Vulnerability",
            "injection": "Injection Attack",
            "unvalidated": "Unvalidated",
            "untrusted": "Untrusted",
            "tainted": "Tainted",
            "unchecked": "Unchecked",
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
            return "No explicit fix instructions available."

        analysis_parts = []
        analysis_parts.append("**Intervention Point Analysis:**\n")

        for i, intv in enumerate(interventions, 1):
            action_type = self._infer_action_type(intv)
            type_names = {
                "boundary_check": "Boundary Check", "null_check": "NULL Check",
                "length_check": "Length Check", "sanitize": "Input Validation",
                "range_check": "Range Check", "overflow_check": "Overflow Check",
                "size_validation": "Size Validation", "guard": "Safety Guard"
            }
            action_name = type_names.get(action_type, action_type)

            analysis_parts.append(f"{i}. **Intervention Location**: Near line {intv.target_line}")
            analysis_parts.append(f"   - **Intervention Type**: {action_name}")
            analysis_parts.append(f"   - **Reason**: {intv.rationale if intv.rationale else 'To block the causal path'}")
            analysis_parts.append(f"   - **Minimal Intervention Principle**: This point is the most effective position to block the vulnerability path.\n")

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
            return "No explicit fix instructions available."

        # Count intervention types
        type_counts = {}
        for intv in interventions:
            action_type = self._infer_action_type(intv)
            type_counts[action_type] = type_counts.get(action_type, 0) + 1

        # Generate summary
        summary_parts = []

        type_names = {
            "boundary_check": "Boundary Check",
            "null_check": "NULL Check",
            "length_check": "Length Check",
            "sanitize": "Input Validation",
            "range_check": "Range Check",
            "overflow_check": "Overflow Check",
            "size_validation": "Size Validation",
            "guard": "Safety Guard"
        }

        for action_type, count in type_counts.items():
            name = type_names.get(action_type, action_type)
            summary_parts.append(f"{count} {name}(s)")

        summary = "Required fixes: " + ", ".join(summary_parts)
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
