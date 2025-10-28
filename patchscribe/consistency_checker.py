"""
Consistency verification between E_bug and E_patch.
This is a key innovation of PatchScribe: verifying that the patch explanation
is consistent with and addresses the bug explanation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .formal_spec import FormalBugExplanation, FormalPatchExplanation
from .verification import CheckOutcome

try:
    from z3 import And, Bool, Not, Or, Solver, substitute, unsat
except ImportError:
    Bool = None


@dataclass
class ConsistencyResult:
    """Result of consistency checking between E_bug and E_patch"""
    causal_coverage: CheckOutcome
    intervention_validity: CheckOutcome
    logical_consistency: CheckOutcome
    completeness: CheckOutcome
    
    @property
    def overall(self) -> bool:
        """All checks must pass"""
        return (
            self.causal_coverage.success
            and self.intervention_validity.success
            and self.logical_consistency.success
            and self.completeness.success
        )
    
    def as_dict(self):
        return {
            'causal_coverage': self.causal_coverage.__dict__,
            'intervention_validity': self.intervention_validity.__dict__,
            'logical_consistency': self.logical_consistency.__dict__,
            'completeness': self.completeness.__dict__,
            'overall': self.overall
        }


class ConsistencyChecker:
    """
    Verifies consistency between bug and patch explanations.
    
    This implements the dual verification approach:
    - Check 1: Causal Coverage - Are all E_bug causes addressed?
    - Check 2: Intervention Validity - Is the intervention properly implemented?
    - Check 3: Logical Consistency - Does intervention make V_bug false?
    - Check 4: Completeness - Are all causal paths disrupted?
    """
    
    def check(
        self,
        E_bug: FormalBugExplanation,
        E_patch: FormalPatchExplanation
    ) -> ConsistencyResult:
        """Perform all consistency checks"""
        return ConsistencyResult(
            causal_coverage=self.check_causal_coverage(E_bug, E_patch),
            intervention_validity=self.check_intervention_validity(E_patch),
            logical_consistency=self.check_logical_consistency(E_bug, E_patch),
            completeness=self.check_completeness(E_bug, E_patch)
        )
    
    def check_causal_coverage(
        self,
        E_bug: FormalBugExplanation,
        E_patch: FormalPatchExplanation
    ) -> CheckOutcome:
        """
        Check 1: Causal Coverage
        Verify that all causes identified in E_bug are addressed in E_patch.
        """
        if not E_bug.causal_paths:
            return CheckOutcome(
                True,
                "No causal paths in E_bug to verify"
            )
        
        # Extract cause descriptions from causal paths
        bug_causes = {path.description for path in E_bug.causal_paths}
        
        # Check which causes are addressed
        addressed_set = set(E_patch.addressed_causes)
        unaddressed_set = set(E_patch.unaddressed_causes)
        
        missing_causes = []
        for cause in bug_causes:
            # Check if this cause is mentioned in addressed or unaddressed
            is_addressed = any(cause in addr for addr in addressed_set)
            is_justified = any(cause in unaddr for unaddr in unaddressed_set)
            
            if not (is_addressed or is_justified):
                missing_causes.append(cause)
        
        if missing_causes:
            return CheckOutcome(
                False,
                f"Causes not addressed: {', '.join(missing_causes[:2])}",
                f"Patch must address or justify: {', '.join(missing_causes)}"
            )
        
        return CheckOutcome(
            True,
            f"All {len(bug_causes)} causes addressed or justified"
        )
    
    def check_intervention_validity(
        self,
        E_patch: FormalPatchExplanation
    ) -> CheckOutcome:
        """
        Check 2: Intervention Validity
        Verify that the claimed intervention is actually present in the code diff.
        """
        intervention = E_patch.intervention
        code_diff = E_patch.code_diff
        
        if not code_diff.added_lines and not code_diff.modified_lines:
            return CheckOutcome(
                False,
                "No code changes detected in patch",
                "Patch claims intervention but has no code changes"
            )
        
        # Check if intervention description matches code changes
        # Look for evidence of intervention in added code
        intervention_keywords = self._extract_keywords(intervention.description)
        
        code_text = " ".join(
            line.get("code", "") 
            for line in code_diff.added_lines + code_diff.modified_lines
        ).lower()
        
        matched_keywords = [kw for kw in intervention_keywords if kw in code_text]
        
        if not matched_keywords and intervention_keywords:
            return CheckOutcome(
                False,
                "Intervention not found in code changes",
                f"Look for: {', '.join(intervention_keywords[:3])}"
            )
        
        return CheckOutcome(
            True,
            f"Intervention validated: found {len(matched_keywords)} relevant changes"
        )
    
    def check_logical_consistency(
        self,
        E_bug: FormalBugExplanation,
        E_patch: FormalPatchExplanation
    ) -> CheckOutcome:
        """
        Check 3: Logical Consistency
        Verify that substituting the intervention into φ_bug makes it false.
        
        This uses SMT solving if available, otherwise uses heuristics.
        """
        # Extract vulnerability condition
        bug_condition = E_bug.formal_condition
        if "⟺" in bug_condition:
            bug_condition = bug_condition.split("⟺")[1].strip()
        
        patch_effect = E_patch.effect_on_Vbug
        
        # Check if patch claims vulnerability is removed
        if "false" in patch_effect.after.lower():
            return CheckOutcome(
                True,
                "Patch effect analysis shows V_bug = false"
            )
        
        # Try SMT-based verification if Z3 is available
        if Bool is not None:
            try:
                result = self._smt_verify_intervention(E_bug, E_patch)
                if result is not None:
                    return result
            except Exception as e:
                # Fall through to heuristic check
                pass
        
        # Heuristic check: look for negation of bug condition in patch reasoning
        reasoning = patch_effect.reasoning.lower()
        if any(word in reasoning for word in ["false", "unsatisfiable", "prevented", "impossible"]):
            return CheckOutcome(
                True,
                "Reasoning indicates vulnerability is eliminated"
            )
        
        return CheckOutcome(
            False,
            "Cannot verify V_bug becomes false",
            "Consider strengthening the patch or intervention"
        )
    
    def check_completeness(
        self,
        E_bug: FormalBugExplanation,
        E_patch: FormalPatchExplanation
    ) -> CheckOutcome:
        """
        Check 4: Completeness
        Verify that all causal paths identified in E_bug are disrupted.
        """
        if not E_bug.causal_paths:
            return CheckOutcome(True, "No causal paths to verify")
        
        undisrupted_paths = []
        for path in E_bug.causal_paths:
            # Check if this path is mentioned in disrupted_paths
            is_disrupted = any(
                path.description in disrupted or path.path_id in disrupted
                for disrupted in E_patch.disrupted_paths
            )
            
            if not is_disrupted:
                undisrupted_paths.append(path.description)
        
        if undisrupted_paths:
            return CheckOutcome(
                False,
                f"Paths not disrupted: {', '.join(undisrupted_paths[:2])}",
                f"Ensure patch breaks these paths: {', '.join(undisrupted_paths)}"
            )
        
        return CheckOutcome(
            True,
            f"All {len(E_bug.causal_paths)} causal paths disrupted"
        )
    
    def _extract_keywords(self, text: str) -> List[str]:
        """Extract meaningful keywords from intervention description"""
        # Common programming keywords to extract
        keywords = []
        words = text.lower().split()
        
        # Filter for meaningful words (length > 3, not common words)
        common_words = {'the', 'and', 'for', 'with', 'this', 'that', 'from', 'into'}
        for word in words:
            clean_word = word.strip('.,;:()[]')
            if len(clean_word) > 3 and clean_word not in common_words:
                keywords.append(clean_word)
        
        return keywords[:10]  # Limit to top 10
    
    def _smt_verify_intervention(
        self,
        E_bug: FormalBugExplanation,
        E_patch: FormalPatchExplanation
    ) -> Optional[CheckOutcome]:
        """
        Use Z3 SMT solver to verify that intervention makes V_bug false.
        Returns None if verification cannot be performed.
        """
        if Bool is None:
            return None
        
        try:
            # Parse bug condition
            condition = E_bug.formal_condition
            if "⟺" in condition:
                condition = condition.split("⟺")[1].strip()
            
            # Create symbolic variables for each variable in E_bug
            variables = {}
            for var_name in E_bug.variables.keys():
                variables[var_name] = Bool(var_name)
            
            # Parse condition into Z3 formula (simplified)
            formula = self._parse_to_z3(condition, variables)
            
            if formula is None:
                return None
            
            # Create solver and add vulnerability condition
            solver = Solver()
            solver.add(formula)
            
            # Add constraints from intervention
            # (Simplified: assume intervention sets affected variables to false)
            for var_name in E_patch.intervention.affected_variables:
                if var_name in variables:
                    solver.add(Not(variables[var_name]))
            
            # Check if vulnerability is still satisfiable
            result = solver.check()
            
            if result == unsat:
                return CheckOutcome(
                    True,
                    "SMT solver confirms V_bug is unsatisfiable after intervention"
                )
            else:
                return CheckOutcome(
                    False,
                    "SMT solver found V_bug may still be satisfiable",
                    "Strengthen the intervention or patch"
                )
        
        except Exception:
            # If anything fails, return None to fall back to heuristics
            return None
    
    def _parse_to_z3(self, condition: str, variables: dict):
        """
        Simplified parsing of logical condition to Z3 formula.
        Handles basic AND, OR, NOT operations.
        """
        if not condition or condition == "True":
            return None
        
        # Very simplified parser - only handles basic cases
        condition = condition.strip()
        
        # Handle NOT
        if condition.startswith("NOT "):
            inner = condition[4:].strip()
            if inner in variables:
                return Not(variables[inner])
        
        # Handle AND
        if " AND " in condition:
            parts = condition.split(" AND ")
            z3_parts = []
            for part in parts:
                part = part.strip()
                if part in variables:
                    z3_parts.append(variables[part])
            if z3_parts:
                return And(*z3_parts)
        
        # Handle OR
        if " OR " in condition:
            parts = condition.split(" OR ")
            z3_parts = []
            for part in parts:
                part = part.strip()
                if part in variables:
                    z3_parts.append(variables[part])
            if z3_parts:
                return Or(*z3_parts)
        
        # Single variable
        if condition in variables:
            return variables[condition]
        
        return None
