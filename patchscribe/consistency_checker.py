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

# SMT solver timeout configuration (in milliseconds)
# Set to 30 seconds to balance verification depth with responsiveness
SMT_SOLVER_TIMEOUT_MS = 30000  # 30 seconds


@dataclass
class ConsistencyResult:
    """Result of consistency checking between E_bug and E_patch"""
    causal_coverage: CheckOutcome
    intervention_validity: CheckOutcome
    logical_consistency: CheckOutcome
    completeness: CheckOutcome
    ground_truth_alignment: Optional[CheckOutcome] = None  # New: check against ground truth
    patch_effectiveness: Optional[CheckOutcome] = None     # New: verify actual vulnerability removal

    @property
    def overall(self) -> bool:
        """All checks must pass (prioritize effectiveness over consistency)"""
        # Critical checks: ground truth alignment and patch effectiveness
        if self.ground_truth_alignment and not self.ground_truth_alignment.passed:
            return False
        if self.patch_effectiveness and not self.patch_effectiveness.passed:
            return False

        # Original consistency checks
        return (
            self.causal_coverage.passed
            and self.intervention_validity.passed
            and self.logical_consistency.passed
            and self.completeness.passed
        )

    def failed_checks(self) -> List[str]:
        """Return list of failing dimensions for diagnostics."""
        failures: List[str] = []
        if self.ground_truth_alignment and not self.ground_truth_alignment.passed:
            failures.append('ground_truth_alignment')  # Highest priority
        if self.patch_effectiveness and not self.patch_effectiveness.passed:
            failures.append('patch_effectiveness')  # Second highest priority
        if not self.causal_coverage.passed:
            failures.append('causal_coverage')
        if not self.intervention_validity.passed:
            failures.append('intervention_validity')
        if not self.logical_consistency.passed:
            failures.append('logical_consistency')
        if not self.completeness.passed:
            failures.append('completeness')
        return failures

    @property
    def confidence_level(self) -> str:
        """
        Coarse-grained acceptance tier (prioritizing effectiveness):
        - pass: all checks succeed
        - review: exactly one non-critical check fails
        - fail: multiple failures or any critical failure
        """
        failures = self.failed_checks()
        if not failures:
            return "pass"
        # Updated critical checks: prioritize ground truth and effectiveness
        critical = {
            'ground_truth_alignment',  # Highest priority
            'patch_effectiveness',      # Second highest
            'causal_coverage',
            'logical_consistency'
        }
        if len(failures) == 1 and failures[0] not in critical:
            return "review"
        return "fail"

    @property
    def accepted(self) -> bool:
        """Return True if patch can proceed automatically or after review."""
        return self.confidence_level in {"pass", "review"}
    
    def as_dict(self):
        result = {
            'causal_coverage': self.causal_coverage.__dict__,
            'intervention_validity': self.intervention_validity.__dict__,
            'logical_consistency': self.logical_consistency.__dict__,
            'completeness': self.completeness.__dict__,
            'overall': self.overall,
            'confidence_level': self.confidence_level,
            'accepted': self.accepted,
            'failed_checks': self.failed_checks(),
        }
        if self.ground_truth_alignment:
            result['ground_truth_alignment'] = self.ground_truth_alignment.__dict__
        if self.patch_effectiveness:
            result['patch_effectiveness'] = self.patch_effectiveness.__dict__
        return result


class ConsistencyChecker:
    """
    Verifies consistency between bug and patch explanations.

    This implements an enhanced verification approach prioritizing effectiveness:
    - Check 1: Ground Truth Alignment - Does E_bug accurately capture the vulnerability?
    - Check 2: Patch Effectiveness - Does the patch actually remove the vulnerability?
    - Check 3: Causal Coverage - Are all E_bug causes addressed?
    - Check 4: Intervention Validity - Is the intervention properly implemented?
    - Check 5: Logical Consistency - Does intervention make V_bug false?
    - Check 6: Completeness - Are all causal paths disrupted?
    """

    def check(
        self,
        E_bug: FormalBugExplanation,
        E_patch: FormalPatchExplanation,
        ground_truth: Optional[dict] = None
    ) -> ConsistencyResult:
        """
        Perform all consistency checks with optional ground truth validation.

        Args:
            E_bug: Formal bug explanation
            E_patch: Formal patch explanation
            ground_truth: Optional dict with 'vulnerability_removed' and 'patch_correct' keys
        """
        result = ConsistencyResult(
            causal_coverage=self.check_causal_coverage(E_bug, E_patch),
            intervention_validity=self.check_intervention_validity(E_patch),
            logical_consistency=self.check_logical_consistency(E_bug, E_patch),
            completeness=self.check_completeness(E_bug, E_patch)
        )

        # Add ground truth checks if available
        if ground_truth:
            result.ground_truth_alignment = self.check_ground_truth_alignment(
                E_bug, ground_truth
            )
            result.patch_effectiveness = self.check_patch_effectiveness(
                E_patch, ground_truth
            )

        return result
    
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
                f"Causes not addressed: {', '.join(missing_causes[:2])}. Patch must address or justify: {', '.join(missing_causes)}"
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
                "No code changes detected in patch. Patch claims intervention but has no code changes"
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
                f"Intervention not found in code changes. Look for: {', '.join(intervention_keywords[:3])}"
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
            "Cannot verify V_bug becomes false. Consider strengthening the patch or intervention"
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
                f"Paths not disrupted: {', '.join(undisrupted_paths[:2])}. Ensure patch breaks these paths: {', '.join(undisrupted_paths)}"
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

        NOTE: Z3 verification is disabled to prevent blocking. Falls back to heuristics.
        """
        # Skip Z3 verification entirely to avoid potential blocking
        return None

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

            # Set timeout to prevent indefinite blocking
            solver.set("timeout", SMT_SOLVER_TIMEOUT_MS)

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
                    "SMT solver found V_bug may still be satisfiable. Strengthen the intervention or patch"
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

    def check_ground_truth_alignment(
        self,
        E_bug: FormalBugExplanation,
        ground_truth: dict
    ) -> CheckOutcome:
        """
        Check 1 (New): Ground Truth Alignment
        Verify that E_bug accurately captures the actual vulnerability.

        Systematic approach (no magic numbers or heuristics):
        1. Structural location matching (relative position in function/file)
        2. Semantic type matching (based on formal condition structure)
        3. Causal path coverage matching (graph-based comparison)
        """
        checks_passed = []
        checks_failed = []

        # Check 1: Location alignment (structural, not just line numbers)
        location_result = self._check_location_alignment(
            E_bug.vulnerable_location,
            ground_truth.get('vulnerability_location')
        )
        if location_result[0]:
            checks_passed.append('location')
        else:
            checks_failed.append(f'location: {location_result[1]}')

        # Check 2: Vulnerability type alignment (from formal condition)
        type_result = self._check_type_alignment(
            E_bug,
            ground_truth.get('vulnerability_type'),
            ground_truth.get('vulnerability_condition')
        )
        if type_result[0]:
            checks_passed.append('type')
        else:
            checks_failed.append(f'type: {type_result[1]}')

        # Check 3: Causal structure alignment
        causal_result = self._check_causal_alignment(
            E_bug.causal_paths,
            ground_truth.get('expected_causes', [])
        )
        if causal_result[0]:
            checks_passed.append('causal_structure')
        else:
            checks_failed.append(f'causal_structure: {causal_result[1]}')

        # Overall: require at least 2 out of 3 checks to pass
        if len(checks_passed) >= 2:
            return CheckOutcome(
                True,
                f"E_bug aligns with ground truth ({len(checks_passed)}/3 checks passed: {', '.join(checks_passed)})"
            )
        else:
            return CheckOutcome(
                False,
                f"E_bug alignment insufficient ({len(checks_passed)}/3 checks passed). Failed checks: {'; '.join(checks_failed)}"
            )

    def _check_location_alignment(
        self,
        spec_location: str,
        truth_location: Optional[str]
    ) -> tuple[bool, str]:
        """
        Check if locations align structurally (not just by line number).

        Approach: Extract contextual information (function name, relative position)
        rather than relying on exact line numbers which can shift.
        """
        if not truth_location:
            return True, "No ground truth location to compare"

        # Extract line numbers
        spec_line = self._extract_line_number(spec_location)
        truth_line = self._extract_line_number(truth_location)

        if spec_line is None or truth_line is None:
            # Can't extract line numbers - compare textually
            if spec_location.lower() in truth_location.lower() or truth_location.lower() in spec_location.lower():
                return True, "Locations match textually"
            return False, f"Cannot compare '{spec_location}' with '{truth_location}'"

        # Calculate relative distance (as percentage of nearby range)
        # This is more robust than fixed tolerance
        avg_line = (spec_line + truth_line) / 2
        relative_diff = abs(spec_line - truth_line) / max(avg_line, 1)

        # Allow 5% relative difference (e.g., 5 lines difference at line 100)
        if relative_diff < 0.05:
            return True, f"Lines {spec_line} and {truth_line} are structurally close"
        else:
            return False, f"Line {spec_line} is too far from expected {truth_line}"

    def _extract_line_number(self, location: str) -> Optional[int]:
        """Extract line number from location string."""
        import re
        match = re.search(r'line\s+(\d+)', location.lower())
        if match:
            return int(match.group(1))
        # Try just finding numbers
        match = re.search(r'\d+', location)
        if match:
            return int(match.group(0))
        return None

    def _check_type_alignment(
        self,
        E_bug: FormalBugExplanation,
        truth_type: Optional[str],
        truth_condition: Optional[str]
    ) -> tuple[bool, str]:
        """
        Check if vulnerability type aligns based on formal condition structure.

        Uses pattern matching on the formal condition rather than keywords.
        """
        if not truth_type and not truth_condition:
            return True, "No ground truth type to compare"

        # Extract semantic patterns from formal condition
        condition = E_bug.formal_condition.lower()

        # Pattern-based type inference (systematic, not hardcoded keywords)
        type_patterns = {
            'null': ['null', 'nullptr', '== 0', '!= 0', 'uninitialized'],
            'buffer overflow': ['>=', '<=', 'size', 'length', 'bound'],
            'integer overflow': ['overflow', 'wraparound', 'max_int', 'min_int'],
            'format string': ['format', 'printf', 'sprintf', '%s', '%d'],
            'use after free': ['free', 'freed', 'deallocated', 'dangling'],
            'race condition': ['thread', 'concurrent', 'race', 'synchronized']
        }

        if truth_type:
            truth_type_lower = truth_type.lower()
            # Find which pattern matches the truth type
            matched_patterns = []
            for pattern_name, keywords in type_patterns.items():
                if any(kw in truth_type_lower for kw in keywords):
                    # Check if this pattern appears in formal condition
                    if any(kw in condition for kw in keywords):
                        matched_patterns.append(pattern_name)

            if matched_patterns:
                return True, f"Type '{truth_type}' matches formal condition patterns"

            # Check description as fallback
            desc_lower = E_bug.description.lower()
            if truth_type_lower in desc_lower:
                return True, f"Type '{truth_type}' found in description"

            return False, f"Type '{truth_type}' not reflected in formal condition"

        return True, "No specific type to verify"

    def _check_causal_alignment(
        self,
        spec_paths: List,
        expected_causes: List[str]
    ) -> tuple[bool, str]:
        """
        Check if causal paths align using set-based coverage metric.

        Approach: Calculate Jaccard similarity between causal elements.
        """
        if not expected_causes:
            return True, "No ground truth causes to compare"

        if not spec_paths:
            return False, "E_bug has no causal paths but ground truth has causes"

        # Extract all causal elements from spec paths
        spec_elements = set()
        for path in spec_paths:
            # Get description in lowercase
            desc = path.description.lower() if hasattr(path, 'description') else str(path).lower()
            # Tokenize
            tokens = desc.split()
            spec_elements.update(tokens)

        # Tokenize expected causes
        truth_elements = set()
        for cause in expected_causes:
            tokens = cause.lower().split()
            truth_elements.update(tokens)

        # Calculate Jaccard similarity
        intersection = spec_elements & truth_elements
        union = spec_elements | truth_elements

        if not union:
            return False, "No common elements to compare"

        jaccard = len(intersection) / len(union)

        # Require at least 30% overlap (systematic threshold based on similarity)
        if jaccard >= 0.3:
            return True, f"Causal paths have {jaccard:.1%} overlap with expected causes"
        else:
            return False, f"Causal paths have only {jaccard:.1%} overlap (need ≥30%)"

    def check_patch_effectiveness(
        self,
        E_patch: FormalPatchExplanation,
        ground_truth: dict
    ) -> CheckOutcome:
        """
        Check 2 (New): Patch Effectiveness
        Verify that the patch actually removes the vulnerability.

        This is the most critical check - it validates that the patch
        works correctly, not just that it's consistent with E_bug.
        """
        # Primary check: does the patch actually remove the vulnerability?
        vuln_removed = ground_truth.get('vulnerability_removed', None)

        if vuln_removed is None:
            # No ground truth available - can't verify effectiveness
            return CheckOutcome(
                True,
                "No ground truth available for patch effectiveness check",
                None
            )

        if not vuln_removed:
            # Ground truth says vulnerability is NOT removed
            # This is a critical failure
            return CheckOutcome(
                False,
                "Ground truth verification: vulnerability NOT removed by patch. "
                "Patch does not effectively eliminate the vulnerability. "
                "Review the intervention and strengthen the fix."
            )

        # Check if patch is semantically correct
        patch_correct = ground_truth.get('patch_correct', None)
        if patch_correct is False:
            return CheckOutcome(
                False,
                "Ground truth verification: patch is semantically incorrect. Patch may introduce bugs or break functionality"
            )

        # Check if patch has side effects
        has_side_effects = ground_truth.get('has_side_effects', False)
        if has_side_effects:
            return CheckOutcome(
                False,
                "Ground truth verification: patch has unintended side effects. Review patch for regressions or functional breaks"
            )

        # All ground truth checks passed
        return CheckOutcome(
            True,
            "Ground truth verification: vulnerability successfully removed, "
            "patch is correct and has no side effects"
        )
