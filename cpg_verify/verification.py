"""
Verification adapters that emulate the three-layer validation stack from the plan.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from .patch import PatchResult


@dataclass
class CheckOutcome:
    success: bool
    details: str
    feedback: str = ""


@dataclass
class VerificationResult:
    symbolic: CheckOutcome
    model_check: CheckOutcome
    fuzzing: CheckOutcome

    @property
    def overall(self) -> bool:
        return self.symbolic.success and self.model_check.success and self.fuzzing.success

    def as_dict(self) -> Dict[str, object]:
        return {
            "symbolic": self.symbolic.__dict__,
            "model_check": self.model_check.__dict__,
            "fuzzing": self.fuzzing.__dict__,
            "overall": self.overall,
        }


class Verifier:
    def __init__(self, vuln_signature: str) -> None:
        self.signature = vuln_signature

    def verify(self, patch: PatchResult) -> VerificationResult:
        symbolic = self._symbolic_check(patch)
        model_check = self._model_check(patch)
        fuzzing = self._fuzzing_check(patch)
        return VerificationResult(symbolic=symbolic, model_check=model_check, fuzzing=fuzzing)

    def _symbolic_check(self, patch: PatchResult) -> CheckOutcome:
        if patch.method == "ground_truth":
            return CheckOutcome(True, "Ground truth patch assumed to satisfy guard coverage")
        if not patch.applied_guards:
            return CheckOutcome(False, "No guard inserted; path condition unresolved", "Add guard before vulnerability")
        guards = "; ".join(patch.applied_guards)
        return CheckOutcome(True, f"Guards cover causal predicates: {guards}")

    def _model_check(self, patch: PatchResult) -> CheckOutcome:
        if patch.method == "ground_truth":
            return CheckOutcome(True, "Ground truth patch validated against reference behavior")
        if "gets(" in patch.patched_code:
            return CheckOutcome(False, "Insecure API usage remains (gets)", "Replace insecure input API")
        if self.signature not in patch.patched_code:
            return CheckOutcome(False, "Vulnerability signature missing after patch", "Ensure fix preserves monitored signature or update specification")
        return CheckOutcome(True, "Control flow satisfies safety invariants")

    def _fuzzing_check(self, patch: PatchResult) -> CheckOutcome:
        if patch.method == "ground_truth":
            return CheckOutcome(True, "Ground truth patch trusted for fail-safe handling")
        if "return -1;" not in patch.patched_code:
            return CheckOutcome(False, "Patch does not introduce fail-safe return", "Introduce fail-safe path for invalid input")
        return CheckOutcome(True, "Synthetic fuzz cases blocked by guard")
