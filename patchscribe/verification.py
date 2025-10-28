"""
Verification adapters that emulate the three-layer validation stack from the plan.
"""
from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

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
    def __init__(
        self,
        vuln_signature: str,
        *,
        original_code: str,
        vuln_line: int | None = None,
    ) -> None:
        self.signature = vuln_signature
        self.original_code = original_code
        self.vuln_line = vuln_line

    def verify(
        self,
        patch: PatchResult,
        *,
        expected_condition: str | None = None,
    ) -> VerificationResult:
        symbolic = self._symbolic_check(patch, expected_condition)
        model_check = self._model_check(patch)
        fuzzing = self._fuzzing_check(patch)
        return VerificationResult(symbolic=symbolic, model_check=model_check, fuzzing=fuzzing)

    def _symbolic_check(
        self,
        patch: PatchResult,
        expected_condition: str | None,
    ) -> CheckOutcome:
        if patch.method == "ground_truth":
            return CheckOutcome(True, "Ground truth patch assumed to cover causal predicates")

        guard_texts = patch.applied_guards or []
        if not guard_texts:
            guard_texts = self._guards_near_vulnerability(patch.patched_code)

        expected_tokens = self._extract_tokens(expected_condition) if expected_condition else []
        vuln_tokens = self._vulnerability_tokens()

        matched = False
        for guard in guard_texts:
            if expected_tokens and all(tok in guard for tok in expected_tokens if tok):
                matched = True
                break
            if vuln_tokens and any(tok in guard for tok in vuln_tokens if tok):
                matched = True
                break

        if not matched:
            return CheckOutcome(
                False,
                "No guard referencing causal predicates detected",
                "Add guard using vulnerability variables or SMT-guided condition",
            )

        return CheckOutcome(True, "Guard references vulnerability predicates")

    def _model_check(self, patch: PatchResult) -> CheckOutcome:
        if patch.method == "ground_truth":
            return CheckOutcome(True, "Ground truth patch assumed verified")

        compile_success, compile_output = self._compile_check(patch.patched_code)
        if not compile_success:
            return CheckOutcome(False, f"Compilation failed: {compile_output}", "Fix compilation errors")

        insecure_calls = self._detect_insecure_calls(patch.patched_code)
        if insecure_calls:
            return CheckOutcome(
                False,
                f"Insecure API usage remains: {', '.join(sorted(insecure_calls))}",
                "Replace with bounded or secure alternatives",
            )

        if self.signature and self.signature in patch.patched_code:
            return CheckOutcome(True, "Signature preserved after patch")

        return CheckOutcome(True, "Compilation succeeded and insecure APIs mitigated")

    def _fuzzing_check(self, patch: PatchResult) -> CheckOutcome:
        if patch.method == "ground_truth":
            return CheckOutcome(True, "Ground truth patch trusted for runtime behaviour")

        guarded_returns = self._count_fail_fast_returns(patch.patched_code)
        if guarded_returns == 0:
            return CheckOutcome(
                False,
                "No fail-fast return detected in guard paths",
                "Introduce fail-fast return or error handling",
            )

        if self.signature and self.signature not in patch.patched_code:
            return CheckOutcome(
                True,
                "Signature removed; assuming exploit path eliminated",
            )

        return CheckOutcome(True, f"Detected {guarded_returns} guard return paths")

    def _guards_near_vulnerability(self, code: str) -> List[str]:
        lines = code.splitlines()
        if not lines or not self.vuln_line:
            return []
        index = max(0, min(self.vuln_line - 1, len(lines) - 1))
        window_start = max(0, index - 5)
        guards: List[str] = []
        for line in lines[window_start:index]:
            stripped = line.strip()
            if stripped.startswith("if ") or stripped.startswith("if("):
                guards.append(stripped)
        return guards

    def _vulnerability_tokens(self) -> List[str]:
        if not self.vuln_line:
            return []
        lines = self.original_code.splitlines()
        if not (1 <= self.vuln_line <= len(lines)):
            return []
        return self._extract_tokens(lines[self.vuln_line - 1])

    @staticmethod
    def _extract_tokens(text: str | None) -> List[str]:
        if not text:
            return []
        tokens: List[str] = []
        current = []
        for ch in text:
            if ch.isalnum() or ch == "_":
                current.append(ch)
            else:
                if current:
                    tokens.append("".join(current))
                    current = []
        if current:
            tokens.append("".join(current))
        return tokens

    @staticmethod
    def _compile_check(code: str) -> Tuple[bool, str]:
        with tempfile.TemporaryDirectory() as tmpdir:
            src_path = Path(tmpdir) / "patch.c"
            src_path.write_text(code)
            cmd = ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-c", str(src_path)]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=10)
            except Exception as exc:  # pragma: no cover - subprocess failure
                return False, f"gcc execution failed: {exc}"
            if proc.returncode != 0:
                return False, (proc.stderr or proc.stdout).strip()
            return True, "ok"

    @staticmethod
    def _detect_insecure_calls(code: str) -> List[str]:
        insecure_patterns = ["gets(", "strcpy(", "strcat(", "sprintf("]
        return [p.rstrip("(") for p in insecure_patterns if p in code]

    @staticmethod
    def _count_fail_fast_returns(code: str) -> int:
        count = 0
        for line in code.splitlines():
            stripped = line.strip()
            if stripped.startswith("return") and ("ERROR" in stripped or "-1" in stripped):
                count += 1
        return count
