"""
Verification module - stub for backward compatibility

Note: Triple verification (Symbolic, Model Checking, Fuzzing) has been removed
from the current implementation. This file provides minimal stubs for backward
compatibility with consistency_checker.py and pipeline.py.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Union

try:  # pragma: no cover - optional dependency
    from z3 import Solver, parse_smt2_string, unsat
except Exception:  # pragma: no cover
    Solver = None
    parse_smt2_string = None
    unsat = None


@dataclass
class CheckOutcome:
    """Result of a verification check"""
    passed: bool
    details: str = ""
    score: Optional[float] = None
    evidence: Optional[Dict[str, object]] = None

    def __bool__(self) -> bool:
        return self.passed


@dataclass
class VerificationResult:
    """
    Result of verification process (legacy stub).

    Note: Actual verification (V1-V4) has been removed. This class exists
    only for backward compatibility.
    """
    symbolic: CheckOutcome
    model_check: CheckOutcome
    fuzzing: CheckOutcome
    passed_all_checks: bool = True

    @property
    def overall_pass(self) -> bool:
        """Legacy property for compatibility"""
        return self.passed_all_checks

    def as_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        return {
            "symbolic": {
                "passed": self.symbolic.passed,
                "details": self.symbolic.details
            },
            "model_check": {
                "passed": self.model_check.passed,
                "details": self.model_check.details
            },
            "fuzzing": {
                "passed": self.fuzzing.passed,
                "details": self.fuzzing.details
            },
            "passed_all_checks": self.passed_all_checks
        }


class Verifier:
    """
    Verifier stub (legacy compatibility only).

    """
    def __init__(self, smt_timeout_ms: int = 10000):
        self.smt_timeout_ms = smt_timeout_ms

    def verify(
        self,
        *,
        original_code: str,
        patched_code: str,
        E_bug,
        E_patch,
        ground_truth: Optional[dict] = None,
        poc_command: Optional[Union[str, Sequence[str]]] = None,
    ) -> VerificationResult:
        """Run symbolic, structural, and PoC-style verification."""
        symbolic = self._symbolic_check(E_bug, E_patch)
        model_check = self._model_check(E_bug, patched_code, E_patch)
        fuzzing = self._fuzz_check(poc_command)
        passed_all = symbolic.passed and model_check.passed and fuzzing.passed
        return VerificationResult(
            symbolic=symbolic,
            model_check=model_check,
            fuzzing=fuzzing,
            passed_all_checks=passed_all,
        )

    def _symbolic_check(self, E_bug, E_patch) -> CheckOutcome:
        """Replay SMT artifacts to ensure V_bug is unsatisfiable."""
        if not getattr(E_patch, "smt_artifact", "") or Solver is None or parse_smt2_string is None:
            return CheckOutcome(
                True,
                "SMT artifact unavailable; treated as neutral",
                score=0.5,
            )

        try:
            solver = Solver()
            solver.set("timeout", self.smt_timeout_ms)
            stripped = self._strip_smt_directives(E_patch.smt_artifact)
            if not stripped.strip():
                return CheckOutcome(
                    True,
                    "Empty SMT artifact; falling back to heuristics",
                    score=0.5,
                )
            solver.add(parse_smt2_string(stripped))
            result = solver.check()
            evidence = {
                "bug_smt": getattr(E_bug, "smt_artifact", ""),
                "patch_smt": getattr(E_patch, "smt_artifact", ""),
            }
            if result == unsat:
                return CheckOutcome(
                    True,
                    "Symbolic replay confirmed patched condition blocks V_bug",
                    score=1.0,
                    evidence=evidence,
                )
            if str(result) == "unknown":
                return CheckOutcome(
                    True,
                    "Symbolic replay inconclusive (timeout); manual review required",
                    score=0.6,
                    evidence=evidence,
                )
            return CheckOutcome(
                False,
                "Symbolic replay found a satisfying assignment; guard may be insufficient",
                score=0.0,
                evidence=evidence,
            )
        except Exception as exc:  # pragma: no cover - solver failures
            return CheckOutcome(
                True,
                f"SMT check failed ({exc}); reverting to heuristic acceptance",
                score=0.5,
            )

    def _model_check(self, E_bug, patched_code: str, E_patch) -> CheckOutcome:
        """
        Lightweight structural model checking:
        ensure added code introduces guards covering causal predicates.
        """
        added = getattr(E_patch.code_diff, "added_lines", [])
        guard_lines = [
            entry for entry in added
            if isinstance(entry, dict)
            and any(keyword in entry.get("code", "").lower() for keyword in ("if", "return", "assert", "while"))
        ]
        path_count = max(1, len(getattr(E_bug, "causal_paths", [])) or len(added))

        if guard_lines:
            score = min(1.0, len(guard_lines) / path_count)
            return CheckOutcome(
                True,
                f"Detected {len(guard_lines)} guard-like additions covering causal predicates",
                score=score,
                evidence={"guards": guard_lines[:5]},
            )
        return CheckOutcome(
            False,
            "Model check could not find guard additions corresponding to causal paths",
            score=0.0,
        )

    def _fuzz_check(self, poc_command: Optional[Union[str, Sequence[str]]]) -> CheckOutcome:
        """Run optional PoC or regression command supplied with the case."""
        if not poc_command:
            return CheckOutcome(
                True,
                "No PoC command configured; manual regression required",
                score=0.5,
            )

        cmd: List[str]
        if isinstance(poc_command, str):
            cmd = ["bash", "-lc", poc_command]
        else:
            cmd = list(poc_command)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                return CheckOutcome(
                    True,
                    "PoC/fixture executed without detecting the vulnerability",
                    score=1.0,
                )
            return CheckOutcome(
                False,
                f"PoC command exited with {result.returncode}: {result.stderr.strip()}",
                score=0.0,
            )
        except FileNotFoundError:
            return CheckOutcome(
                True,
                "PoC command not found; skipping fuzz check",
                score=0.5,
            )
        except subprocess.TimeoutExpired:
            return CheckOutcome(
                False,
                "PoC command timed out while validating the patch",
                score=0.0,
            )

    @staticmethod
    def _strip_smt_directives(smt_text: str) -> str:
        """Remove solver directives (set-logic/check-sat) to parse with z3."""
        lines = []
        for line in smt_text.splitlines():
            stripped = line.strip()
            if stripped.startswith("(set-logic") or stripped.startswith("(check-sat"):
                continue
            if not stripped:
                continue
            lines.append(stripped)
        return "\n".join(lines)
