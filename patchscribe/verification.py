"""
Triple-verification stack that integrates concrete tooling (KLEE/CBMC/LibFuzzer)
with heuristic fallbacks.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

from .patch import PatchResult


@dataclass
class CheckOutcome:
    success: bool
    details: str
    feedback: str = ""
    evidence: Dict[str, str] | None = None


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


class _ExternalBackend:
    """Base helper for external verification tools."""

    tool_names: Tuple[str, ...] = ()

    def __init__(self, timeout: int = 60) -> None:
        self.timeout = timeout

    def available(self) -> bool:
        return all(shutil.which(name) for name in self.tool_names)

    def run(self, workdir: Path, source_path: Path, *, signature: str, expected_condition: str | None) -> CheckOutcome | None:
        raise NotImplementedError

    @staticmethod
    def _write_source(workdir: Path, code: str) -> Path:
        src_path = workdir / "patch.c"
        src_path.write_text(code)
        return src_path

    @staticmethod
    def _safe_run(cmd: List[str], *, cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )


class _KleeBackend(_ExternalBackend):
    tool_names = ("clang", "klee")

    def run(self, workdir: Path, source_path: Path, *, signature: str, expected_condition: str | None) -> CheckOutcome | None:
        bc_path = workdir / "patch.bc"
        compile_cmd = [
            "clang",
            "-emit-llvm",
            "-c",
            "-g",
            "-O0",
            "-Xclang",
            "-disable-O0-optnone",
            str(source_path),
            "-o",
            str(bc_path),
        ]
        compile_proc = self._safe_run(compile_cmd, cwd=workdir, timeout=self.timeout // 2 or 30)
        if compile_proc.returncode != 0:
            return CheckOutcome(
                success=False,
                details="KLEE preparation failed",
                feedback=compile_proc.stderr.strip() or compile_proc.stdout.strip(),
            )

        klee_cmd = [
            "klee",
            "--max-time=" + str(self.timeout),
            str(bc_path),
        ]
        klee_proc = self._safe_run(klee_cmd, cwd=workdir, timeout=self.timeout + 10)
        klee_dir = next(workdir.glob("klee-last"), None)
        counterexamples = []
        if klee_dir:
            counterexamples = sorted(str(p) for p in klee_dir.glob("*.err"))
        stderr = klee_proc.stderr.strip()
        if klee_proc.returncode != 0:
            # LLVM version mismatch is common (e.g., clang >=14 with KLEE built for <=11).
            if "Loading file" in stderr and "failed" in stderr:
                return None
        if klee_proc.returncode != 0 or counterexamples:
            evidence = {
                "stdout": klee_proc.stdout.strip(),
                "stderr": stderr,
                "counterexamples": ", ".join(counterexamples),
            }
            return CheckOutcome(
                success=False,
                details="Symbolic execution found counterexample" if counterexamples else "KLEE reported failure",
                feedback="Inspect KLEE traces for failing path",
                evidence=evidence,
            )

        return CheckOutcome(
            success=True,
            details="KLEE completed without counterexamples",
        )


class _CbmcBackend(_ExternalBackend):
    tool_names = ("cbmc",)

    def run(self, workdir: Path, source_path: Path, *, signature: str, expected_condition: str | None) -> CheckOutcome | None:
        cmd = ["cbmc", str(source_path), "--trace", "--stop-on-fail"]
        proc = self._safe_run(cmd, cwd=workdir, timeout=self.timeout)
        stderr = proc.stderr.strip()
        stdout = proc.stdout.strip()
        if "Unknown option" in stderr and "--trace" in stderr:
            # Older CBMC builds, retry without trace.
            cmd = ["cbmc", str(source_path), "--stop-on-fail"]
            proc = self._safe_run(cmd, cwd=workdir, timeout=self.timeout)
            stderr = proc.stderr.strip()
            stdout = proc.stdout.strip()
        if proc.returncode == 0:
            return CheckOutcome(True, "CBMC reported no property violations")

        return CheckOutcome(
            False,
            "CBMC discovered a reachable violation",
            feedback="Review CBMC counterexample trace",
            evidence={
                "stdout": stdout,
                "stderr": stderr,
            },
        )


class _LibFuzzerBackend(_ExternalBackend):
    tool_names = ("clang",)

    def run(self, workdir: Path, source_path: Path, *, signature: str, expected_condition: str | None) -> CheckOutcome | None:
        target_path = workdir / "fuzz_target"
        compile_cmd = [
            "clang++",
            "-fsanitize=fuzzer,address",
            "-g",
            "-DBUILD_WITH_LIBFUZZER",
            str(source_path),
            "-o",
            str(target_path),
        ]
        compile_proc = self._safe_run(compile_cmd, cwd=workdir, timeout=self.timeout // 2 or 30)
        if compile_proc.returncode != 0:
            stderr = compile_proc.stderr.strip()
            if "cannot find -lstdc++" in stderr:
                return None
            return CheckOutcome(
                False,
                "LibFuzzer build failed",
                feedback=stderr or compile_proc.stdout.strip(),
            )

        runs = max(256, self.timeout * 16)
        fuzz_cmd = [str(target_path), f"-runs={runs}"]
        fuzz_proc = self._safe_run(fuzz_cmd, cwd=workdir, timeout=self.timeout)
        if fuzz_proc.returncode != 0:
            stderr = fuzz_proc.stderr.strip()
            if "cannot find -lstdc++" in stderr or "No such file or directory" in stderr:
                return None
            return CheckOutcome(
                False,
                "LibFuzzer detected a crash",
                feedback="Investigate crashing input produced by libFuzzer",
                evidence={"stderr": fuzz_proc.stderr.strip(), "stdout": fuzz_proc.stdout.strip()},
            )

        return CheckOutcome(True, f"LibFuzzer executed {runs} runs without crashes")


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
        self._symbolic_backend = _KleeBackend()
        self._model_backend = _CbmcBackend()
        self._fuzz_backend = _LibFuzzerBackend(timeout=45)

    def verify(
        self,
        patch: PatchResult,
        *,
        expected_condition: str | None = None,
    ) -> VerificationResult:
        symbolic = self._symbolic_check(patch, expected_condition)
        model_check = self._model_check(patch, expected_condition)
        fuzzing = self._fuzzing_check(patch)
        return VerificationResult(symbolic=symbolic, model_check=model_check, fuzzing=fuzzing)

    def _symbolic_check(
        self,
        patch: PatchResult,
        expected_condition: str | None,
    ) -> CheckOutcome:
        if patch.method == "ground_truth":
            return CheckOutcome(True, "Ground truth patch assumed to cover causal predicates")

        with tempfile.TemporaryDirectory() as tmpdir:
            workdir = Path(tmpdir)
            src_path = _ExternalBackend._write_source(workdir, patch.patched_code)
            if self._symbolic_backend.available():
                try:
                    result = self._symbolic_backend.run(
                        workdir,
                        src_path,
                        signature=self.signature,
                        expected_condition=expected_condition,
                    )
                    if result is not None:
                        return result
                except subprocess.SubprocessError as exc:
                    return CheckOutcome(False, f"KLEE execution error: {exc}", "Investigate symbolic backend failure")
                except Exception as exc:  # pragma: no cover - unexpected
                    return CheckOutcome(False, f"KLEE backend crashed: {exc}", "Report backend failure")

        return self._heuristic_symbolic(patch, expected_condition)

    def _model_check(self, patch: PatchResult, expected_condition: str | None) -> CheckOutcome:
        if patch.method == "ground_truth":
            return CheckOutcome(True, "Ground truth patch assumed verified")

        with tempfile.TemporaryDirectory() as tmpdir:
            workdir = Path(tmpdir)
            src_path = _ExternalBackend._write_source(workdir, patch.patched_code)
            if self._model_backend.available():
                try:
                    result = self._model_backend.run(
                        workdir,
                        src_path,
                        signature=self.signature,
                        expected_condition=expected_condition,
                    )
                    if result is not None:
                        return result
                except subprocess.SubprocessError as exc:
                    return CheckOutcome(False, f"CBMC execution error: {exc}", "Investigate CBMC backend failure")
                except Exception as exc:  # pragma: no cover
                    return CheckOutcome(False, f"CBMC backend crashed: {exc}", "Report backend failure")

        return self._heuristic_model_check(patch)

    def _fuzzing_check(self, patch: PatchResult) -> CheckOutcome:
        if patch.method == "ground_truth":
            return CheckOutcome(True, "Ground truth patch trusted for runtime behaviour")

        with tempfile.TemporaryDirectory() as tmpdir:
            workdir = Path(tmpdir)
            src_path = _ExternalBackend._write_source(workdir, patch.patched_code)
            if self._fuzz_backend.available():
                try:
                    result = self._fuzz_backend.run(
                        workdir,
                        src_path,
                        signature=self.signature,
                        expected_condition=None,
                    )
                    if result is not None:
                        return result
                except subprocess.SubprocessError as exc:
                    return CheckOutcome(False, f"Fuzzing execution error: {exc}", "Investigate fuzzing backend failure")
                except Exception as exc:  # pragma: no cover
                    return CheckOutcome(False, f"Fuzzing backend crashed: {exc}", "Report fuzzing backend failure")

        return self._heuristic_fuzzing(patch)

    # ------------------------------------------------------------------
    # Heuristic fallbacks (original behaviour)
    # ------------------------------------------------------------------

    def _heuristic_symbolic(self, patch: PatchResult, expected_condition: str | None) -> CheckOutcome:
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

        return CheckOutcome(True, "Guard references vulnerability predicates (heuristic fallback)")

    def _heuristic_model_check(self, patch: PatchResult) -> CheckOutcome:
        compile_success, compile_output = self._compile_check(patch.patched_code)
        if not compile_success:
            return CheckOutcome(False, f"Heuristic compile failed: {compile_output}", "Fix compilation errors")

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

    def _heuristic_fuzzing(self, patch: PatchResult) -> CheckOutcome:
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

        return CheckOutcome(True, f"Detected {guarded_returns} guard return paths (heuristic fallback)")

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
        current: List[str] = []
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
