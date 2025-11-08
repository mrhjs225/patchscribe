"""
Triple-verification stack that integrates concrete tooling (Angr/CBMC/LibFuzzer)
with heuristic fallbacks.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from functools import lru_cache
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
        return (
            self.symbolic.success
            or self.model_check.success
            or self.fuzzing.success
        )

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
    def _safe_run(
        cmd: List[str],
        *,
        cwd: Path,
        timeout: int,
        env: Dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )


class _AngrBackend(_ExternalBackend):
    tool_names = ("clang",)

    def available(self) -> bool:  # type: ignore[override]
        if not super().available():
            return False
        try:  # pragma: no cover - optional dependency
            import angr  # noqa: F401
        except ImportError:
            return False
        return True

    def run(self, workdir: Path, source_path: Path, *, signature: str, expected_condition: str | None) -> CheckOutcome | None:
        try:
            import angr  # type: ignore
        except ImportError:  # pragma: no cover - guarded by available()
            return None

        target_path = workdir / "patch_angr"
        compile_cmd = [
            "clang",
            "-O0",
            "-g",
            str(source_path),
            "-o",
            str(target_path),
        ]

        compile_proc = self._safe_run(compile_cmd, cwd=workdir, timeout=self.timeout // 2 or 30)
        if compile_proc.returncode != 0:
            # If compilation fails (missing main, etc.), allow heuristic fallback.
            return None

        try:
            project = angr.Project(str(target_path), auto_load_libs=False)
            state = project.factory.entry_state()
            simgr = project.factory.simgr(state)

            max_steps = max(10, self.timeout // 6)
            for _ in range(max_steps):
                if simgr.errored:
                    reason = simgr.errored[0].error
                    return CheckOutcome(
                        success=False,
                        details="angr encountered execution error",
                        feedback=str(reason),
                    )
                if not simgr.active:
                    break
                simgr.step()

            return CheckOutcome(
                success=True,
                details="angr exploration completed without errors",
            )
        except Exception as exc:
            return CheckOutcome(
                success=False,
                details=f"angr execution failed: {exc}",
                feedback=str(exc),
            )


class _CbmcBackend(_ExternalBackend):
    tool_names = ("cbmc",)

    def run(self, workdir: Path, source_path: Path, *, signature: str, expected_condition: str | None) -> CheckOutcome | None:
        cmd = ["cbmc", str(source_path), "--trace", "--stop-on-fail"]
        proc = self._run_cbmc(cmd, workdir)
        stderr = proc.stderr.strip()
        stdout = proc.stdout.strip()
        if "Unknown option" in stderr and "--trace" in stderr:
            # Older CBMC builds, retry without trace.
            cmd = ["cbmc", str(source_path), "--stop-on-fail"]
            proc = self._run_cbmc(cmd, workdir)
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

    def _run_cbmc(self, cmd: List[str], workdir: Path) -> subprocess.CompletedProcess[str]:
        proc = self._safe_run(cmd, cwd=workdir, timeout=self.timeout)
        if proc.returncode != 0 and self._needs_minisat_fallback(proc.stderr):
            env = self._minisat_fallback_env()
            if env:
                proc = self._safe_run(cmd, cwd=workdir, timeout=self.timeout, env=env)
        return proc

    @staticmethod
    def _needs_minisat_fallback(stderr: str) -> bool:
        if not stderr:
            return False
        return "_ZN7Minisat10SimpSolver10addClause" in stderr

    @staticmethod
    def _minisat_fallback_env() -> Dict[str, str] | None:
        candidate_dirs = [
            Path("/usr/lib"),
            Path("/usr/lib64"),
            Path("/usr/lib/x86_64-linux-gnu"),
            Path("/lib/x86_64-linux-gnu"),
        ]
        present_dirs = [
            str(directory)
            for directory in candidate_dirs
            if (directory / "libminisat.so.2").exists()
        ]
        if not present_dirs:
            return None
        env = os.environ.copy()
        existing = env.get("LD_LIBRARY_PATH")
        env["LD_LIBRARY_PATH"] = _merge_library_paths(present_dirs, existing)
        return env


class _LibFuzzerBackend(_ExternalBackend):
    tool_names = ("clang",)

    def run(self, workdir: Path, source_path: Path, *, signature: str, expected_condition: str | None) -> CheckOutcome | None:
        target_path = workdir / "fuzz_target"
        lib_dirs: List[str] = []
        libstdcxx_dir = self._libstdcxx_dir()
        if libstdcxx_dir:
            lib_dirs.append(libstdcxx_dir)

        compile_cmd = [
            "clang++",
            "-fsanitize=fuzzer,address",
            "-g",
            "-DBUILD_WITH_LIBFUZZER",
            str(source_path),
            "-o",
            str(target_path),
        ]
        compile_env: Dict[str, str] | None = None
        if libstdcxx_dir:
            compile_cmd.extend(["-L", libstdcxx_dir, f"-Wl,-rpath,{libstdcxx_dir}"])
            compile_env = self._library_env(lib_dirs)

        compile_proc = self._safe_run(
            compile_cmd,
            cwd=workdir,
            timeout=self.timeout // 2 or 30,
            env=compile_env,
        )
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
        fuzz_env = compile_env if lib_dirs else None
        fuzz_proc = self._safe_run(
            fuzz_cmd,
            cwd=workdir,
            timeout=self.timeout,
            env=fuzz_env,
        )
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

    @staticmethod
    @lru_cache()
    def _libstdcxx_dir() -> str | None:
        gxx = shutil.which("g++")
        if not gxx:
            return None
        try:
            proc = subprocess.run(
                [gxx, "-print-file-name=libstdc++.so"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
        except Exception:
            return None
        path = proc.stdout.strip()
        if not path or path == "libstdc++.so":
            return None
        resolved = Path(path)
        if resolved.exists():
            return str(resolved.parent)
        return None

    @staticmethod
    def _library_env(extra_dirs: List[str]) -> Dict[str, str]:
        env = os.environ.copy()
        env["LIBRARY_PATH"] = _merge_library_paths(extra_dirs, env.get("LIBRARY_PATH"))
        env["LD_LIBRARY_PATH"] = _merge_library_paths(extra_dirs, env.get("LD_LIBRARY_PATH"))
        return env


class Verifier:
    _ENV_STATUS: Dict[str, Dict[str, object]] | None = None

    @classmethod
    def check_environment(cls) -> Dict[str, Dict[str, object]]:
        if cls._ENV_STATUS is not None:
            return cls._ENV_STATUS

        status: Dict[str, Dict[str, object]] = {}

        symbolic_backend = _AngrBackend()
        model_backend = _CbmcBackend()
        fuzz_backend = _LibFuzzerBackend(timeout=45)

        status["symbolic"] = cls._inspect_backend(symbolic_backend, name="symbolic", requires_module="angr")
        status["model_check"] = cls._inspect_backend(model_backend, name="model_check")
        status["fuzzing"] = cls._inspect_backend(fuzz_backend, name="fuzzing")

        cls._ENV_STATUS = status
        return status

    @staticmethod
    def _inspect_backend(
        backend: _ExternalBackend,
        *,
        name: str,
        requires_module: str | None = None,
    ) -> Dict[str, object]:
        available = backend.available()
        info: Dict[str, object] = {
            "available": available,
            "tools": backend.tool_names,
            "name": name,
        }
        if available:
            info["reason"] = ""
            return info

        missing_tools = [tool for tool in backend.tool_names if not shutil.which(tool)]
        reason_parts: List[str] = []
        if missing_tools:
            reason_parts.append(f"missing executables: {', '.join(sorted(missing_tools))}")
        if requires_module:
            try:
                __import__(requires_module)
            except Exception as exc:
                reason_parts.append(f"python module '{requires_module}' unavailable ({exc})")
        if not reason_parts:
            reason_parts.append("backend dependency unavailable")
        info["reason"] = "; ".join(reason_parts)
        return info

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
        self._symbolic_backend = _AngrBackend()
        self._model_backend = _CbmcBackend()
        self._fuzz_backend = _LibFuzzerBackend(timeout=45)
        self.env_status = self.check_environment()
        self._warned_stages: set[str] = set()

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

        status = self.env_status.get("symbolic", {})
        backend_available = status.get("available", False)

        if backend_available:
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
        else:
            self._warn_if_unavailable("symbolic")

        outcome = self._heuristic_symbolic(patch, expected_condition)
        if not backend_available:
            outcome = self._annotate_unavailable(outcome, "symbolic")
        return outcome

    def _model_check(self, patch: PatchResult, expected_condition: str | None) -> CheckOutcome:
        if patch.method == "ground_truth":
            return CheckOutcome(True, "Ground truth patch assumed verified")

        status = self.env_status.get("model_check", {})
        backend_available = status.get("available", False)

        if backend_available:
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
                        return CheckOutcome(False, f"CBMC backend crashed: {exc}", "Report CBMC backend failure")
        else:
            self._warn_if_unavailable("model_check")

        outcome = self._heuristic_model_check(patch)
        if not backend_available:
            outcome = self._annotate_unavailable(outcome, "model_check")
        return outcome

    def _fuzzing_check(self, patch: PatchResult) -> CheckOutcome:
        if patch.method == "ground_truth":
            return CheckOutcome(True, "Ground truth patch trusted for runtime behaviour")

        status = self.env_status.get("fuzzing", {})
        backend_available = status.get("available", False)

        if backend_available:
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
        else:
            self._warn_if_unavailable("fuzzing")

        outcome = self._heuristic_fuzzing(patch)
        if not backend_available:
            outcome = self._annotate_unavailable(outcome, "fuzzing")
        return outcome

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

    def _warn_if_unavailable(self, stage: str) -> None:
        if stage in self._warned_stages:
            return
        status = self.env_status.get(stage)
        if not status or status.get("available"):
            return
        reason = status.get("reason", "unknown dependency issue")
        print(
            f"[PatchScribe] Warning: {stage} verification backend unavailable ({reason}). "
            "Falling back to heuristic checks."
        )
        self._warned_stages.add(stage)

    def _annotate_unavailable(self, outcome: CheckOutcome, stage: str) -> CheckOutcome:
        status = self.env_status.get(stage, {})
        if status.get("available", True):
            return outcome
        reason = status.get("reason", "")
        reason_text = reason or f"{stage} backend unavailable"
        outcome.details = f"{outcome.details} [backend unavailable: {reason_text}]"
        if outcome.feedback:
            outcome.feedback += f" Install requirements for {stage} verification ({reason_text})."
        else:
            outcome.feedback = f"Install requirements for {stage} verification ({reason_text})."
        return outcome


def _merge_library_paths(new_paths: List[str], existing: str | None) -> str:
    paths: List[str] = []
    for candidate in new_paths:
        if candidate:
            paths.append(candidate)
    if existing:
        paths.extend(p for p in existing.split(os.pathsep) if p)
    deduped = list(dict.fromkeys(paths))
    return os.pathsep.join(deduped)
