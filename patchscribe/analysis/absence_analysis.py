"""
Absence (Missing Guard) analysis for Phase-1 PCG construction.

Implements the paper's “absence predicate” library by scanning the source code
around the vulnerable statement and emitting dedicated PCG nodes when required
defensive constructs are missing. The implementation keeps the logic heuristic
so it can run without heavyweight parsers, yet each pattern records structured
metadata so downstream stages (SCM, formal specs, consistency) can audit why a
MissingGuard node exists.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import re
from typing import Dict, Iterable, List, Sequence

from ..pcg import PCGNode, ProgramCausalGraph, next_node_id


@dataclass
class AbsenceFinding:
    """Structured record describing one missing-guard detection."""

    pattern: str
    line: int
    snippet: str
    severity: str
    guard_hint: str
    rationale: str
    categories: List[str] = field(default_factory=list)
    evidence: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "pattern": self.pattern,
            "line": self.line,
            "snippet": self.snippet,
            "severity": self.severity,
            "guard_hint": self.guard_hint,
            "rationale": self.rationale,
            "categories": list(self.categories),
            "evidence": dict(self.evidence),
        }


@dataclass
class AbsenceAnalysisResult:
    graph: ProgramCausalGraph
    findings: List[AbsenceFinding]
    metrics: Dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class AbsencePattern:
    """Definition of a missing-guard pattern."""

    name: str
    trigger_keywords: Sequence[str]
    guard_keywords: Sequence[str]
    description: str
    guard_hint: str
    severity: str
    categories: Sequence[str] = field(default_factory=list)
    guard_window: int = 8
    requires_identifier: bool = False


def _build_absence_patterns() -> List[AbsencePattern]:
    """
    Construct the 32-pattern absence library referenced in the paper.

    The patterns are grouped across memory-safety, authentication, resource
    lifecycle, and data validation themes. Each entry contains lightweight
    trigger/guard keywords so the analyzer can work on plain source text.
    """
    patterns: List[AbsencePattern] = [
        AbsencePattern(
            name="missing_null_check",
            trigger_keywords=["->", "strcpy", "memcpy", "memmove", "strlen", "sprintf"],
            guard_keywords=["== null", "!= null", "if (!", "if (NULL", "if (null"],
            description="Pointer dereference without NULL validation",
            guard_hint="Add NULL guard before dereference",
            severity="critical",
            categories=["memory", "pointer"],
            requires_identifier=True,
        ),
        AbsencePattern(
            name="missing_bounds_check_copy",
            trigger_keywords=["strcpy", "strcat", "gets", "scanf", "sprintf", "memcpy"],
            guard_keywords=["len", "size", "bound", "<", "<=", "sizeof"],
            description="Unbounded copy into fixed-size buffer",
            guard_hint="Validate length against destination capacity",
            severity="critical",
            categories=["memory", "bounds"],
        ),
        AbsencePattern(
            name="missing_length_validation",
            trigger_keywords=["length", "len", "size", "count"],
            guard_keywords=["<", "<=", ">", ">=", "min", "max"],
            description="Derived size used without relational guard",
            guard_hint="Compare derived length to allowable range",
            severity="high",
            categories=["bounds"],
        ),
        AbsencePattern(
            name="missing_return_code_check",
            trigger_keywords=["= malloc", "= fopen", "= read", "= recv", "= send", "= write"],
            guard_keywords=["==", "!=", "if (!", "if (NULL", "if (rc"],
            description="Return value from resource acquisition not checked",
            guard_hint="Check result/errno before downstream use",
            severity="high",
            categories=["resource"],
            requires_identifier=True,
        ),
        AbsencePattern(
            name="missing_error_path",
            trigger_keywords=["strtol", "atoi", "parse", "deserialize"],
            guard_keywords=["errno", "error", "fail", "return", "goto"],
            description="Parsing result not validated for errors",
            guard_hint="Inspect errno/result to detect invalid input",
            severity="medium",
            categories=["validation"],
        ),
        AbsencePattern(
            name="missing_integer_overflow_guard",
            trigger_keywords=["* size", "+ size", "* len", "+ len"],
            guard_keywords=["__builtin_mul_overflow", "SIZE_MAX", "overflow", "check_mul"],
            description="Potential integer overflow without capacity guard",
            guard_hint="Add overflow check before arithmetic",
            severity="high",
            categories=["arithmetic"],
        ),
        AbsencePattern(
            name="missing_signedness_check",
            trigger_keywords=["(int)", "(short)", "(char)", "signed"],
            guard_keywords=[">= 0", "< 0", "abs", "labs"],
            description="Cast between signed/unsigned without range validation",
            guard_hint="Validate value fits destination bit width",
            severity="medium",
            categories=["arithmetic"],
        ),
        AbsencePattern(
            name="missing_format_string_guard",
            trigger_keywords=["printf", "fprintf", "syslog"],
            guard_keywords=["\"%s\"", "\"%d\"", "\"%"],
            description="User-controlled format string without literal template",
            guard_hint="Use fixed format string and pass data as parameters",
            severity="high",
            categories=["format-string"],
        ),
        AbsencePattern(
            name="missing_authentication_check",
            trigger_keywords=["login", "auth", "token", "session"],
            guard_keywords=["is_admin", "is_authenticated", "has_perm", "validate_token"],
            description="Sensitive operation without authentication gate",
            guard_hint="Check caller identity/permission before execution",
            severity="critical",
            categories=["auth"],
        ),
        AbsencePattern(
            name="missing_authorization_check",
            trigger_keywords=["chmod", "delete", "update", "write", "exec"],
            guard_keywords=["is_authorized", "role", "check_acl", "permission"],
            description="State-changing action without authorization filter",
            guard_hint="Enforce role/ACL check before acting",
            severity="critical",
            categories=["auth", "access-control"],
        ),
        AbsencePattern(
            name="missing_state_validation",
            trigger_keywords=["state", "status", "phase", "initialized", "ready"],
            guard_keywords=["== READY", "!= READY", "is_initialized", "initialized"],
            description="Object state assumed without validation",
            guard_hint="Ensure object is initialized before use",
            severity="medium",
            categories=["state"],
        ),
        AbsencePattern(
            name="missing_resource_cleanup",
            trigger_keywords=["malloc", "calloc", "fopen", "socket", "lock"],
            guard_keywords=["free", "close", "unlock", "cleanup"],
            description="Allocated resource not paired with cleanup path",
            guard_hint="Add cleanup in error and success paths",
            severity="medium",
            categories=["resource"],
        ),
        AbsencePattern(
            name="missing_double_free_guard",
            trigger_keywords=["free", "delete"],
            guard_keywords=["ptr = NULL", "if (ptr", "already_freed", "flag"],
            description="Potential double free without nulling pointer",
            guard_hint="Clear pointer or track ownership before second free",
            severity="high",
            categories=["memory"],
            requires_identifier=True,
        ),
        AbsencePattern(
            name="missing_path_sanitization",
            trigger_keywords=["open(", "fopen", "stat", "unlink"],
            guard_keywords=["realpath", "sanitize", "basename", "../"],
            description="Filesystem path used without traversal sanitization",
            guard_hint="Normalize and whitelist path components",
            severity="high",
            categories=["io", "path"],
        ),
        AbsencePattern(
            name="missing_command_sanitization",
            trigger_keywords=["system(", "popen", "exec", "execl", "execve"],
            guard_keywords=["escape", "sanitize", "allowlist", "validate"],
            description="Shell command built from untrusted input",
            guard_hint="Validate/escape command arguments before execution",
            severity="critical",
            categories=["command-injection"],
        ),
        AbsencePattern(
            name="missing_tls_validation",
            trigger_keywords=["SSL_", "tls", "curl_easy_setopt"],
            guard_keywords=["VERIFY", "CAfile", "cert", "pin"],
            description="TLS connection without certificate validation",
            guard_hint="Enable certificate verification / pin trusted roots",
            severity="high",
            categories=["crypto", "network"],
        ),
        AbsencePattern(
            name="missing_random_seed_check",
            trigger_keywords=["rand(", "srand", "random"],
            guard_keywords=["seed", "entropy", "urandom"],
            description="Predictable randomness without entropy seed",
            guard_hint="Seed RNG with high-entropy source",
            severity="medium",
            categories=["crypto"],
        ),
        AbsencePattern(
            name="missing_session_binding",
            trigger_keywords=["session", "cookie", "token"],
            guard_keywords=["secure", "httponly", "bind", "ip", "user-agent"],
            description="Session sensitive action without binding to context",
            guard_hint="Bind session to user/device metadata",
            severity="medium",
            categories=["auth"],
        ),
        AbsencePattern(
            name="missing_rate_limit",
            trigger_keywords=["login", "auth", "password", "reset"],
            guard_keywords=["rate", "throttle", "cooldown"],
            description="Sensitive endpoint lacks brute-force throttling",
            guard_hint="Add rate limiting or exponential backoff",
            severity="medium",
            categories=["auth"],
        ),
        AbsencePattern(
            name="missing_input_sanitization",
            trigger_keywords=["user_input", "request", "argv", "env"],
            guard_keywords=["sanitize", "escape", "filter", "validate"],
            description="Untrusted input used without sanitization",
            guard_hint="Normalize/escape user input before use",
            severity="high",
            categories=["validation"],
        ),
        AbsencePattern(
            name="missing_output_encoding",
            trigger_keywords=["html", "printf(", "response", "return"],
            guard_keywords=["htmlspecialchars", "encode", "escape"],
            description="User data echoed without output encoding",
            guard_hint="Encode output context appropriately",
            severity="high",
            categories=["xss"],
        ),
        AbsencePattern(
            name="missing_locale_guard",
            trigger_keywords=["tolower", "toupper", "strcoll"],
            guard_keywords=["setlocale", "locale", "C_locale"],
            description="Locale-sensitive comparison without locale guard",
            guard_hint="Set deterministic locale before comparison",
            severity="low",
            categories=["consistency"],
        ),
        AbsencePattern(
            name="missing_time_of_check_guard",
            trigger_keywords=["stat(", "access(", "fstat"],
            guard_keywords=["re-stat", "open", "descriptor", "O_NOFOLLOW"],
            description="TOCTOU vulnerable sequence without invariant check",
            guard_hint="Revalidate object between check and use",
            severity="high",
            categories=["race"],
        ),
        AbsencePattern(
            name="missing_lock_guard",
            trigger_keywords=["shared", "global", "counter", "list"],
            guard_keywords=["mutex", "lock", "spin", "atomic"],
            description="Shared state mutation without synchronization",
            guard_hint="Acquire lock or use atomic update",
            severity="high",
            categories=["concurrency"],
        ),
        AbsencePattern(
            name="missing_unlock_on_error",
            trigger_keywords=["mutex", "lock", "spin"],
            guard_keywords=["unlock", "finally", "goto cleanup"],
            description="Lock path misses failure cleanup guard",
            guard_hint="Ensure locks unlock on every exit path",
            severity="medium",
            categories=["concurrency"],
        ),
        AbsencePattern(
            name="missing_privilege_drop",
            trigger_keywords=["setuid", "seteuid", "sudo"],
            guard_keywords=["setuid(0)", "drop_privileges", "seteuid(getuid"],
            description="Privileged block lacks drop back to user mode",
            guard_hint="Drop privileges immediately after privileged action",
            severity="critical",
            categories=["privilege"],
        ),
        AbsencePattern(
            name="missing_config_validation",
            trigger_keywords=["config", "env", "ENV", "option"],
            guard_keywords=["validate", "default", "allowed", "range"],
            description="Configuration values consumed without validation",
            guard_hint="Check config value is in expected range/enum",
            severity="medium",
            categories=["config"],
        ),
        AbsencePattern(
            name="missing_default_case",
            trigger_keywords=["switch", "enum"],
            guard_keywords=["default:", "else"],
            description="Switch lacks default handling for unexpected input",
            guard_hint="Add default case to handle unexpected values",
            severity="low",
            categories=["logic"],
        ),
        AbsencePattern(
            name="missing_encoding_check",
            trigger_keywords=["utf8", "unicode", "wide char", "mbstowcs"],
            guard_keywords=["is_valid_utf8", "sanitize", "iconv"],
            description="Unicode data assumed valid without validation",
            guard_hint="Validate encoding before processing",
            severity="medium",
            categories=["validation"],
        ),
        AbsencePattern(
            name="missing_entropy_check",
            trigger_keywords=["nonce", "salt", "iv"],
            guard_keywords=["random", "entropy", "hrng"],
            description="Cryptographic material not checked for randomness",
            guard_hint="Ensure salt/nonce derived from CSPRNG",
            severity="high",
            categories=["crypto"],
        ),
        AbsencePattern(
            name="missing_policy_enforcement",
            trigger_keywords=["policy", "compliance", "quota", "limit"],
            guard_keywords=["enforce", "check_policy", "quota", "limit_exceeded"],
            description="Business policy assumed without enforcement",
            guard_hint="Call policy enforcement routine before action",
            severity="medium",
            categories=["business-logic"],
        ),
        AbsencePattern(
            name="missing_logging_redaction",
            trigger_keywords=["log", "printf", "fprintf", "syslog"],
            guard_keywords=["redact", "mask", "hash", "sanitize"],
            description="Sensitive data logged without redaction",
            guard_hint="Mask sensitive fields before logging",
            severity="medium",
            categories=["compliance"],
        ),
    ]
    return patterns


ABSENCE_PATTERNS: List[AbsencePattern] = _build_absence_patterns()


class AbsenceAnalyzer:
    """
    Detect referenced absence predicates near the vulnerability location.

    The analyzer scans a configurable window around the vulnerable line,
    checking each pattern's trigger keywords and verifying that the expected
    guard keywords do not appear in the nearby code. When a guard is missing,
    a dedicated PCGMissingGuard node is created so downstream stages can reason
    about absence predicates the same way they do about explicit operations.
    """

    def __init__(
        self,
        program: str,
        vuln_line: int,
        window: int = 12,
        expected_patterns: Sequence[str] | None = None,
    ) -> None:
        self.program = program
        self.lines = program.splitlines()
        self.vuln_line = max(1, vuln_line)
        self.window = max(4, window)
        self.seq: Dict[str, int] = {}
        self.expected_patterns = self._normalize_expected(expected_patterns)

    def run(self) -> AbsenceAnalysisResult:
        graph = ProgramCausalGraph()
        findings: List[AbsenceFinding] = []
        candidate_lines = self._candidate_line_numbers()

        for line_no in candidate_lines:
            line = self._get_line(line_no)
            if not line:
                continue
            lowered = line.lower()
            identifiers = list(self._extract_identifiers(line))

            for pattern in ABSENCE_PATTERNS:
                if not self._matches_triggers(lowered, pattern.trigger_keywords):
                    continue
                if self._has_guard(line_no, pattern, identifiers, lowered):
                    continue

                node_id = next_node_id(self.seq, "m")
                finding = AbsenceFinding(
                    pattern=pattern.name,
                    line=line_no,
                    snippet=line.strip(),
                    severity=pattern.severity,
                    guard_hint=pattern.guard_hint,
                    rationale=pattern.description,
                    categories=list(pattern.categories),
                    evidence={
                        "trigger_keywords": list(pattern.trigger_keywords),
                        "guard_keywords": list(pattern.guard_keywords),
                        "identifiers": identifiers,
                        "node_id": node_id,
                    },
                )
                findings.append(finding)
                graph.add_node(
                    PCGNode(
                        node_id=node_id,
                        node_type="missing_guard",
                        description=f"{pattern.guard_hint} ({pattern.name})",
                        location=line_no,
                        metadata={
                            "pattern": pattern.name,
                            "severity": pattern.severity,
                            "categories": list(pattern.categories),
                            "snippet": line.strip(),
                            "guard_hint": pattern.guard_hint,
                            "rationale": pattern.description,
                        },
                    )
                )

        metrics = self._compute_metrics(findings)
        return AbsenceAnalysisResult(graph=graph, findings=findings, metrics=metrics)

    # ------------------------------------------------------------------ #
    # Helper methods
    # ------------------------------------------------------------------ #

    def _candidate_line_numbers(self) -> Iterable[int]:
        start = max(1, self.vuln_line - self.window)
        end = min(len(self.lines), self.vuln_line + self.window)
        return range(start, end + 1)

    def _get_line(self, line_no: int) -> str:
        if 1 <= line_no <= len(self.lines):
            return self.lines[line_no - 1]
        return ""

    def _matches_triggers(self, lowered_line: str, keywords: Sequence[str]) -> bool:
        return any(keyword.lower() in lowered_line for keyword in keywords)

    def _has_guard(
        self,
        line_no: int,
        pattern: AbsencePattern,
        identifiers: Sequence[str],
        lowered_line: str,
    ) -> bool:
        # Immediate guard on same line (e.g., ternary or inline check)
        if any(guard in lowered_line for guard in pattern.guard_keywords):
            return True

        start = max(0, line_no - pattern.guard_window - 1)
        end = line_no  # exclusive
        guard_region = [self.lines[i].lower() for i in range(start, end - 1)]
        if not guard_region:
            return False

        if pattern.requires_identifier and identifiers:
            lowered_ids = [ident.lower() for ident in identifiers]
            for guard_line in guard_region:
                if any(guard in guard_line for guard in pattern.guard_keywords):
                    if any(identifier in guard_line for identifier in lowered_ids):
                        return True
            return False

        return any(guard in guard_line for guard_line in guard_region for guard in pattern.guard_keywords)

    @staticmethod
    def _extract_identifiers(line: str) -> Iterable[str]:
        # Rough heuristic for identifiers (avoids keywords)
        for token in re.findall(r"\b[_a-zA-Z]\w+\b", line):
            if token in {
                "if",
                "for",
                "while",
                "return",
                "switch",
                "case",
                "sizeof",
                "struct",
                "union",
                "goto",
            }:
                continue
            yield token

    @staticmethod
    def _normalize_expected(patterns: Sequence[str] | None) -> Counter:
        counter: Counter[str] = Counter()
        if not patterns:
            return counter
        for pattern in patterns:
            if isinstance(pattern, str) and pattern:
                counter[pattern] += 1
        return counter

    def _compute_metrics(self, findings: List[AbsenceFinding]) -> Dict[str, object]:
        metrics = {
            "total_findings": len(findings),
            "unique_patterns": len({finding.pattern for finding in findings}),
        }
        if not self.expected_patterns:
            metrics.update(
                {
                    "precision": None,
                    "recall": None,
                    "f1": None,
                    "true_positive": 0,
                    "false_positive": len(findings),
                    "false_negative": 0,
                    "labeled_support": 0,
                }
            )
            return metrics

        predictions = Counter(finding.pattern for finding in findings)
        tp = sum(
            min(count, predictions.get(pattern, 0))
            for pattern, count in self.expected_patterns.items()
        )
        fp = len(findings) - tp
        fn = sum(self.expected_patterns.values()) - tp
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        metrics.update(
            {
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "true_positive": tp,
                "false_positive": fp,
                "false_negative": fn,
                "labeled_support": sum(self.expected_patterns.values()),
            }
        )
        return metrics
