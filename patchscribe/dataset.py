"""Dataset loaders for PatchScribe PoC and research evaluation."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class DatasetCase:
    id: str
    source: str
    vuln_line: int
    cwe_id: str
    cve_id: str
    signature: str
    expected_success: bool
    ground_truth: Optional[str] = None
    metadata: Dict[str, object] | None = None
    max_iterations: int = 3

    def to_dict(self) -> Dict[str, object]:
        data = {
            "id": self.id,
            "source": self.source,
            "vuln_line": self.vuln_line,
            "cwe_id": self.cwe_id,
            "signature": self.signature,
            "expected_success": self.expected_success,
            "max_iterations": self.max_iterations,
        }
        if self.cve_id:
            data["cve_id"] = self.cve_id
        if self.ground_truth is not None:
            data["ground_truth"] = self.ground_truth
        if self.metadata:
            data["metadata"] = self.metadata
        return data


# ---------------------------------------------------------------------------
# Default PoC cases (legacy)
# ---------------------------------------------------------------------------


def _legacy_poc_cases() -> List[DatasetCase]:
    return [
        DatasetCase(
            id="buffer_overflow_simple",
            cwe_id="CWE-120",
            cve_id="",
            vuln_line=9,
            signature="strcpy(buf, input)",
            expected_success=True,
            source="""
#include <string.h>

int handle_input(const char *input) {
    char buf[16];
    size_t input_len = strlen(input);
    if (input_len > sizeof(buf)) {
        log_overflow(input_len);
    }
    strcpy(buf, input);
    return 0;
}
""".strip("\n"),
        ),
        DatasetCase(
            id="format_string_guarded",
            cwe_id="CWE-134",
            cve_id="",
            vuln_line=11,
            signature="printf(user_input)",
            expected_success=True,
            source="""
#include <stdio.h>
#include <stdbool.h>

bool is_trusted(const char *input);
void flag_alert(const char *input);

void process_message(const char *user_input) {
    if (!is_trusted(user_input)) {
        flag_alert(user_input);
    }
    printf(user_input);
}
""".strip("\n"),
        ),
        DatasetCase(
            id="unsafe_input_gets",
            cwe_id="CWE-242",
            cve_id="",
            vuln_line=6,
            signature="gets(buf)",
            expected_success=False,
            source="""
#include <stdio.h>

int read_line(void) {
    char buf[32];
    gets(buf);
    return handle(buf);
}
""".strip("\n"),
        ),
    ]


# ---------------------------------------------------------------------------
# Zeroday repair dataset loader
# ---------------------------------------------------------------------------


def _load_zeroday_cases(limit: Optional[int] = None) -> List[DatasetCase]:
    base = _ROOT / "datasets" / "zeroday_repair"
    cases: List[DatasetCase] = []
    if not base.exists():
        return cases
    for idx, directory in enumerate(sorted(base.iterdir())):
        if limit is not None and idx >= limit:
            break
        if not directory.is_dir():
            continue
        try:
            case = _parse_zeroday_directory(directory)
        except Exception:
            continue
        cases.append(case)
    return cases


def _parse_zeroday_directory(directory: Path) -> DatasetCase:
    parts = directory.name.split("___")
    if len(parts) < 4:
        raise ValueError(f"Unexpected directory format: {directory.name}")
    cwe = parts[0]
    cve = parts[1].replace(".c", "")
    line_hint = parts[-1]
    vuln_line = _safe_int(line_hint.split(".")[0], default=1)
    source_path = directory / "vul.c"
    patched_path = directory / "nonvul.c"
    source = source_path.read_text()
    ground_truth = patched_path.read_text() if patched_path.exists() else None
    signature = _extract_signature(source, vuln_line)
    metadata = {
        "line_hint": line_hint,
        "range": parts[2],
        "dataset": "zeroday_repair",
        "path": str(directory),
    }
    return DatasetCase(
        id=directory.name,
        cwe_id=cwe,
        cve_id=cve,
        vuln_line=vuln_line,
        signature=signature,
        expected_success=True,
        source=source,
        ground_truth=ground_truth,
        metadata=metadata,
        max_iterations=5,
    )


def _load_extractfix_cases(limit: Optional[int] = None) -> List[DatasetCase]:
    base = _ROOT / "datasets" / "extractfix_dataset"
    cases: List[DatasetCase] = []
    if not base.exists():
        return cases

    vul_files = sorted(base.glob("*_vul.c"))
    for idx, vul_path in enumerate(vul_files):
        if limit is not None and idx >= limit:
            break
        try:
            case = _parse_extractfix_case(vul_path)
        except Exception:
            continue
        cases.append(case)
    return cases


def _parse_extractfix_case(vul_path: Path) -> DatasetCase:
    name = vul_path.name
    if not name.endswith("_vul.c"):
        raise ValueError(f"Unexpected extractfix file: {name}")

    base_name = name[: -len("_vul.c")]
    parts = base_name.split("___")
    if len(parts) < 2:
        raise ValueError(f"Malformed extractfix filename: {name}")

    cwe_id = parts[0]
    line_token_segment = parts[-1]
    line_range = parts[-2] if len(parts) >= 2 else ""
    if len(parts) > 3:
        path_hint = "/".join(parts[1:-2])
    elif len(parts) > 1:
        path_hint = parts[1]
    else:
        path_hint = ""

    line_token = line_token_segment.split(".c", 1)[0]
    vuln_line = _safe_int(line_token, default=1)

    source = vul_path.read_text()
    nonvul_path = vul_path.with_name(name.replace("_vul.c", "_nonvul.c"))
    ground_truth = nonvul_path.read_text() if nonvul_path.exists() else None

    signature = _extract_signature(source, vuln_line)
    metadata = {
        "dataset": "extractfix",
        "path_hint": path_hint,
        "line_range": line_range,
        "filename": name,
    }

    return DatasetCase(
        id=base_name,
        cwe_id=cwe_id,
        cve_id="",
        vuln_line=vuln_line,
        signature=signature,
        expected_success=True,
        source=source,
        ground_truth=ground_truth,
        metadata=metadata,
        max_iterations=5,
    )


def _safe_int(value: str, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _extract_signature(source: str, line_no: int) -> str:
    lines = source.splitlines()
    if 1 <= line_no <= len(lines):
        sig = lines[line_no - 1].strip()
        if sig:
            return sig
    return lines[0].strip() if lines else ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_cases(dataset: str = "poc", limit: Optional[int] = None) -> List[Dict[str, object]]:
    if dataset == "zeroday":
        return [case.to_dict() for case in _load_zeroday_cases(limit)]
    if dataset == "extractfix":
        return [case.to_dict() for case in _load_extractfix_cases(limit)]
    # default to legacy poc cases (optionally limited)
    cases = _legacy_poc_cases()
    if limit is not None:
        cases = cases[:limit]
    return [case.to_dict() for case in cases]
