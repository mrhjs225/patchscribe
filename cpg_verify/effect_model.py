"""
Patch effect analysis that compares pre- and post-patch causal conditions.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from .pcg_builder import PCGBuilder, PCGBuilderConfig
from .scm import SCMBuilder


@dataclass
class PatchEffect:
    signature_found: bool
    original_condition: str
    patched_condition: str
    vulnerability_removed: bool
    diagnostics: Dict[str, object]

    def as_dict(self) -> Dict[str, object]:
        return {
            "signature_found": self.signature_found,
            "original_condition": self.original_condition,
            "patched_condition": self.patched_condition,
            "vulnerability_removed": self.vulnerability_removed,
            "diagnostics": self.diagnostics,
        }


class PatchEffectAnalyzer:
    def __init__(self, config: PCGBuilderConfig | None = None) -> None:
        self.config = config or PCGBuilderConfig()

    def analyze(
        self,
        original_condition: str,
        patched_code: str,
        signature: str,
    ) -> PatchEffect:
        location = self._find_signature_line(patched_code, signature)
        if location is None:
            return PatchEffect(
                signature_found=False,
                original_condition=original_condition,
                patched_condition="False",
                vulnerability_removed=True,
                diagnostics={"reason": "Signature removed from patched code"},
            )
        vuln_info = {"location": location, "cwe_id": "Unknown"}
        graph, diagnostics = PCGBuilder(patched_code, vuln_info, self.config).build()
        patched_scm = SCMBuilder(graph).derive()
        patched_condition = patched_scm.vulnerable_condition or "False"
        removed = patched_condition in {"False", ""} or patched_condition != original_condition
        return PatchEffect(
            signature_found=True,
            original_condition=original_condition,
            patched_condition=patched_condition,
            vulnerability_removed=removed,
            diagnostics=diagnostics,
        )

    @staticmethod
    def _find_signature_line(program: str, signature: str) -> Optional[int]:
        if not signature:
            return None
        lines = program.splitlines()
        for idx, line in enumerate(lines, start=1):
            if signature in line:
                return idx
        return None
