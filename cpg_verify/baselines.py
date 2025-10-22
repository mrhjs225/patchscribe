"""Baseline patchers used for comparative evaluation."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from .intervention import InterventionSpec
from .patch import PatchGenerator, PatchResult
from .pcg import ProgramCausalGraph


@dataclass
class Baseline:
    name: str

    def generate(
        self,
        graph: ProgramCausalGraph | None,
        program: str,
        vuln_line: int,
        signature: str,
        spec: InterventionSpec | None = None,
    ) -> PatchResult:
        generator = PatchGenerator(graph or ProgramCausalGraph(), program, vuln_line, signature)
        if spec is None:
            spec = InterventionSpec()
        patch = generator.generate(spec)
        patch.method = self.name
        return patch


BASELINES: Dict[str, Baseline] = {
    "raw_gpt4": Baseline("raw_gpt4"),
    "vrpilot": Baseline("vrpilot"),
    "san2patch": Baseline("san2patch"),
}
