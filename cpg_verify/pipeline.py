"""
High-level orchestration of the CPG-Verify proof-of-concept workflow.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .effect_model import PatchEffectAnalyzer
from .explanation import (
    ExplanationBundle,
    build_prompt_context,
    build_natural_context,
    generate_explanations,
)
from .intervention import InterventionSpec, InterventionPlanner, refine_intervention
from .patch import PatchGenerator, PatchResult
from .pcg_builder import PCGBuilder, PCGBuilderConfig
from .scm import SCMBuilder
from .verification import VerificationResult, Verifier


@dataclass
class PipelineArtifacts:
    pcg: Dict[str, object]
    scm: Dict[str, object]
    intervention: InterventionSpec
    patch: PatchResult
    effect: Dict[str, object]
    verification: VerificationResult
    iterations: List[Dict[str, object]]
    explanations: ExplanationBundle


class CPGVerifyPipeline:
    def __init__(
        self,
        config: PCGBuilderConfig | None = None,
        *,
        strategy: str = "formal",
        explain_mode: str = "template",
        explanation_patch_source: str = "ground_truth",
        explanation_extra_prompt: str | None = None,
    ) -> None:
        self.config = config or PCGBuilderConfig()
        self.effect_analyzer = PatchEffectAnalyzer(self.config)
        self.strategy = strategy
        self.explain_mode = explain_mode
        if explanation_patch_source not in {"generated", "ground_truth"}:
            raise ValueError("explanation_patch_source must be 'generated' or 'ground_truth'")
        self.explanation_patch_source = explanation_patch_source
        self.explanation_extra_prompt = explanation_extra_prompt

    def run(self, vuln_case: Dict[str, object]) -> PipelineArtifacts:
        program = vuln_case["source"].strip("\n")
        vuln_info = {
            "location": vuln_case["vuln_line"],
            "cwe_id": vuln_case.get("cwe_id", "Unknown"),
        }
        pcg, diagnostics = PCGBuilder(program, vuln_info, self.config).build()
        scm = SCMBuilder(pcg).derive()
        intervention = InterventionPlanner(pcg, scm).compute()
        iterations: List[Dict[str, object]] = []
        spec = intervention
        patch: PatchResult | None = None
        effect_dict: Dict[str, object] | None = None
        verification: VerificationResult | None = None
        max_iterations = vuln_case.get("max_iterations", 3)
        natural_context = None
        if self.strategy == "formal":
            natural_context = build_prompt_context(pcg, scm, intervention)
        elif self.strategy in {"natural", "only_natural"}:
            natural_context = build_natural_context(pcg, scm, intervention)
        for _ in range(max_iterations):
            patch = PatchGenerator(
                pcg,
                program,
                vuln_case["vuln_line"],
                vuln_case.get("signature", ""),
                strategy=self.strategy,
                natural_context=natural_context if self.strategy != "minimal" else None,
            ).generate(spec)
            effect = self.effect_analyzer.analyze(
                original_condition=scm.vulnerable_condition,
                patched_code=patch.patched_code,
                signature=vuln_case.get("signature", ""),
            )
            verifier = Verifier(vuln_case.get("signature", ""))
            verification = verifier.verify(patch)
            iterations.append(
                {
                    "patch_method": patch.method,
                    "effect": effect.as_dict(),
                    "verification": verification.as_dict(),
                }
            )
            if verification.overall:
                effect_dict = effect.as_dict()
                break
            feedback = " ".join(
                outcome.feedback
                for outcome in [verification.symbolic, verification.model_check, verification.fuzzing]
                if not outcome.success and outcome.feedback
            )
            spec = refine_intervention(spec, feedback)
            if self.strategy == "formal":
                natural_context = build_prompt_context(pcg, scm, spec)
            elif self.strategy in {"natural", "only_natural"}:
                natural_context = build_natural_context(pcg, scm, spec)
            effect_dict = effect.as_dict()
        if patch is None or verification is None or effect_dict is None:
            raise RuntimeError("Patch pipeline did not produce results")
        patch_for_explanations = patch
        effect_for_explanations = effect_dict
        verification_for_output = verification
        if (
            self.explanation_patch_source == "ground_truth"
            and vuln_case.get("ground_truth")
        ):
            ground_truth_code = vuln_case["ground_truth"]
            patch_for_explanations = PatchResult(
                patched_code=ground_truth_code,
                diff=PatchGenerator._diff(program, ground_truth_code),
                applied_guards=[],
                method="ground_truth",
            )
            gt_effect = self.effect_analyzer.analyze(
                original_condition=scm.vulnerable_condition,
                patched_code=ground_truth_code,
                signature=vuln_case.get("signature", ""),
            )
            effect_for_explanations = gt_effect.as_dict()
            verification_for_output = Verifier(vuln_case.get("signature", "")).verify(
                patch_for_explanations
            )

        explanations = generate_explanations(
            pcg,
            scm,
            spec,
            patch_for_explanations,
            effect_for_explanations,
            mode=self.explain_mode,
            strategy=self.strategy,
            signature=vuln_case.get("signature", ""),
            extra_instructions=self.explanation_extra_prompt,
        )
        final_spec = spec
        return PipelineArtifacts(
            pcg=self._pcg_to_dict(pcg, diagnostics),
            scm=scm.as_dict(),
            intervention=final_spec,
            patch=patch_for_explanations,
            effect=effect_for_explanations,
            verification=verification_for_output,
            iterations=iterations,
            explanations=explanations,
        )

    @staticmethod
    def _pcg_to_dict(pcg, diagnostics: Dict[str, object]) -> Dict[str, object]:
        return {
            "nodes": [
                {
                    "id": node.node_id,
                    "type": node.node_type,
                    "description": node.description,
                    "location": node.location,
                }
                for node in pcg.nodes.values()
            ],
            "edges": [edge.__dict__ for edge in pcg.edges],
            "diagnostics": diagnostics,
        }
