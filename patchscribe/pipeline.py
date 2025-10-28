"""
High-level orchestration of the PatchScribe proof-of-concept workflow.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .consistency_checker import ConsistencyChecker, ConsistencyResult
from .effect_model import PatchEffectAnalyzer
from .explanation import (
    ExplanationBundle,
    build_prompt_context,
    build_natural_context,
    generate_explanations,
)
from .explanation_quality import ExplanationEvaluator
from .formal_spec import (
    FormalBugExplanation,
    FormalPatchExplanation,
    generate_E_bug,
    generate_E_patch,
)
from .intervention import InterventionSpec, InterventionPlanner, refine_intervention
from .patch import PatchGenerator, PatchResult
from .pcg_builder import PCGBuilder, PCGBuilderConfig
from .performance import PerformanceProfiler, PerformanceProfile, measure_code_complexity
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
    explanation_metrics: Dict[str, object]
    # New: Formal specifications
    E_bug: FormalBugExplanation | None = None
    E_patch: FormalPatchExplanation | None = None
    consistency: ConsistencyResult | None = None
    # Performance metrics
    performance: PerformanceProfile | None = None


class PatchScribePipeline:
    def __init__(
        self,
        config: PCGBuilderConfig | None = None,
        *,
        strategy: str = "formal",
        explain_mode: str = "template",
        explanation_patch_source: str = "ground_truth",
        explanation_extra_prompt: str | None = None,
        enable_consistency_check: bool = True,
        enable_performance_profiling: bool = False,
    ) -> None:
        self.config = config or PCGBuilderConfig()
        self.effect_analyzer = PatchEffectAnalyzer(self.config)
        self.strategy = strategy
        self.explain_mode = explain_mode
        if explanation_patch_source not in {"generated", "ground_truth"}:
            raise ValueError("explanation_patch_source must be 'generated' or 'ground_truth'")
        self.explanation_patch_source = explanation_patch_source
        self.explanation_extra_prompt = explanation_extra_prompt
        self.explanation_evaluator = ExplanationEvaluator()
        self.enable_consistency_check = enable_consistency_check
        self.consistency_checker = ConsistencyChecker() if enable_consistency_check else None
        self.enable_performance_profiling = enable_performance_profiling

    def run(self, vuln_case: Dict[str, object]) -> PipelineArtifacts:
        program = vuln_case["source"].strip("\n")
        vuln_info = {
            "location": vuln_case["vuln_line"],
            "cwe_id": vuln_case.get("cwe_id", "Unknown"),
        }
        
        # Initialize profiler
        profiler = PerformanceProfiler() if self.enable_performance_profiling else None
        if profiler:
            profiler.start_total()
            code_complexity = measure_code_complexity(program)
        
        # Phase 1: Vulnerability Formalization
        if profiler:
            phase1_context = profiler.profile_phase("phase1_formalization")
            phase1_context.__enter__()
        
        pcg, diagnostics = PCGBuilder(program, vuln_info, self.config).build()
        scm = SCMBuilder(pcg).derive()
        intervention = InterventionPlanner(pcg, scm).compute()
        
        # Generate E_bug (Formal Bug Explanation)
        E_bug = generate_E_bug(pcg, scm, intervention, vuln_info)
        
        if profiler:
            phase1_context.__exit__(None, None, None)
        
        iterations: List[Dict[str, object]] = []
        spec = intervention
        patch: PatchResult | None = None
        effect_dict: Dict[str, object] | None = None
        verification: VerificationResult | None = None
        consistency: ConsistencyResult | None = None
        E_patch: FormalPatchExplanation | None = None
        first_attempt_success: bool | None = None
        
        max_iterations = vuln_case.get("max_iterations", 3)
        natural_context = None
        if self.strategy == "formal":
            natural_context = build_prompt_context(pcg, scm, intervention)
        elif self.strategy in {"natural", "only_natural"}:
            natural_context = build_natural_context(pcg, scm, intervention)
        
        # Phase 2: Theory-Guided Patch Generation with iteration
        if profiler:
            phase2_context = profiler.profile_phase("phase2_generation")
            phase2_context.__enter__()
        
        for iteration_idx in range(max_iterations):
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
            effect_dict = effect.as_dict()
            
            # Generate E_patch (Formal Patch Explanation)
            E_patch = generate_E_patch(
                patch.patched_code,
                patch.diff,
                E_bug,
                pcg,
                scm,
                effect_dict
            )
            
            # Phase 3: Dual Verification
            if profiler and iteration_idx == 0:
                phase3_context = profiler.profile_phase("phase3_verification")
                phase3_context.__enter__()
            
            verifier = Verifier(
                vuln_case.get("signature", ""),
                original_code=program,
                vuln_line=vuln_case.get("vuln_line"),
            )
            verification = verifier.verify(patch, expected_condition=scm.vulnerable_condition)
            
            # Consistency checking
            if self.consistency_checker:
                consistency = self.consistency_checker.check(E_bug, E_patch)
            
            if profiler and iteration_idx == 0:
                phase3_context.__exit__(None, None, None)
            
            # Record first attempt success
            if iteration_idx == 0:
                if self.consistency_checker:
                    first_attempt_success = verification.overall and consistency.overall
                else:
                    first_attempt_success = verification.overall
            
            iterations.append(
                {
                    "patch_method": patch.method,
                    "effect": effect_dict,
                    "verification": verification.as_dict(),
                    "consistency": consistency.as_dict() if consistency else None,
                    "first_attempt": (iteration_idx == 0),
                }
            )
            
            # Check overall success (verification + consistency)
            overall_success = verification.overall
            if self.consistency_checker and consistency:
                overall_success = overall_success and consistency.overall
            
            if overall_success:
                break
            
            # Generate feedback for refinement
            feedback_parts = []
            
            # Verification feedback
            for outcome in [verification.symbolic, verification.model_check, verification.fuzzing]:
                if not outcome.success and outcome.feedback:
                    feedback_parts.append(outcome.feedback)
            
            # Consistency feedback
            if consistency and not consistency.overall:
                if not consistency.causal_coverage.success:
                    feedback_parts.append(consistency.causal_coverage.feedback)
                if not consistency.completeness.success:
                    feedback_parts.append(consistency.completeness.feedback)
            
            feedback = " ".join(feedback_parts)
            spec = refine_intervention(spec, feedback)
            
            if self.strategy == "formal":
                natural_context = build_prompt_context(pcg, scm, spec)
            elif self.strategy in {"natural", "only_natural"}:
                natural_context = build_natural_context(pcg, scm, spec)
        
        # End Phase 2 profiling
        if profiler:
            phase2_context.__exit__(None, None, None)
        
        if patch is None or verification is None or effect_dict is None:
            raise RuntimeError("Patch pipeline did not produce results")
        
        patch_for_explanations = patch
        effect_for_explanations = effect_dict
        verification_for_output = verification
        E_patch_for_output = E_patch
        
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
            verification_for_output = Verifier(
                vuln_case.get("signature", ""),
                original_code=program,
                vuln_line=vuln_case.get("vuln_line"),
            ).verify(
                patch_for_explanations,
                expected_condition=scm.vulnerable_condition,
            )
            
            # Regenerate E_patch for ground truth
            E_patch_for_output = generate_E_patch(
                ground_truth_code,
                patch_for_explanations.diff,
                E_bug,
                pcg,
                scm,
                effect_for_explanations
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
        explanation_metrics = self.explanation_evaluator.evaluate(
            explanations,
            case=vuln_case,
            use_llm=self.explain_mode in {"llm", "both"},
        )
        final_spec = spec
        
        # End performance profiling
        if profiler:
            case_id = vuln_case.get("id", "unknown")
            performance_profile = profiler.end_total(
                case_id=case_id,
                iteration_count=len(iterations),
                code_complexity=None  # TODO: Add code complexity metrics
            )
        else:
            performance_profile = None
        
        return PipelineArtifacts(
            pcg=self._pcg_to_dict(pcg, diagnostics),
            scm=scm.as_dict(),
            intervention=final_spec,
            patch=patch_for_explanations,
            effect=effect_for_explanations,
            verification=verification_for_output,
            iterations=iterations,
            explanations=explanations,
            explanation_metrics={
                "checklist_coverage": explanation_metrics.checklist_coverage,
                "checklist_hits": explanation_metrics.checklist_hits,
                "missing_items": explanation_metrics.missing_items,
                "llm_scores": explanation_metrics.llm_scores,
                "llm_raw": explanation_metrics.llm_raw,
                "first_attempt_success": first_attempt_success,
            },
            E_bug=E_bug,
            E_patch=E_patch_for_output,
            consistency=consistency,
            performance=performance_profile,
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
