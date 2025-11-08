"""
High-level orchestration of the PatchScribe proof-of-concept workflow.
"""
from __future__ import annotations

from contextlib import nullcontext
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
from .patch_quality import PatchQualityEvaluator
from .formal_spec import (
    FormalBugExplanation,
    FormalPatchExplanation,
    generate_E_bug,
    generate_E_patch,
)
from .intervention import InterventionSpec, InterventionPlanner, refine_intervention
from .patch import PatchGenerator, PatchResult
from .llm import LLMClient
from .pcg_builder import PCGBuilder, PCGBuilderConfig
from .performance import (
    PerformanceProfiler,
    PerformanceProfile,
    measure_code_complexity,
    categorize_complexity,
)
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
    patch_quality: Dict[str, object] | None = None


class PatchScribePipeline:
    def __init__(
        self,
        config: PCGBuilderConfig | None = None,
        *,
        strategy: str = "formal",
        explain_mode: str = "template",
        explanation_patch_source: str = "generated",
        explanation_extra_prompt: str | None = None,
        enable_consistency_check: bool = True,
        enable_performance_profiling: bool = False,
        llm_client: LLMClient | None = None,
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
        self.llm_client = llm_client or LLMClient()
        self.patch_quality_evaluator = PatchQualityEvaluator(self.llm_client)

    def run(self, vuln_case: Dict[str, object]) -> PipelineArtifacts:
        program = vuln_case["source"].strip("\n")
        vuln_info = {
            "location": vuln_case["vuln_line"],
            "cwe_id": vuln_case.get("cwe_id", "Unknown"),
        }
        
        # Initialize profiler
        profiler = PerformanceProfiler() if self.enable_performance_profiling else None
        code_complexity = None
        if profiler:
            profiler.start_total()
            code_complexity = measure_code_complexity(program)
        
        # Phase 1: Vulnerability Formalization
        phase1_context = profiler.profile_phase("phase1_formalization") if profiler else nullcontext()
        with phase1_context:
            pcg, diagnostics = PCGBuilder(program, vuln_info, self.config).build()
            scm = SCMBuilder(pcg).derive()
            intervention = InterventionPlanner(pcg, scm).compute()
            
            # Generate E_bug (Formal Bug Explanation)
            E_bug = generate_E_bug(pcg, scm, intervention, vuln_info)
        
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

        patch_generator = PatchGenerator(
            pcg,
            program,
            vuln_case["vuln_line"],
            vuln_case.get("signature", ""),
            llm_client=self.llm_client,
            strategy=self.strategy,
            natural_context=natural_context if self.strategy != "minimal" else None,
        )
        verifier = Verifier(
            vuln_case.get("signature", ""),
            original_code=program,
            vuln_line=vuln_case.get("vuln_line"),
        )
        
        # Phase 2 & 3: Iterative generation and verification
        for iteration_idx in range(max_iterations):
            generation_ctx = profiler.profile_phase("phase2_generation") if profiler else nullcontext()
            with generation_ctx:
                if self.strategy != "minimal":
                    patch_generator.natural_context = natural_context
                else:
                    patch_generator.natural_context = None
                patch = patch_generator.generate(spec)
                
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
            
            verification_ctx = profiler.profile_phase("phase3_verification") if profiler else nullcontext()
            with verification_ctx:
                verification = verifier.verify(patch, expected_condition=scm.vulnerable_condition)
                
                # Consistency checking
                if self.consistency_checker:
                    consistency = self.consistency_checker.check(E_bug, E_patch)
            
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
                    "original_code": program,
                    "patched_code": patch.patched_code,
                    "vulnerability_signature": vuln_case.get("signature", ""),
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

        auto_instructions = self._build_case_prompt_directives(vuln_case)
        combined_instructions_parts: List[str] = []
        if self.explanation_extra_prompt:
            extra = self.explanation_extra_prompt.strip()
            if extra:
                combined_instructions_parts.append(extra)
        if auto_instructions:
            combined_instructions_parts.append(auto_instructions)
        combined_instructions = "\n\n".join(combined_instructions_parts) if combined_instructions_parts else None

        explanations = generate_explanations(
            pcg,
            scm,
            spec,
            patch_for_explanations,
            effect_for_explanations,
            mode=self.explain_mode,
            strategy=self.strategy,
            signature=vuln_case.get("signature", ""),
            extra_instructions=combined_instructions,
        )
        explanation_metrics = self.explanation_evaluator.evaluate(
            explanations,
            case=vuln_case,
            use_llm=self.explain_mode in {"llm", "both"},
        )
        patch_quality = self.patch_quality_evaluator.evaluate(
            patch_for_explanations,
            E_bug,
            E_patch_for_output,
            verification_for_output,
        )
        final_spec = spec
        
        # End performance profiling
        if profiler:
            if code_complexity is not None:
                loc = code_complexity.get("lines_of_code", 0)
                code_complexity["complexity_bucket"] = categorize_complexity(loc)
            case_id = (
                vuln_case.get("id")
                or vuln_case.get("case_id")
                or vuln_case.get("filename")
                or "unknown"
            )
            performance_profile = profiler.end_total(
                case_id=case_id,
                iteration_count=len(iterations),
                code_complexity=code_complexity,
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
            patch_quality=patch_quality.as_dict(),
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

    @staticmethod
    def _build_case_prompt_directives(case: Dict[str, object]) -> str | None:
        directives: List[str] = []

        cwe = case.get("cwe_id")
        if isinstance(cwe, str) and cwe and cwe.lower() != "unknown":
            directives.append(f"Explicitly cite the vulnerability classification `{cwe}`.")

        cve = case.get("cve_id")
        if isinstance(cve, str) and cve:
            directives.append(f"Mention the CVE identifier `{cve}` if relevant.")

        vuln_line = case.get("vuln_line")
        if isinstance(vuln_line, int) and vuln_line > 0:
            directives.append(f"State that the vulnerable code is located at line {vuln_line}.")

        signature = case.get("signature", "")
        if isinstance(signature, str) and signature.strip():
            normalized = " ".join(signature.strip().split())
            if len(normalized) > 120:
                normalized = normalized[:117].rstrip() + "..."
            directives.append(f"Reference the vulnerable statement `{normalized}` when describing the root cause.")

        if directives:
            directives.append("Describe the causal chain that leads to the vulnerability in one clear sentence.")
            directives.append("Close with a sentence explaining why the patched condition satisfies the formal requirements.")
            return "Follow these additional requirements:\n" + "\n".join(f"- {item}" for item in directives)

        return None
