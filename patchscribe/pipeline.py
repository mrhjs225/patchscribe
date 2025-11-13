"""
High-level orchestration of the PatchScribe proof-of-concept workflow.
"""
from __future__ import annotations

import hashlib
import os
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
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
from .llm import LLMClient, PromptOptions
from .pcg_builder import PCGBuilder, PCGBuilderConfig
from .pcg import ProgramCausalGraph
from .performance import (
    PerformanceProfiler,
    PerformanceProfile,
    measure_code_complexity,
    categorize_complexity,
)
from .scm import SCMBuilder
from .spec_builder import build_specification_for_condition, SpecificationLevel
from .stage1_cache import Stage1Cache, Stage1Data
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


@dataclass
class IterationOutcome:
    patch: PatchResult
    effect: Dict[str, object]
    e_patch: FormalPatchExplanation | None
    iterations: List[Dict[str, object]]
    consistency: ConsistencyResult | None
    first_attempt_success: bool | None
    spec: InterventionSpec


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
        stage1_cache_dir: str | Path | None = None,
        force_stage1_recompute: bool = False,
        prompt_options: PromptOptions | None = None,
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
        self.llm_client.register_telemetry_hook(self._handle_llm_telemetry)
        self._active_profiler: PerformanceProfiler | None = None
        self.prompt_options = prompt_options
        self.patch_quality_evaluator = PatchQualityEvaluator(self.llm_client)
        self.verifier = Verifier()
        resolved_cache_dir = self._resolve_stage1_cache_dir(stage1_cache_dir)
        self.stage1_cache = Stage1Cache(resolved_cache_dir) if resolved_cache_dir else None
        self.force_stage1_recompute = force_stage1_recompute

    def _map_strategy_to_condition(self) -> str:
        """Map strategy to condition name (c1-c4)"""
        mapping = {
            'minimal': 'c1',
            'only_natural': 'c1',
            'natural': 'c2',
            'formal': 'c3',  # Default to c3
        }
        # c4 is distinguished by enable_consistency_check
        if self.strategy == 'formal' and self.enable_consistency_check:
            return 'c4'
        return mapping.get(self.strategy, 'c3')

    def run(self, vuln_case: Dict[str, object]) -> PipelineArtifacts:
        program, vuln_info = self._extract_program_and_vuln_info(vuln_case)
        profiler, code_complexity = self._init_profiler(program)

        stage1 = self._build_stage1_with_profiling(
            vuln_case=vuln_case,
            program=program,
            vuln_info=vuln_info,
            profiler=profiler,
        )
        pcg = stage1.pcg
        diagnostics = stage1.diagnostics
        scm = stage1.scm
        e_bug = stage1.e_bug

        max_iterations = vuln_case.get("max_iterations", 3)
        natural_context = self._build_natural_context(pcg, scm, stage1.intervention)
        spec_level = self._build_specification_level(
            vuln_case=vuln_case,
            intervention=stage1.intervention,
            e_bug=e_bug,
            natural_context=natural_context,
        )

        patch_generator = PatchGenerator(
            pcg,
            program,
            vuln_case["vuln_line"],
            vuln_case.get("signature", ""),
            llm_client=self.llm_client,
            spec_level=spec_level,
            strategy=self.strategy,
            natural_context=natural_context if self.strategy != "minimal" else None,
            prompt_options=self.prompt_options,
        )

        iteration_result = self._run_patch_iterations(
            vuln_case=vuln_case,
            stage1=stage1,
            patch_generator=patch_generator,
            program=program,
            initial_spec=stage1.intervention,
            initial_context=natural_context,
            max_iterations=max_iterations,
            profiler=profiler,
        )

        (
            patch_for_explanations,
            effect_for_explanations,
            E_patch_for_output,
        ) = self._resolve_patch_for_explanations(
            vuln_case=vuln_case,
            program=program,
            stage1=stage1,
            generated_patch=iteration_result.patch,
            generated_effect=iteration_result.effect,
            generated_e_patch=iteration_result.e_patch,
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
            iteration_result.spec,
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
            e_bug,
            E_patch_for_output,
            iteration_result.consistency,
        )
        final_spec = iteration_result.spec
        ground_truth_meta = vuln_case.get("verification")
        if not isinstance(ground_truth_meta, dict):
            ground_truth_meta = vuln_case.get("ground_truth_meta")
        if not isinstance(ground_truth_meta, dict):
            ground_truth_meta = None
        poc_command = vuln_case.get("poc_command") or vuln_case.get("poc")
        verification = self.verifier.verify(
            original_code=program,
            patched_code=patch_for_explanations.patched_code,
            E_bug=e_bug,
            E_patch=E_patch_for_output,
            ground_truth=ground_truth_meta,
            poc_command=poc_command,
        )
        
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
                iteration_count=len(iteration_result.iterations),
                code_complexity=code_complexity,
            )
        else:
            performance_profile = None
        
        # Create a minimal verification result for backwards compatibility
        if self._active_profiler is profiler:
            self._active_profiler = None

        return PipelineArtifacts(
            pcg=self._pcg_to_dict(pcg, diagnostics),
            scm=scm.as_dict(),
            intervention=final_spec,
            patch=patch_for_explanations,
            effect=effect_for_explanations,
            verification=verification,
            iterations=iteration_result.iterations,
            explanations=explanations,
            explanation_metrics={
                "checklist_coverage": explanation_metrics.checklist_coverage,
                "checklist_hits": explanation_metrics.checklist_hits,
                "missing_items": explanation_metrics.missing_items,
                "llm_scores": explanation_metrics.llm_scores,
                "llm_raw": explanation_metrics.llm_raw,
                "first_attempt_success": iteration_result.first_attempt_success,
                "consistency_confidence": (
                    iteration_result.consistency.confidence_level if iteration_result.consistency else None
                ),
            },
            E_bug=e_bug,
            E_patch=E_patch_for_output,
            consistency=iteration_result.consistency,
            performance=performance_profile,
            patch_quality=patch_quality.as_dict(),
        )

    def _extract_program_and_vuln_info(
        self,
        vuln_case: Dict[str, object],
    ) -> tuple[str, Dict[str, object]]:
        program = vuln_case["source"].strip("\n")
        vuln_info = {
            "location": vuln_case["vuln_line"],
            "cwe_id": vuln_case.get("cwe_id", "Unknown"),
        }
        return program, vuln_info

    def _init_profiler(
        self,
        program: str,
    ) -> tuple[PerformanceProfiler | None, Dict[str, object] | None]:
        if not self.enable_performance_profiling:
            self._active_profiler = None
            return None, None
        profiler = PerformanceProfiler()
        profiler.start_total()
        code_complexity = measure_code_complexity(program)
        self._active_profiler = profiler
        return profiler, code_complexity

    def _build_stage1_with_profiling(
        self,
        *,
        vuln_case: Dict[str, object],
        program: str,
        vuln_info: Dict[str, object],
        profiler: PerformanceProfiler | None,
    ) -> Stage1Data:
        phase1_context = profiler.profile_phase("phase1_formalization") if profiler else nullcontext()
        with phase1_context:
            return self._load_or_build_stage1(vuln_case, program, vuln_info)

    def _build_natural_context(
        self,
        pcg: ProgramCausalGraph,
        scm,
        spec: InterventionSpec,
    ) -> str | None:
        if self.strategy == "formal":
            return build_prompt_context(pcg, scm, spec)
        if self.strategy in {"natural", "only_natural"}:
            return build_natural_context(pcg, scm, spec)
        return None

    def _build_specification_level(
        self,
        *,
        vuln_case: Dict[str, object],
        intervention: InterventionSpec,
        e_bug: FormalBugExplanation,
        natural_context: str | None,
    ) -> SpecificationLevel:
        condition = self._map_strategy_to_condition()
        return build_specification_for_condition(
            condition=condition,
            vuln_case=vuln_case,
            intervention_spec=intervention,
            ebug=e_bug,
            natural_context=natural_context,
        )

    def _run_patch_iterations(
        self,
        *,
        vuln_case: Dict[str, object],
        stage1: Stage1Data,
        patch_generator: PatchGenerator,
        program: str,
        initial_spec: InterventionSpec,
        initial_context: str | None,
        max_iterations: int,
        profiler: PerformanceProfiler | None,
    ) -> IterationOutcome:
        iterations: List[Dict[str, object]] = []
        current_spec = initial_spec
        current_context = initial_context
        patch: PatchResult | None = None
        effect_dict: Dict[str, object] | None = None
        e_patch: FormalPatchExplanation | None = None
        consistency: ConsistencyResult | None = None
        first_attempt_success: bool | None = None

        for iteration_idx in range(max_iterations):
            generation_ctx = profiler.profile_phase("phase2_generation") if profiler else nullcontext()
            with generation_ctx:
                patch_generator.natural_context = (
                    None if self.strategy == "minimal" else current_context
                )
                patch = patch_generator.generate(current_spec)
                effect = self.effect_analyzer.analyze(
                    original_condition=stage1.scm.vulnerable_condition,
                    patched_code=patch.patched_code,
                    signature=vuln_case.get("signature", ""),
                )
                effect_dict = effect.as_dict()
                e_patch = generate_E_patch(
                    patch.patched_code,
                    patch.diff,
                    stage1.e_bug,
                    stage1.pcg,
                    stage1.scm,
                    effect_dict,
                )

            if self.consistency_checker:
                consistency = self.consistency_checker.check(stage1.e_bug, e_patch)
            else:
                consistency = None

            if iteration_idx == 0:
                if self.consistency_checker and consistency:
                    first_attempt_success = consistency.accepted
                else:
                    first_attempt_success = True

            iterations.append(
                {
                    "patch_method": patch.method,
                    "effect": effect_dict,
                    "consistency": consistency.as_dict() if consistency else None,
                    "first_attempt": iteration_idx == 0,
                    "original_code": program,
                    "patched_code": patch.patched_code,
                    "vulnerability_signature": vuln_case.get("signature", ""),
                }
            )

            overall_success = False
            if self.consistency_checker and consistency:
                overall_success = consistency.accepted
            else:
                overall_success = True

            if overall_success:
                break

            feedback = self._build_consistency_feedback(consistency)
            current_spec = refine_intervention(current_spec, feedback)
            current_context = self._build_natural_context(stage1.pcg, stage1.scm, current_spec)

        if patch is None or effect_dict is None:
            raise RuntimeError("Patch pipeline did not produce results")

        return IterationOutcome(
            patch=patch,
            effect=effect_dict,
            e_patch=e_patch,
            iterations=iterations,
            consistency=consistency,
            first_attempt_success=first_attempt_success,
            spec=current_spec,
        )

    def _build_consistency_feedback(self, consistency: ConsistencyResult | None) -> str:
        if not consistency or consistency.overall:
            return ""
        parts: List[str] = []
        if not consistency.causal_coverage.passed and getattr(consistency.causal_coverage, "feedback", None):
            parts.append(consistency.causal_coverage.feedback)
        if not consistency.completeness.passed and getattr(consistency.completeness, "feedback", None):
            parts.append(consistency.completeness.feedback)
        return " ".join(part for part in parts if part)

    def _resolve_patch_for_explanations(
        self,
        *,
        vuln_case: Dict[str, object],
        program: str,
        stage1: Stage1Data,
        generated_patch: PatchResult,
        generated_effect: Dict[str, object],
        generated_e_patch: FormalPatchExplanation | None,
    ) -> tuple[PatchResult, Dict[str, object], FormalPatchExplanation | None]:
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
                original_condition=stage1.scm.vulnerable_condition,
                patched_code=ground_truth_code,
                signature=vuln_case.get("signature", ""),
            ).as_dict()
            regenerated_e_patch = generate_E_patch(
                ground_truth_code,
                patch_for_explanations.diff,
                stage1.e_bug,
                stage1.pcg,
                stage1.scm,
                gt_effect,
            )
            return patch_for_explanations, gt_effect, regenerated_e_patch

        return generated_patch, generated_effect, generated_e_patch

    @staticmethod
    def _pcg_to_dict(pcg, diagnostics: Dict[str, object]) -> Dict[str, object]:
        data = pcg.to_dict()
        data["diagnostics"] = diagnostics
        return data

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

    # ------------------------------------------------------------------
    # Stage-1 caching helpers
    # ------------------------------------------------------------------

    def precompute_stage1(self, vuln_case: Dict[str, object]) -> Stage1Data:
        """Run only Stage-1 and populate cache without invoking any LLMs."""
        program = vuln_case["source"].strip("\n")
        vuln_info = {
            "location": vuln_case["vuln_line"],
            "cwe_id": vuln_case.get("cwe_id", "Unknown"),
        }
        return self._load_or_build_stage1(
            vuln_case,
            program,
            vuln_info,
            force_recompute=self.force_stage1_recompute or False,
        )

    def _load_or_build_stage1(
        self,
        vuln_case: Dict[str, object],
        program: str,
        vuln_info: Dict[str, object],
        *,
        force_recompute: bool = False,
    ) -> Stage1Data:
        case_id = self._resolve_case_id(vuln_case)
        source_hash = hashlib.sha256(program.encode("utf-8")).hexdigest()
        use_cache = (
            self.stage1_cache is not None
            and not self.force_stage1_recompute
            and not force_recompute
        )
        if use_cache:
            cached = self.stage1_cache.load(case_id, source_hash)
            if cached:
                return cached

        stage1 = self._build_stage1(program, vuln_info)

        if self.stage1_cache:
            case_meta = vuln_case.get("metadata") or {}
            metadata = {
                "case_id": case_id,
                "dataset": case_meta.get("dataset"),
                "cwe_id": vuln_case.get("cwe_id"),
                "cve_id": vuln_case.get("cve_id"),
            }
            self.stage1_cache.store(case_id, source_hash, stage1, metadata=metadata)
        return stage1

    def _build_stage1(
        self,
        program: str,
        vuln_info: Dict[str, object],
    ) -> Stage1Data:
        pcg, diagnostics = PCGBuilder(program, vuln_info, self.config).build()
        scm = SCMBuilder(pcg).derive()
        intervention = InterventionPlanner(pcg, scm).compute()
        e_bug = generate_E_bug(pcg, scm, intervention, vuln_info)
        stats = self._collect_analysis_stats(pcg, diagnostics)
        return Stage1Data(
            pcg=pcg,
            diagnostics=diagnostics,
            scm=scm,
            intervention=intervention,
            e_bug=e_bug,
            analysis_stats=stats,
        )

    @staticmethod
    def _resolve_case_id(case: Dict[str, object]) -> str:
        return (
            case.get("id")
            or case.get("case_id")
            or case.get("filename")
            or "unknown_case"
        )

    @staticmethod
    def _resolve_stage1_cache_dir(user_dir: str | Path | None) -> Path | None:
        env_value = os.environ.get("PATCHSCRIBE_STAGE1_CACHE")
        if env_value:
            token = env_value.strip().lower()
            if token in {"0", "false", "disable", "disabled", "off"}:
                return None
            return Path(env_value)
        if user_dir is not None:
            return Path(user_dir)
        # Default cache inside workspace
        return Path(".patchscribe_cache") / "stage1"

    @staticmethod
    def _collect_analysis_stats(
        pcg: ProgramCausalGraph,
        diagnostics: Dict[str, object],
    ) -> Dict[str, object]:
        summary = diagnostics.get("pcg_summary") or {}
        absence = diagnostics.get("absence_findings") or []
        return {
            "pcg_nodes": summary.get("node_count", len(pcg.nodes)),
            "pcg_edges": summary.get("edge_count", len(pcg.edges)),
            "missing_guard_nodes": summary.get("missing_guard_count", 0),
            "absence_findings": absence,
        }

    def _handle_llm_telemetry(self, record: Dict[str, object]) -> None:
        """Forward LLM telemetry records to the active profiler."""
        if self._active_profiler:
            self._active_profiler.record_llm_call(record)
