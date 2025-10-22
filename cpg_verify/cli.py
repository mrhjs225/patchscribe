"""
Command-line entry point for executing the CPG-Verify PoC pipeline.
"""
from __future__ import annotations

import argparse
import json
import difflib
import os
from pathlib import Path
from typing import Dict, Optional

from .dataset import load_cases
from .evaluation import Evaluator
from .pipeline import CPGVerifyPipeline
from .baselines import BASELINES


def _serialize_intervention(intervention) -> Dict[str, object]:
    return {
        "summary": intervention.summary,
        "interventions": [
            {
                "target_line": item.target_line,
                "enforce": item.enforce,
                "rationale": item.rationale,
            }
            for item in intervention.interventions
        ],
    }


def _serialize_patch(patch) -> Dict[str, object]:
    return {
        "diff": patch.diff,
        "guards": patch.applied_guards,
        "method": patch.method,
        "llm_metadata": patch.llm_metadata,
        "patched_code": patch.patched_code,
    }


def _emit_output(data, output_path: str | None, fmt: str) -> None:
    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if fmt == "markdown":
            content = _format_markdown(data)
            path.write_text(content)
        else:
            path.write_text(json.dumps(data, indent=2))
        print(f"Saved results to {path}")
    else:
        print(json.dumps(data, indent=2))


def _format_markdown(data: Dict[str, object]) -> str:
    lines: list[str] = []
    if "metrics" in data and "cases" in data:
        lines.append("# CPG-Verify Evaluation Report\n")
        lines.append("## Metrics\n")
        for key, value in data["metrics"].items():
            lines.append(f"- **{key}**: {value}")
        lines.append("\n## Cases\n")
        for case in data["cases"]:
            lines.extend(_format_case_markdown(case))
    else:
        lines.append("# CPG-Verify Run Results\n")
        for case_id, case_data in data.items():
            lines.append(f"## Case: {case_id}\n")
            case_meta = case_data.get("case", {})
            if case_meta:
                lines.append("### Case Metadata\n")
                for key, value in case_meta.items():
                    if key in {"ground_truth_preview", "ground_truth", "original_code"}:
                        continue
                    lines.append(f"- **{key}**: {value}")
                preview = case_meta.get("ground_truth_preview")
                if preview:
                    lines.append("\n### Reference Patch (excerpts)\n")
                    lines.append("```c")
                    lines.append(preview)
                    lines.append("```")
            original_code = case_meta.get("original_code")
            ground_truth_code = case_meta.get("ground_truth")
            patched_code = case_data["patch"].get("patched_code")
            if original_code and ground_truth_code:
                lines.append("\n### Diff (Original vs. Ground Truth)\n")
                lines.append("```diff")
                lines.append(_code_diff(original_code, ground_truth_code, "original", "ground_truth"))
                lines.append("```")
            if original_code and patched_code:
                patch_method = case_data["patch"].get("method")
                label = "Provided Patch" if patch_method == "ground_truth" else "Generated Patch"
                to_label = "provided" if patch_method == "ground_truth" else "generated"
                lines.append(f"\n### Diff (Original vs. {label})\n")
                lines.append("```diff")
                lines.append(_code_diff(original_code, patched_code, "original", to_label))
                lines.append("```")
            else:
                lines.append("\n### Patch Diff\n")
                lines.append("```diff")
                lines.append(case_data["patch"].get("diff", "(no diff)"))
                lines.append("```")
            explanations = case_data.get("explanations", {})
            lines.append("\n### Natural Explanation (template)\n")
            lines.append(explanations.get("natural_template", "(not available)"))
            llm_text = explanations.get("natural_llm")
            if llm_text:
                lines.append("\n### Natural Explanation (LLM)\n")
                lines.append(llm_text)
            lines.append("\n### Formal Explanation\n")
            lines.append(explanations.get("formal", "(not available)"))
            lines.append("\n### Prompt Context\n")
            lines.append("```")
            lines.append(explanations.get("prompt_context", ""))
            lines.append("```")
            llm_prompt = explanations.get("llm_prompt")
            if llm_prompt:
                lines.append("\n### Explanation LLM Prompt\n")
                lines.append("```")
                lines.append(llm_prompt)
                lines.append("```")
            lines.append("\n---\n")
    return "\n".join(lines).strip() + "\n"


def _format_case_markdown(case: Dict[str, object]) -> list[str]:
    lines: list[str] = []
    lines.append(f"### {case['case_id']}\n")
    lines.append(f"- **Expected success**: {case['expected_success']}")
    lines.append(f"- **Actual success**: {case['actual_success']}")
    patch = case.get("patch", {})
    lines.append(f"- **Patch method**: {patch.get('method')}")
    lines.append("\n#### Verification\n")
    for stage, outcome in case.get("verification", {}).items():
        if isinstance(outcome, dict):
            lines.append(f"- **{stage}**: success={outcome.get('success')} ({outcome.get('details')})")
    explanations = case.get("explanations", {})
    prompt_context = explanations.get("prompt_context", "")
    if prompt_context:
        lines.append("\n### Prompt Context\n")
        lines.append("```\n" + prompt_context + "\n```")
    natural_template = explanations.get("natural_template")
    if natural_template:
        lines.append("\n### Natural Explanation (template)\n")
        lines.append(natural_template)
    natural_llm = explanations.get("natural_llm")
    if natural_llm:
        lines.append("\n### Natural Explanation (LLM)\n")
        lines.append(natural_llm)
    formal = explanations.get("formal")
    if formal:
        lines.append("\n### Formal Explanation\n")
        lines.append(formal)
    lines.append("\n")
    return lines


def _code_diff(original: Optional[str], target: Optional[str], from_label: str, to_label: str) -> str:
    if not original or not target:
        return "(diff unavailable)"
    diff = difflib.unified_diff(
        original.splitlines(),
        target.splitlines(),
        fromfile=from_label,
        tofile=to_label,
        lineterm="",
    )
    diff_lines = list(diff)
    if not diff_lines:
        return "(no differences)"
    max_lines = 200
    if len(diff_lines) > max_lines:
        diff_lines = diff_lines[:max_lines] + ["... (diff truncated)"]
    return "\n".join(diff_lines)
def _run_baselines(case: Dict[str, object], artifacts) -> Dict[str, object]:
    baselines = {}
    graph = artifacts.pcg
    for name, baseline in BASELINES.items():
        patch = baseline.generate(
            graph=None,
            program=case["source"],
            vuln_line=case["vuln_line"],
            signature=case.get("signature", ""),
            spec=artifacts.intervention,
        )
        baselines[name] = {
            "method": patch.method,
            "diff": patch.diff,
        }
    return baselines


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run CPG-Verify PoC pipeline")
    parser.add_argument("case_id", nargs="?", help="Dataset case identifier to process")
    parser.add_argument(
        "--evaluate",
        action="store_true",
        help="Aggregate metrics across the selected cases",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Include baseline patchers for comparative analysis",
    )
    parser.add_argument(
        "--dataset",
        choices=["poc", "zeroday"],
        default="poc",
        help="Dataset to load cases from",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Maximum number of cases to process",
    )
    parser.add_argument(
        "--strategy",
        choices=["formal", "natural", "only_natural", "minimal"],
        default="formal",
        help="Patch generation strategy",
    )
    parser.add_argument(
        "--explain-mode",
        choices=["template", "llm", "both"],
        default="template",
        help="Strategy for generating natural-language explanations",
    )
    parser.add_argument(
        "--explanation-patch-source",
        choices=["generated", "ground_truth"],
        default="ground_truth",
        help="Select which patch variant to feed into explanation generation",
    )
    parser.add_argument(
        "--output",
        help="Optional path to save results instead of printing to stdout",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="json",
        help="Output format when --output is provided",
    )
    parser.add_argument(
        "--llm-model",
        help="Override LLM model identifier (sets CPG_VERIFY_LLM_MODEL).",
    )
    parser.add_argument(
        "--llm-provider",
        help="Override LLM provider name (sets CPG_VERIFY_LLM_PROVIDER).",
    )
    parser.add_argument(
        "--llm-endpoint",
        help="Override LLM HTTP endpoint (sets CPG_VERIFY_LLM_ENDPOINT).",
    )
    parser.add_argument(
        "--llm-timeout",
        type=int,
        help="Override LLM request timeout in seconds (sets CPG_VERIFY_LLM_TIMEOUT).",
    )
    parser.add_argument(
        "--explanation-prompt",
        help="Additional instructions appended to the explanation LLM prompt.",
    )
    parser.add_argument(
        "--explanation-prompt-file",
        help="Path to a file containing additional explanation LLM instructions.",
    )
    args = parser.parse_args(argv)

    if args.llm_provider:
        os.environ["CPG_VERIFY_LLM_PROVIDER"] = args.llm_provider
    if args.llm_model:
        os.environ["CPG_VERIFY_LLM_MODEL"] = args.llm_model
    if args.llm_endpoint:
        os.environ["CPG_VERIFY_LLM_ENDPOINT"] = args.llm_endpoint
    if args.llm_timeout is not None:
        os.environ["CPG_VERIFY_LLM_TIMEOUT"] = str(args.llm_timeout)

    extra_prompt = args.explanation_prompt or ""
    if args.explanation_prompt_file:
        path = Path(args.explanation_prompt_file)
        if not path.exists():
            raise SystemExit(f"Explanation prompt file not found: {path}")
        file_text = path.read_text()
        extra_prompt = (extra_prompt + "\n" + file_text).strip() if extra_prompt else file_text
    explanation_extra = extra_prompt or None

    selected_cases = load_cases(args.dataset, limit=args.limit)
    cases = {case["id"]: case for case in selected_cases}
    if args.case_id:
        if args.case_id not in cases:
            raise SystemExit(f"Unknown case_id '{args.case_id}'")
        selected = [cases[args.case_id]]
    else:
        selected = list(cases.values())

    if args.evaluate:
        report = Evaluator(
            CPGVerifyPipeline(
                strategy=args.strategy,
                explain_mode=args.explain_mode,
                explanation_patch_source=args.explanation_patch_source,
                explanation_extra_prompt=explanation_extra,
            )
        ).run(selected)
        data = report.as_dict()
        _emit_output(data, args.output, args.format)
        return

    pipeline = CPGVerifyPipeline(
        strategy=args.strategy,
        explain_mode=args.explain_mode,
        explanation_patch_source=args.explanation_patch_source,
        explanation_extra_prompt=explanation_extra,
    )
    results = {}
    for case in selected:
        artifacts = pipeline.run(case)
        ground_truth = case.get("ground_truth")
        preview = (
            "\n".join(ground_truth.splitlines()[:40]) if ground_truth else "(no ground truth available)"
        )
        results[case["id"]] = {
            "pcg": artifacts.pcg,
            "scm": artifacts.scm,
            "intervention": _serialize_intervention(artifacts.intervention),
            "patch": _serialize_patch(artifacts.patch),
            "effect": artifacts.effect,
            "verification": artifacts.verification.as_dict(),
            "iterations": artifacts.iterations,
            "explanations": {
                "formal": artifacts.explanations.formal_summary,
                "natural_template": artifacts.explanations.natural_template,
                "natural_llm": artifacts.explanations.natural_llm,
                "prompt_context": artifacts.explanations.prompt_context,
                "llm_prompt": artifacts.explanations.llm_prompt,
            },
            "case": {
                "expected_success": case.get("expected_success"),
                "cwe_id": case.get("cwe_id"),
                "cve_id": case.get("cve_id"),
                "metadata": case.get("metadata", {}),
                "ground_truth_preview": preview,
                "ground_truth": ground_truth,
                "original_code": case.get("source"),
                "strategy": args.strategy,
                "explain_mode": args.explain_mode,
            },
        }
        if args.compare:
            results[case["id"]]["baselines"] = _run_baselines(case, artifacts)
    _emit_output(results, args.output, args.format)


if __name__ == "__main__":  # pragma: no cover
    main()
