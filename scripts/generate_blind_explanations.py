#!/usr/bin/env python3
"""Generate blind evaluation files for zeroday explanations.

This script aggregates the Natural Explanation (LLM) sections from the
selected strategy markdown reports per model, shuffles the variant
order per CVE case, and writes per-model blind evaluation markdown files
along with JSON keys that map options back to their original variants.
"""
from __future__ import annotations

import argparse
import json
import random
import re
from pathlib import Path
from typing import Dict, List, Tuple

CASE_PATTERN = re.compile(
    r"^## Case: (?P<case>.+?)\n(?P<body>.*?)(?=^## Case: |\Z)",
    re.MULTILINE | re.DOTALL,
)

STOP_MARKERS: Tuple[str, ...] = (
    "\n### Formal Explanation",
    "\n### Explanation LLM Prompt",
    "\n### Prompt Context",
    "\n### Explanation (LLM)",
)

DEFAULT_STRATEGIES: Tuple[str, ...] = ("minimal", "formal", "natural", "only_natural")


def extract_explanation(section: str) -> str | None:
    marker = "### Natural Explanation (LLM)"
    idx = section.find(marker)
    if idx == -1:
        return None
    segment = section[idx + len(marker):]
    segment = segment.lstrip("\n")
    stop = len(segment)
    for marker_text in STOP_MARKERS:
        candidate = segment.find(marker_text)
        if candidate != -1 and candidate < stop:
            stop = candidate
    explanation = segment[:stop].strip()
    return explanation or None


def parse_report(path: Path, skip_missing: bool = False) -> Dict[str, str]:
    text = path.read_text(encoding="utf-8")
    results: Dict[str, str] = {}
    for match in CASE_PATTERN.finditer(text):
        case_id = match.group("case").strip()
        section = match.group("body")
        explanation = extract_explanation(section)
        if explanation is None:
            if skip_missing:
                continue
            raise ValueError(f"Failed to find Natural Explanation (LLM) in {path} for case {case_id}")
        results[case_id] = explanation
    return results


def build_cases(variant_files: Dict[str, Path], skip_missing: bool) -> Dict[str, Dict[str, str]]:
    cases: Dict[str, Dict[str, str]] = {}
    for variant, file_path in variant_files.items():
        variant_data = parse_report(file_path, skip_missing=skip_missing)
        for case_id, explanation in variant_data.items():
            cases.setdefault(case_id, {})[variant] = explanation
    return cases


def ensure_complete(cases: Dict[str, Dict[str, str]], variants: List[str]) -> None:
    missing: List[str] = []
    for case_id, case_variants in cases.items():
        for variant in variants:
            if variant not in case_variants:
                missing.append(f"{case_id} -> {variant}")
    if missing:
        details = "\n".join(missing)
        raise ValueError(f"Missing explanations for:\n{details}")


def filter_cases_with_min_variants(
    cases: Dict[str, Dict[str, str]], variants: List[str], min_variants: int
) -> tuple[Dict[str, Dict[str, str]], Dict[str, List[str]]]:
    filtered: Dict[str, Dict[str, str]] = {}
    missing: Dict[str, List[str]] = {}
    for case_id, case_variants in cases.items():
        present = [variant for variant in variants if variant in case_variants]
        if len(present) >= min_variants:
            filtered[case_id] = {variant: case_variants[variant] for variant in present}
        else:
            missing_variants = [variant for variant in variants if variant not in case_variants]
            missing[case_id] = missing_variants
    return filtered, missing


def render_markdown(
    dataset_label: str,
    model_label: str,
    cases: Dict[str, Dict[str, str]],
    variants: List[str],
    seed: int | None,
    output_path: Path,
    key_path: Path,
) -> None:
    rng = random.Random(seed)
    option_labels = [chr(ord("A") + i) for i in range(26)]

    lines: List[str] = [
        f"# {dataset_label} Blind Evaluation",
        f"\n**Model**: {model_label}",
        f"\n**Variants**: {', '.join(variants)}",
    ]
    key: Dict[str, Dict[str, str]] = {}

    for case_id in sorted(cases.keys()):
        lines.append(f"\n## Case: {case_id}")
        entries = list(cases[case_id].items())
        rng.shuffle(entries)
        case_key: Dict[str, str] = {}
        for idx, (variant, explanation) in enumerate(entries):
            if idx >= len(option_labels):
                raise ValueError("Exceeded supported option labels (limited to 26).")
            label = option_labels[idx]
            lines.append(f"\n### Option {label}")
            lines.append("\n" + explanation.strip())
            lines.append(
                "\n**Evaluation**\n- Clarity:\n- Technical accuracy:\n- Completeness:\n- Notes:\n"
            )
            case_key[label] = variant
        key[case_id] = case_key
        lines.append("\n---")

    output_path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
    key_path.write_text(json.dumps(key, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def infer_models(input_dir: Path, dataset: str, strategies: List[str]) -> List[str]:
    models: set[str] = set()
    for strategy in strategies:
        prefix = f"{dataset}_{strategy}_"
        for file_path in input_dir.glob(f"{prefix}*.md"):
            stem = file_path.stem
            if not stem.startswith(prefix):
                continue
            model_name = stem[len(prefix):]
            if model_name:
                models.add(model_name)
    if not models:
        raise ValueError(
            f"No matching report files found in {input_dir} for dataset '{dataset}' "
            f"and strategies {strategies}."
        )
    return sorted(models)


def format_dataset_label(dataset: str) -> str:
    words = dataset.replace("-", " ").replace("_", " ").split()
    return " ".join(word.capitalize() for word in words) or dataset


def generate_for_model(
    dataset: str,
    model: str,
    strategies: List[str],
    input_dir: Path,
    output_dir: Path,
    key_dir: Path,
    seed: int | None,
    strict: bool,
    skip_missing: bool,
    min_variants_required: int,
) -> None:
    variant_files = {
        strategy: input_dir / f"{dataset}_{strategy}_{model}.md" for strategy in strategies
    }

    for strategy, file_path in variant_files.items():
        if not file_path.is_file():
            raise FileNotFoundError(
                f"Expected report file not found for model '{model}' "
                f"and strategy '{strategy}': {file_path}"
            )

    cases = build_cases(variant_files, skip_missing=skip_missing)
    if strict:
        ensure_complete(cases, strategies)
    else:
        effective_min = max(1, min(len(strategies), min_variants_required))
        cases, missing_cases = filter_cases_with_min_variants(
            cases,
            strategies,
            min_variants=effective_min,
        )
        if missing_cases:
            samples = []
            for case_id, missing_variants in list(missing_cases.items())[:5]:
                samples.append(f"{case_id} ({', '.join(missing_variants)})")
            summary = "; ".join(samples)
            remaining = len(missing_cases) - len(samples)
            if remaining > 0:
                summary += f"; ... (+{remaining} more)"
            print(
                f"Skipping {len(missing_cases)} cases with fewer than {effective_min} variants for model '{model}': {summary}"
            )
        if not cases:
            raise ValueError(
                f"No cases meet the minimum variant requirement for model '{model}'. "
                "Consider rerunning with --strict to diagnose missing strategies or lowering --min-variants."
            )

    output_dir.mkdir(parents=True, exist_ok=True)
    key_dir.mkdir(parents=True, exist_ok=True)

    dataset_label = format_dataset_label(dataset)
    output_path = output_dir / f"{dataset}_blind_{model}.md"
    key_path = key_dir / f"{dataset}_blind_{model}_key.json"

    render_markdown(dataset_label, model, cases, strategies, seed, output_path, key_path)
    print(f"Wrote {output_path} and {key_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate blind evaluation materials for zeroday reports."
    )
    parser.add_argument(
        "--dataset",
        default="zeroday",
        help="Dataset identifier used as the file prefix (default: zeroday).",
    )
    parser.add_argument(
        "--strategies",
        nargs="+",
        default=list(DEFAULT_STRATEGIES),
        help="Strategies to include when gathering explanations (default: minimal formal natural only_natural).",
    )
    parser.add_argument(
        "--models",
        nargs="+",
        default=None,
        help="Optional list of model identifiers (matching report filenames) to process. "
             "If omitted, models are inferred from available report files.",
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=Path("results/poc"),
        help="Directory containing per-strategy markdown reports (default: results/poc).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/poc"),
        help="Directory where blind evaluation markdown files will be written (default: results/poc).",
    )
    parser.add_argument(
        "--key-dir",
        type=Path,
        default=None,
        help="Directory for JSON key files (default: matches --output-dir).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if any case is missing a Natural Explanation for the selected strategies.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for shuffling option order per case.",
    )
    parser.add_argument(
        "--min-variants",
        type=int,
        default=2,
        help="Minimum number of strategies with explanations required to keep a case (default: 2).",
    )
    args = parser.parse_args()

    strategies = list(dict.fromkeys(args.strategies))
    if not strategies:
        raise ValueError("At least one strategy must be provided.")

    input_dir = args.input_dir
    if not input_dir.is_dir():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    models = args.models or infer_models(input_dir, args.dataset, strategies)
    key_dir = args.key_dir or args.output_dir
    min_variants_required = max(1, args.min_variants)

    for model in models:
        generate_for_model(
            dataset=args.dataset,
            model=model,
            strategies=strategies,
            input_dir=input_dir,
            output_dir=args.output_dir,
            key_dir=key_dir,
            seed=args.seed,
            strict=args.strict,
            skip_missing=not args.strict,
            min_variants_required=min_variants_required,
        )


if __name__ == "__main__":
    main()
