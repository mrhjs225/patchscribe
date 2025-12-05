#!/usr/bin/env python3
"""
Aggregate multi-seed PatchScribe experiment results.

The PatchScribe paper evaluates every configuration across three seeds
(42/123/7220) and reports the mean ± standard deviation.  This helper pulls a
set of per-seed result directories or files and emits consolidated statistics
for RQ1-style metrics (success rate, ground-truth alignment, etc.).
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_CONDITIONS = ["c1", "c2", "c3", "c4"]
DEFAULT_METRICS = [
    "success_rate",
    "ground_truth_match_rate",
    "first_attempt_success_rate",
    "consistency_pass_rate",
    "vulnerability_elimination_rate",
    "avg_ast_overall_similarity",
]


@dataclass
class ConditionResult:
    path: Path
    metrics: Dict[str, Any]
    metadata: Dict[str, Any]
    raw: Dict[str, Any]


@dataclass
class SeedRun:
    identifier: str
    seed: Optional[int]
    conditions: Dict[str, ConditionResult]


def _infer_condition_from_name(path: Path, conditions: List[str]) -> Optional[str]:
    stem = path.stem.lower()
    for cond in conditions:
        if cond in stem:
            return cond
    return None


def _infer_seed(path: Path, payload: Dict[str, Any]) -> Optional[int]:
    metadata = payload.get("metadata") or {}
    snapshot = payload.get("config_fingerprint", {}).get("snapshot", {})
    for candidate in (metadata, snapshot):
        seed_val = candidate.get("seed")
        if seed_val is not None:
            try:
                return int(seed_val)
            except (TypeError, ValueError):
                continue

    match = re.search(r"seed(\d+)", str(path))
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return None
    return None


def _load_condition_file(path: Path) -> ConditionResult:
    with path.open("r") as fp:
        payload = json.load(fp)
    metrics = payload.get("metrics", {})
    metadata = payload.get("metadata") or {}
    return ConditionResult(path=path, metrics=metrics, metadata=metadata, raw=payload)


def _gather_directory_runs(run_path: Path, conditions: List[str]) -> SeedRun:
    condition_map: Dict[str, ConditionResult] = {}
    discovered_seed: Optional[int] = None

    for condition in conditions:
        # Accept any file such as c4_results.json, c4_server0_results.json, etc.
        candidates = sorted(run_path.glob(f"{condition}*results.json"))
        if not candidates:
            continue
        result = _load_condition_file(candidates[0])
        condition_map[condition] = result
        if discovered_seed is None:
            discovered_seed = _infer_seed(result.path, result.raw)

    identifier = run_path.name
    if not condition_map:
        raise FileNotFoundError(f"No condition results found under {run_path}")
    if discovered_seed is None:
        any_condition = next(iter(condition_map.values()))
        discovered_seed = _infer_seed(any_condition.path, any_condition.raw)
    return SeedRun(identifier=identifier, seed=discovered_seed, conditions=condition_map)


def _gather_runs(paths: List[Path], conditions: List[str]) -> List[SeedRun]:
    runs: List[SeedRun] = []
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")
        if path.is_dir():
            runs.append(_gather_directory_runs(path, conditions))
        else:
            condition = _infer_condition_from_name(path, conditions)
            if not condition:
                raise ValueError(f"Unable to infer condition from filename: {path}")
            result = _load_condition_file(path)
            run = SeedRun(identifier=path.parent.name or path.stem, seed=_infer_seed(path, result.raw), conditions={condition: result})
            runs.append(run)
    return runs


def _summarize(values: List[float]) -> Dict[str, float]:
    return {
        "mean": statistics.mean(values),
        "std": statistics.stdev(values) if len(values) > 1 else 0.0,
        "min": min(values),
        "max": max(values),
        "samples": len(values),
    }


def analyze_runs(runs: List[SeedRun], metrics: List[str], conditions: List[str]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}
    for condition in conditions:
        per_metric_values: Dict[str, List[float]] = {metric: [] for metric in metrics}
        run_entries: List[Dict[str, Any]] = []

        for run in runs:
            cond_result = run.conditions.get(condition)
            if not cond_result:
                continue
            entry = {
                "seed": run.seed,
                "identifier": run.identifier,
                "path": str(cond_result.path),
            }
            for metric in metrics:
                value = cond_result.metrics.get(metric)
                if isinstance(value, (int, float)):
                    entry[metric] = float(value)
                    per_metric_values[metric].append(float(value))
            run_entries.append(entry)

        metric_summary = {}
        for metric, values in per_metric_values.items():
            if values:
                metric_summary[metric] = _summarize(values)

        summary[condition] = {
            "runs": run_entries,
            "metric_summary": metric_summary,
        }
    return summary


def render_markdown(summary: Dict[str, Any], metrics: List[str]) -> str:
    lines: List[str] = ["# Multi-Seed PatchScribe Summary"]
    for condition, payload in summary.items():
        runs = payload["runs"]
        metric_summary = payload["metric_summary"]
        lines.append(f"\n## Condition {condition.upper()}")
        lines.append(f"- Runs included: {len(runs)}")
        if runs:
            seeds = [
                str(entry["seed"]) if entry.get("seed") is not None else "?"
                for entry in runs
            ]
            lines.append(f"- Seeds: {', '.join(seeds)}")

        lines.append("\n| Metric | Mean | Std | Min | Max | Samples |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for metric in metrics:
            stats = metric_summary.get(metric)
            if not stats:
                continue
            lines.append(
                f"| {metric} | {stats['mean']:.4f} | {stats['std']:.4f} | "
                f"{stats['min']:.4f} | {stats['max']:.4f} | {int(stats['samples'])} |"
            )
        if not any(metric_summary.values()):
            lines.append("| (no metrics) | - | - | - | - | - |")

    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Aggregate PatchScribe metrics across multiple seeds.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "runs",
        nargs="+",
        type=Path,
        help="Result directories (e.g., results/local/gpt-5-mini/seed42)",
    )
    parser.add_argument(
        "--conditions",
        nargs="+",
        default=DEFAULT_CONDITIONS,
        help="Conditions to aggregate.",
    )
    parser.add_argument(
        "--metrics",
        nargs="+",
        default=DEFAULT_METRICS,
        help="Metric keys to summarize.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional Markdown output file.",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="Optional JSON summary output file.",
    )
    parser.add_argument(
        "--min-runs",
        type=int,
        default=2,
        help="Minimum number of runs required before reporting.",
    )

    args = parser.parse_args()

    runs = _gather_runs(args.runs, args.conditions)
    if len(runs) < args.min_runs:
        print(f"[WARN] Only {len(runs)} run(s) supplied; consider adding more seeds.", file=sys.stderr)

    summary = analyze_runs(runs, args.metrics, args.conditions)
    markdown = render_markdown(summary, args.metrics)

    print(markdown)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(markdown)

    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
