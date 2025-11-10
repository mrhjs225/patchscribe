# PatchScribe Analysis Notes (2025-11-09)

## Dual-Verification Tiers

- Consistency checks now emit a `confidence_level` with three tiers:
  - `pass`: all causal checks succeed.
  - `review`: exactly one non-critical check (completeness/intervention) fails.
  - `fail`: multiple failures or any causal/logical miss.
- Pipelines treat `pass` and `review` as automatically accepted patches. The previous `overall` flag is preserved for strict auditing.
- Metrics:
  - `consistency_pass_rate` now tracks accepted patches (pass + review).
  - `consistency_strict_rate` captures the old “all checks passed” signal.
  - First-attempt success and iteration stopping use the acceptance tier, lifting otherwise good fixes that only missed completeness.

## Reporting Changes

- Unified summaries show both accepted and strict consistency columns, plus per-condition confidence tier counts in the RQ2 tables.
- LLM judge success breakdowns are mutually exclusive (SynEq → SemEq → Plausible) so failure percentages remain non-negative.
- Aggregate tables include the strict rate so papers can cite the more conservative number when needed.

## Explanation Metrics

- LLM judge responses that omit `completeness` are normalized on read by re-parsing the stored JSON. Completeness now averages to ~2.3–2.4 across conditions instead of 0.0.
- `scripts/analyze.py` recomputes LLM averages directly from the case data before generating summaries, so cached metrics cannot go stale.

## What to Update in the Paper

- When referencing `consistency_pass_rate` in the evaluation section, clarify that it corresponds to the accepted tier, and also cite the strict rate for completeness.
- The explanation-quality subsection can now report non-zero completeness scores; cite both the numeric improvements and the new confidence-tier histogram to explain why some patches still require reviewer attention.
