# Implementation Notes: Enhanced Verification & GPT Evaluation

## Triple Verification Integration (Gap 1)
- **Backends**: Introduce dedicated adapters for KLEE, CBMC, and AFL/LibFuzzer under `patchscribe.verification`.
- **Workflow**:
  1. Emit patched C source into an isolated temporary workspace.
  2. Compile to the format required by each tool (e.g., LLVM bitcode for KLEE).
  3. Spawn the external verifier with timeouts and capture counterexamples.
  4. Parse tool output into the `CheckOutcome` structure, including diffable evidence.
- **Fallbacks**: When a tool is unavailable or errors, fall back to heuristic guards with explicit status messaging so the pipeline degrades gracefully.
- **Configuration**: Provide environment variables/CLI switches to force-enable/disable individual backends and to adjust resource budgets.

## GPT-Based Patch & Explanation Evaluation (Gap 3)
- **Prompts**: Build structured prompts that include the diff, formal specs (E_bug/E_patch), verification outcomes, and explanation text.
- **Scoring**: Request JSON scores (accuracy, safety, completeness, clarity, causality) from a GPT endpoint via the shared `LLMClient`.
- **Integration Points**:
  - Extend `ExplanationEvaluator` to optionally use GPT for both explanation and patch quality.
  - Surface scores in `CaseEvaluation` so downstream reports can compute aggregate metrics.
- **Reliability**: Log prompt/response pairs, support deterministic temperature settings, and retain a manual-review hook for auditing.
