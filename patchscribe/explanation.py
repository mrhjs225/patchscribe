"""
Natural-language and structured explanation utilities for PatchScribe.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple, Set

from .intervention import InterventionSpec
from .llm import LLMClient, LLMUnavailable
from .patch import PatchResult
from .pcg import ProgramCausalGraph
from .scm import StructuralCausalModel


@dataclass
class ExplanationBundle:
    formal_summary: str
    natural_template: str
    prompt_context: str
    natural_llm: Optional[str] = None
    llm_prompt: Optional[str] = None


def build_prompt_context(
    graph: ProgramCausalGraph,
    model: StructuralCausalModel,
    intervention: InterventionSpec,
) -> str:
    vulnerability_line, vulnerability_desc = _vulnerability_node(graph)
    sections: List[str] = [
        "Vulnerability summary:\n"
        f"- location: line {vulnerability_line}\n"
        f"- description: {vulnerability_desc}"
    ]
    causal_chain = _format_causal_chain(graph).strip()
    if _has_meaningful_chain(causal_chain):
        sections.append("Causal chain (from PCG):\n" + causal_chain)
    structural_condition = (model.vulnerable_condition or "").strip()
    if structural_condition:
        sections.append("Structural model condition:\n" + structural_condition)
    intervention_text = _format_interventions(intervention).strip()
    if _has_meaningful_interventions(intervention_text):
        sections.append("Recommended interventions:\n" + intervention_text)
    return "\n\n".join(sections)


def build_natural_context(
    graph: ProgramCausalGraph,
    model: StructuralCausalModel | None,
    intervention: InterventionSpec,
    *,
    effect: dict | None = None,
    patch: PatchResult | None = None,
) -> str:
    vulnerability_line, vulnerability_desc = _vulnerability_node(graph)
    sections: List[str] = []

    sections.append(
        "\n".join(
            [
                "### 취약점 개요",
                f"- 위치: line {vulnerability_line if vulnerability_line != -1 else '알 수 없음'}",
                f"- 취약 조건: {vulnerability_desc or '(설명 없음)'}",
            ]
        )
    )

    if model and model.vulnerable_condition:
        sections.append(
            "\n".join(
                [
                    "### 형식 모델 해석",
                    f"- 원래 취약 조건: {model.vulnerable_condition}",
                    f"- 자연어 해설: { _humanize_condition(model.vulnerable_condition) }",
                ]
            )
        )

    causal_chain = _format_causal_chain(graph)
    sections.append(
        "### 인과 경로 분석\n"
        + (
            causal_chain
            if causal_chain.strip()
            else "- 인과 경로 정보를 찾을 수 없습니다."
        )
    )

    sections.append(_describe_interventions(graph, intervention))

    if patch:
        sections.append(_describe_patch_changes(patch))

    if effect:
        sections.append(_describe_patch_effect(effect))

    return "\n\n".join(section.strip() for section in sections if section.strip())


def generate_explanations(
    graph: ProgramCausalGraph,
    model: StructuralCausalModel,
    intervention: InterventionSpec,
    patch: PatchResult,
    effect: dict,
    *,
    mode: str = "template",
    llm_client: Optional[LLMClient] = None,
    strategy: str = "formal",
    signature: str = "",
    extra_instructions: Optional[str] = None,
) -> ExplanationBundle:
    causal_context = build_natural_context(graph, model, intervention, effect=effect, patch=patch)
    if strategy == "only_natural":
        prompt_context = causal_context
    else:
        prompt_context = build_prompt_context(graph, model, intervention)
    formal = _build_formal_summary(model, effect)
    patch_summary = _summarize_patch(patch)
    natural_template = _build_natural_summary(graph, intervention, patch_summary, effect)
    natural_llm = None
    llm_prompt = None
    if mode in {"llm", "both"}:
        llm_prompt = _build_llm_prompt(
            strategy=strategy,
            prompt_context=prompt_context,
            patch_summary=patch_summary,
            effect=effect,
            patched_code=patch.patched_code,
            signature=signature,
            causal_context=causal_context,
            extra_instructions=extra_instructions,
        )
        client = llm_client or LLMClient()
        try:
            natural_llm = client.generate_explanation(llm_prompt)
        except LLMUnavailable:
            natural_llm = None
    return ExplanationBundle(
        formal_summary=formal,
        natural_template=natural_template,
        prompt_context=prompt_context,
        natural_llm=natural_llm,
        llm_prompt=llm_prompt,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _vulnerability_node(graph: ProgramCausalGraph) -> tuple[int, str]:
    for node in graph.nodes.values():
        if node.node_type == "vulnerability":
            return node.location or -1, node.description
    return -1, "(unknown vulnerability)"


def _format_causal_chain(graph: ProgramCausalGraph) -> str:
    """Generate causal flow narrative instead of flat list"""
    vuln_id = None
    vuln_node = None
    for node_id, node in graph.nodes.items():
        if node.node_type == "vulnerability":
            vuln_id = node_id
            vuln_node = node
            break

    if vuln_id is None:
        return "Unable to determine causal chain to vulnerability."

    # Trace causal path backwards from vulnerability
    causal_path = _trace_causal_path_backwards(graph, vuln_id)

    if not causal_path:
        return (
            f"The vulnerability at line {vuln_node.location} occurs directly "
            f"without intermediate causal conditions."
        )

    # Build narrative
    narrative_parts = []
    narrative_parts.append(
        f"The vulnerability at line {vuln_node.location} occurs through this causal flow:"
    )

    for i, (pred_id, curr_id) in enumerate(causal_path, 1):
        pred_node = graph.nodes[pred_id]
        curr_node = graph.nodes[curr_id]

        # Determine relationship
        if curr_id == vuln_id:
            relationship = "directly enables the vulnerable operation"
        elif i == len(causal_path):
            relationship = "directly enables"
        else:
            relationship = "leads to"

        narrative_parts.append(
            f"{i}. At line {pred_node.location}, the condition `{pred_node.description}` "
            f"{relationship} {'the vulnerability' if curr_id == vuln_id else f'line {curr_node.location}'}"
        )

    narrative_parts.append(
        "\nBreaking any link in this causal chain will prevent the vulnerability."
    )

    return "\n".join(narrative_parts)


def _has_meaningful_chain(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    placeholders = {
        "- no explicit predecessors (treat as exogenous)",
        "- unable to determine causal chain",
        "- predecessors resolved but descriptions missing",
    }
    return stripped.lower() not in {p.lower() for p in placeholders}


def _format_interventions(spec: InterventionSpec) -> str:
    if not spec.interventions:
        return "- no intervention generated"
    lines = []
    for item in spec.interventions:
        target = "line N/A" if item.target_line < 0 else f"line {item.target_line}"
        lines.append(f"- {item.enforce} @ {target}: {item.rationale}")
    return "\n".join(lines)


def _has_meaningful_interventions(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    return stripped.lower() != "- no intervention generated"


def _build_formal_summary(model: StructuralCausalModel, effect: dict) -> str:
    equations = "\n".join(f"{eq.target} := {eq.expression}" for eq in model.equations)
    vulnerable_condition = model.vulnerable_condition or "True"
    effect_condition = effect.get("patched_condition", "Unknown")
    removed = effect.get("vulnerability_removed", False)
    return (
        "### Formal Summary\n"
        "**Structural equations**\n"
        f"{equations}\n\n"
        "**Original vulnerability condition**\n"
        f"{vulnerable_condition}\n\n"
        "**Post-patch condition**\n"
        f"{effect_condition}\n\n"
        f"**Inference**: vulnerability removed = {removed}"
    )


def _build_natural_summary(
    graph: ProgramCausalGraph,
    intervention: InterventionSpec,
    patch_summary: str,
    effect: dict,
) -> str:
    vuln_line, vuln_desc = _vulnerability_node(graph)
    causal_chain = _format_causal_chain(graph)
    intervention_text = _format_interventions(intervention)

    # Enhanced removal reasoning with causal explanation
    if effect.get("vulnerability_removed"):
        removal_reason = (
            "The patch eliminates the vulnerability by breaking the causal chain. "
            "Specifically:\n"
            f"- **Vulnerability cause**: {vuln_desc}\n"
            f"- **Causal path**: {causal_chain}\n"
            f"- **Intervention**: {intervention_text}\n"
            "- **Result**: The conditions necessary for exploitation are now unsatisfiable"
        )
    else:
        removal_reason = (
            "Formal analysis could not confirm complete removal of the vulnerability. "
            "The patch may provide partial mitigation but additional checks are recommended."
        )

    return (
        "## Vulnerability Fix Explanation\n\n"
        "### What was wrong?\n"
        f"- **Location**: line {vuln_line}\n"
        f"- **Issue**: {vuln_desc}\n"
        f"- **Root cause**: {causal_chain}\n\n"
        "### What code was changed?\n"
        f"{patch_summary}\n\n"
        "### Why this change fixes the vulnerability?\n"
        f"{removal_reason}\n\n"
        "### Causal reasoning\n"
        "The vulnerability occurred due to a causal chain from inputs to the vulnerable operation. "
        "The patch intervenes at a critical point in this chain, preventing the vulnerability "
        "condition from being satisfied.\n"
    )


def _summarize_patch(patch: PatchResult) -> str:
    if patch.method == "noop":
        return "No patch applied."

    # Enhanced diff parsing with line numbers and detailed analysis
    if patch.diff:
        diff_lines = patch.diff.splitlines()
        added_lines = []
        removed_lines = []
        modified_context = []
        current_line_num = None

        for line in diff_lines:
            # Parse unified diff line numbers
            if line.startswith("@@"):
                # Extract line number from @@ -a,b +c,d @@
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        # Get the +c,d part
                        plus_part = [p for p in parts if p.startswith('+')][0]
                        current_line_num = int(plus_part.split(',')[0].lstrip('+'))
                    except (IndexError, ValueError):
                        pass
                modified_context.append(line)
            elif line.startswith("+") and not line.startswith("+++"):
                code = line[1:].strip()
                if code:  # Skip empty lines
                    line_info = f"Line {current_line_num}: {code}" if current_line_num else code
                    added_lines.append(line_info)
                    if current_line_num:
                        current_line_num += 1
            elif line.startswith("-") and not line.startswith("---"):
                code = line[1:].strip()
                if code:  # Skip empty lines
                    removed_lines.append(code)
            elif current_line_num and line.startswith(" "):
                # Context line
                current_line_num += 1

        # Build detailed summary
        summary_parts = [f"Applied method: {patch.method}"]

        if added_lines:
            summary_parts.append("\n**Added code:**")
            for added in added_lines[:5]:  # Show first 5
                summary_parts.append(f"  + {added}")
            if len(added_lines) > 5:
                summary_parts.append(f"  ... and {len(added_lines) - 5} more additions")

        if removed_lines:
            summary_parts.append("\n**Removed code:**")
            for removed in removed_lines[:3]:  # Show first 3
                summary_parts.append(f"  - {removed}")
            if len(removed_lines) > 3:
                summary_parts.append(f"  ... and {len(removed_lines) - 3} more removals")

        preview_text = "\n".join(summary_parts)
    else:
        preview_text = "(No diff generated)"

    applied = ", ".join(patch.applied_guards) if patch.applied_guards else "None"
    notes = ", ".join(patch.notes) if patch.notes else "None"

    return (
        f"{preview_text}\n\n"
        f"**Applied guards:** {applied}\n"
        f"**Notes:** {notes}"
    )


def _build_llm_prompt(
    *,
    strategy: str,
    prompt_context: str,
    patch_summary: str,
    effect: dict,
    patched_code: str,
    signature: str,
    causal_context: str,
    extra_instructions: Optional[str] = None,
) -> str:
    removal = "removed" if effect.get("vulnerability_removed") else "not yet removed"
    persona = (
        "You are a senior security engineer who produces concise, technically precise vulnerability-fix explanations."
    )
    objective = (
        "Produce a markdown section that begins with '### Vulnerability Fix Explanation' and answers:\n"
        "1. What caused the vulnerability (what)\n"
        "2. WHICH SPECIFIC CODE LINES were changed (be explicit about line numbers and code)\n"
        "3. How the patch changes the code (how) - reference the actual diff changes\n"
        "4. Why this change eliminates the vulnerability (why) - explain the causal link\n"
        "5. What is the causal relationship between the vulnerability and the fix\n"
        "6. Write your response in English.\n"
        "\n"
        "IMPORTANT REQUIREMENTS:\n"
        "- You MUST explicitly describe which code was modified (e.g., 'Added NULL check at line X')\n"
        "- You MUST explain WHY this specific change fixes the vulnerability\n"
        "- You MUST describe the causal relationship (e.g., 'The vulnerability occurred because X, "
        "which led to Y. The patch breaks this causal chain by...')\n"
        "- Reference specific lines from the diff when describing changes"
    )
    if extra_instructions:
        objective += "\n" + extra_instructions.strip()

    info_descriptions: List[str] = []
    info_items: List[tuple[str, str]] = []

    if strategy in {"formal", "natural"}:
        info_descriptions.append("- 형식적 PCG/SCM 분석 요약")
        info_items.append(("Formal Context", prompt_context))
    if strategy in {"natural", "only_natural"}:
        info_descriptions.append("- 인과적 자연어 설명")
        info_items.append(("Causal Explanation", causal_context))
    if strategy in {"natural", "only_natural"}:
        info_descriptions.append("- 패치 요약 (diff 미리보기 포함)")
        info_items.append(("Patch Summary", patch_summary))

    info_descriptions.append("- 취약점 시그니처와 패치된 코드")
    info_items.append(("Vulnerability Signature", signature or "(signature unavailable)"))
    code_block = f"```c\n{patched_code.strip()}\n```"
    info_items.append(("Patched Code", code_block))

    info_overview = "\n".join(info_descriptions)

    provided_blocks = []
    for title, content in info_items:
        provided_blocks.append(f"#### {title}\n{content}\n")
    provided_info = "".join(provided_blocks)

    verification_note = (
        "Formal analysis currently reports the vulnerability is "
        f"{removal}."
    )

    return (
        persona
        + "\n\n"
        + objective
        + "\n\n"
        + "You will receive the following information:\n"
        + info_overview
        + "\n\n"
        + "### Provided Information\n"
        + provided_info
        + verification_note
    )


def _humanize_condition(condition: str) -> str:
    if not condition:
        return "조건 정보가 제공되지 않았습니다."
    text = condition
    replacements = {
        "&&": " 그리고 ",
        "AND": " 그리고 ",
        "||": " 또는 ",
        "OR": " 또는 ",
        "!": " NOT ",
        "NOT": " NOT ",
        "==": " == ",
        "!=": " != ",
        ">=": " 이상",
        "<=": " 이하",
        ">": " 초과",
        "<": " 미만",
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    words = []
    for token in text.split():
        if token.startswith("V_"):
            words.append(f"{token[2:]} 조건")
        else:
            words.append(token)
    sentence = " ".join(words)
    sentence = sentence.replace("  ", " ").strip()
    return sentence or "조건 정보가 제공되지 않았습니다."


def _describe_interventions(graph: ProgramCausalGraph, spec: InterventionSpec) -> str:
    if not spec.interventions:
        return "### 개입 계획 (원인 → 조치 → 기대 효과)\n- 생성된 개입이 없습니다."

    lines: List[str] = ["### 개입 계획 (원인 → 조치 → 기대 효과)"]
    for item in spec.interventions:
        action = _enforce_to_text(graph, item.enforce)
        target = "알 수 없음" if item.target_line < 0 else f"line {item.target_line}"
        rationale = item.rationale or "추가 설명 없음"
        lines.append(f"- 원인: {rationale}")
        lines.append(f"  · 조치: {action}")
        lines.append(f"  · 대상 위치: {target}")
        expected = "취약 경로를 차단하도록 설계되었습니다."
        lines.append(f"  · 기대 효과: {expected}")
    return "\n".join(lines)


def _enforce_to_text(graph: ProgramCausalGraph, enforce: str) -> str:
    prefix = "ENFORCE NOT "
    if enforce.startswith(prefix):
        variable = enforce[len(prefix):]
        node = _node_from_variable(graph, variable)
        if node:
            return f"{node.description} 조건을 차단"
    return enforce


def _node_from_variable(graph: ProgramCausalGraph, variable: str):
    node_id = variable[2:] if variable.startswith("V_") else variable
    return graph.nodes.get(node_id)


def _describe_patch_changes(patch: PatchResult) -> str:
    lines: List[str] = ["### 패치 변경 요약"]
    lines.append(f"- 적용 방식: {patch.method}")
    if patch.applied_guards:
        guards = "; ".join(patch.applied_guards)
        lines.append(f"- 추가된 가드: {guards}")
    else:
        lines.append("- 추가된 가드: 없음")
    if patch.notes:
        lines.append(f"- 메모: {', '.join(patch.notes)}")
    if patch.diff:
        diff_lines = [
            line
            for line in patch.diff.splitlines()
            if line.startswith("+") or line.startswith("-")
        ][:10]
        if diff_lines:
            lines.append("- 주요 코드 변경:")
            for entry in diff_lines:
                lines.append(f"  {entry}")
    else:
        lines.append("- 코드 diff가 생성되지 않았습니다.")
    return "\n".join(lines)


def _describe_patch_effect(effect: dict) -> str:
    lines: List[str] = ["### 패치 효과 분석"]
    original = effect.get("original_condition")
    patched = effect.get("patched_condition")
    removed = effect.get("vulnerability_removed")
    signature_found = effect.get("signature_found")
    if original:
        lines.append(f"- 원래 취약 조건: {original}")
        lines.append(f"  · 자연어 해설: {_humanize_condition(original)}")
    if patched:
        lines.append(f"- 패치 후 조건: {patched}")
        lines.append(f"  · 자연어 해설: {_humanize_condition(patched)}")
    if removed is not None:
        verdict = "제거됨" if removed else "여전히 존재함"
        lines.append(f"- 분석 결과: 취약점 {verdict}")
    if signature_found is not None:
        signature_text = "찾음" if signature_found else "제거됨"
        lines.append(f"- 시그니처 탐지: {signature_text}")
    diagnostics = effect.get("diagnostics") or {}
    if diagnostics:
        lines.append(f"- 추가 진단 정보: {diagnostics}")
    return "\n".join(lines)


def _trace_causal_path_backwards(
    graph: ProgramCausalGraph,
    vuln_id: str,
    max_depth: int = 5
) -> List[Tuple[str, str]]:
    """Trace backwards from vulnerability to find causal path"""
    path = []
    current = vuln_id
    visited: Set[str] = set()

    for _ in range(max_depth):
        if current in visited:
            break
        visited.add(current)

        predecessors = list(graph.predecessors(current))
        if not predecessors:
            break

        # Choose most direct predecessor (heuristic: closest line number)
        current_node = graph.nodes.get(current)
        if not current_node:
            break

        best_pred = min(
            predecessors,
            key=lambda p: abs(graph.nodes[p].location - current_node.location)
            if graph.nodes.get(p) and graph.nodes.get(p).location and current_node.location
            else float('inf')
        )

        path.append((best_pred, current))
        current = best_pred

    # Reverse to show forward flow
    return list(reversed(path))
