"""
Natural-language and structured explanation utilities for CPG-Verify.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional

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
    causal_chain = _format_causal_chain(graph)
    intervention_text = _format_interventions(intervention)
    return (
        "Vulnerability summary:\n"
        f"- location: line {vulnerability_line}\n"
        f"- description: {vulnerability_desc}\n\n"
        "Causal chain (from PCG):\n"
        f"{causal_chain}\n\n"
        "Structural model condition:\n"
        f"{model.vulnerable_condition or 'Unavailable'}\n\n"
        "Recommended interventions:\n"
        f"{intervention_text}"
    )


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
    vuln_id = None
    for node_id, node in graph.nodes.items():
        if node.node_type == "vulnerability":
            vuln_id = node_id
            break
    if vuln_id is None:
        return "- unable to determine causal chain"
    parents = graph.predecessors(vuln_id)
    if not parents:
        return "- no explicit predecessors (treat as exogenous)"
    lines: List[str] = []
    for parent_id in parents:
        node = graph.nodes.get(parent_id)
        if not node:
            continue
        lines.append(f"- {node.description} (line {node.location})")
    return "\n".join(lines) if lines else "- predecessors resolved but descriptions missing"


def _format_interventions(spec: InterventionSpec) -> str:
    if not spec.interventions:
        return "- no intervention generated"
    lines = []
    for item in spec.interventions:
        target = "line N/A" if item.target_line < 0 else f"line {item.target_line}"
        lines.append(f"- {item.enforce} @ {target}: {item.rationale}")
    return "\n".join(lines)


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
    removal_reason = (
        "The patched condition eliminates the causal prerequisites"
        if effect.get("vulnerability_removed")
        else "Formal analysis could not confirm removal of the causal prerequisites"
    )
    return (
        "## Vulnerability Fix Explanation\n\n"
        "### What was wrong?\n"
        f"- Location: line {vuln_line}\n- Issue: {vuln_desc}\n\n"
        "### Root cause (from PCG)\n"
        f"{causal_chain}\n\n"
        "### Planned interventions\n"
        f"{intervention_text}\n\n"
        "### Patch summary\n"
        f"{patch_summary}\n\n"
        "### Why this works\n"
        f"{removal_reason}\n"
    )


def _summarize_patch(patch: PatchResult) -> str:
    if patch.method == "noop":
        return "No patch applied."
    if patch.diff:
        diff_lines = patch.diff.splitlines()
        preview = [line for line in diff_lines if line.startswith("+") or line.startswith("-")]
        preview_text = "\n".join(preview[:8])
    else:
        preview_text = "(No diff generated)"
    applied = ", ".join(patch.applied_guards) if patch.applied_guards else "None"
    return f"Applied method: {patch.method}.\nGuards: {applied}.\nDiff preview:\n{preview_text}"


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
        "1. 무엇이 취약점을 유발했는지 (what)\n"
        "2. 패치가 코드에 어떤 변화를 주었는지 (how)\n"
        "3. 그 변화가 왜 취약점을 제거하는지 (why)\n"
        "4. 답변은 한국어로 작성합니다."
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
