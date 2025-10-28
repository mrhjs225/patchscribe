"""
Formal specifications for bug and patch explanations.
These structures integrate information from PCG, SCM, and intervention analysis
to provide complete, machine-checkable vulnerability specifications.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .intervention import InterventionSpec
from .pcg import ProgramCausalGraph
from .scm import StructuralCausalModel


@dataclass
class VariableSpec:
    """Specification of a variable in the formal model"""
    name: str
    var_type: str  # "bool", "int", "pointer"
    meaning: str
    code_location: str
    domain: List[str] = field(default_factory=list)


@dataclass
class CausalPath:
    """Representation of a causal path from inputs to vulnerability"""
    path_id: str
    nodes: List[str]
    description: str
    

@dataclass
class Assertion:
    """Verification assertion"""
    expression: str
    location: str
    description: str


@dataclass
class FormalBugExplanation:
    """
    Complete formal specification of a vulnerability (E_bug).
    This is the output of Phase 1: Vulnerability Formalization.
    """
    # Formal specification
    formal_condition: str  # "V_bug ⟺ φ(X₁, ..., Xₙ)"
    variables: Dict[str, VariableSpec]
    
    # Natural language description
    description: str
    manifestation: str
    
    # Code mapping
    vulnerable_location: str
    causal_paths: List[CausalPath]
    
    # Fix requirements
    safety_property: str  # "∀inputs: ¬V_bug(inputs)"
    intervention_options: List[str]
    
    # Verification artifacts
    preconditions: List[str]
    postconditions: List[str]
    assertions: List[Assertion]


@dataclass
class CodeDiff:
    """Structured representation of code changes"""
    added_lines: List[Dict[str, object]]
    modified_lines: List[Dict[str, object]]
    deleted_lines: List[Dict[str, object]]


@dataclass
class InterventionDescription:
    """Formal description of patch intervention"""
    formal: str  # "do(Variable = value)"
    affected_variables: List[str]
    description: str


@dataclass
class EffectAnalysis:
    """Analysis of patch effect on vulnerability"""
    before: str  # Original V_bug condition
    after: str   # Modified condition
    reasoning: str


@dataclass
class FormalPatchExplanation:
    """
    Complete formal specification of a patch (E_patch).
    This is the output of Phase 2: Theory-Guided Patch Generation.
    """
    # Code changes
    code_diff: CodeDiff
    
    # Causal intervention
    intervention: InterventionDescription
    
    # Effect on vulnerability
    effect_on_Vbug: EffectAnalysis
    
    # Causal analysis
    addressed_causes: List[str]
    unaddressed_causes: List[str]
    disrupted_paths: List[str]
    
    # Natural language
    summary: str
    mechanism: str
    consequence: str
    
    # Verification properties
    postconditions: List[str]
    new_assertions: List[str]


def generate_E_bug(
    pcg: ProgramCausalGraph,
    scm: StructuralCausalModel,
    intervention_spec: InterventionSpec,
    vuln_info: Dict[str, object]
) -> FormalBugExplanation:
    """
    Generate complete formal bug explanation from PCG, SCM, and intervention spec.
    Integrates distributed information into a unified specification.
    """
    # Extract variables from SCM with code locations from PCG
    variables = {}
    for var_name, scm_var in scm.variables.items():
        node_id = var_name[2:] if var_name.startswith("V_") else var_name
        node = pcg.nodes.get(node_id)
        
        variables[var_name] = VariableSpec(
            name=var_name,
            var_type=scm_var.var_type,
            meaning=node.description if node else "Unknown",
            code_location=f"line {node.location}" if node and node.location else "Unknown",
            domain=scm_var.domain
        )
    
    # Extract causal paths from PCG
    causal_paths = _extract_causal_paths(pcg)
    
    # Generate assertions from postconditions
    assertions = _generate_assertions(scm, pcg, vuln_info)
    
    # Build intervention options from InterventionSpec
    intervention_options = [
        f"Option {i+1}: {interv.rationale} (enforce {interv.enforce})"
        for i, interv in enumerate(intervention_spec.interventions)
    ]
    
    # Find vulnerability node for description
    vuln_node = None
    vuln_location = "Unknown"
    for node in pcg.nodes.values():
        if node.node_type == "vulnerability":
            vuln_node = node
            vuln_location = f"line {node.location}, {node.description}" if node.location else node.description
            break
    
    description = (
        f"Vulnerability occurs when {scm.vulnerable_condition or 'condition not determined'}. "
        f"Located at {vuln_location}."
    )
    
    return FormalBugExplanation(
        formal_condition=f"V_bug ⟺ {scm.vulnerable_condition or 'True'}",
        variables=variables,
        description=description,
        manifestation=f"Manifests at {vuln_location}",
        vulnerable_location=vuln_location,
        causal_paths=causal_paths,
        safety_property=f"∀inputs: ¬({scm.vulnerable_condition or 'V_bug'})",
        intervention_options=intervention_options,
        preconditions=[
            "Input can be attacker-controlled",
            "Execution reaches vulnerable location"
        ],
        postconditions=[
            f"Vulnerable condition ({scm.vulnerable_condition}) is unsatisfiable",
            "OR vulnerable location is unreachable"
        ],
        assertions=assertions
    )


def generate_E_patch(
    patch_code: str,
    diff: str,
    E_bug: FormalBugExplanation,
    pcg: ProgramCausalGraph,
    scm: StructuralCausalModel,
    effect_dict: Dict[str, object]
) -> FormalPatchExplanation:
    """
    Generate complete formal patch explanation by analyzing how the patch
    intervenes on the causal model.
    """
    # Parse code diff
    code_diff = _parse_diff(diff)
    
    # Identify intervention
    intervention = _identify_intervention(patch_code, diff, scm, pcg)
    
    # Analyze effect on V_bug
    effect_analysis = EffectAnalysis(
        before=E_bug.formal_condition,
        after=effect_dict.get("patched_condition", "Unknown"),
        reasoning=_explain_effect(E_bug, intervention, effect_dict)
    )
    
    # Classify addressed vs unaddressed causes
    addressed_causes, unaddressed_causes = _classify_causes(
        E_bug, intervention, code_diff
    )
    
    # Analyze disrupted paths
    disrupted_paths = _analyze_disrupted_paths(E_bug, intervention, pcg)
    
    # Generate postconditions
    postconditions = [
        f"{var} constraint satisfied" 
        for var in intervention.affected_variables
    ]
    
    # Generate new assertions
    new_assertions = [
        f"assert({post})" for post in postconditions
    ]
    
    return FormalPatchExplanation(
        code_diff=code_diff,
        intervention=intervention,
        effect_on_Vbug=effect_analysis,
        addressed_causes=addressed_causes,
        unaddressed_causes=unaddressed_causes,
        disrupted_paths=disrupted_paths,
        summary=f"Patch intervenes on {', '.join(intervention.affected_variables)}",
        mechanism=intervention.description,
        consequence="Vulnerability condition becomes unsatisfiable" if effect_dict.get("vulnerability_removed") else "Partial mitigation",
        postconditions=postconditions,
        new_assertions=new_assertions
    )


def _extract_causal_paths(pcg: ProgramCausalGraph) -> List[CausalPath]:
    """Extract causal paths from PCG leading to vulnerability"""
    paths = []
    
    # Find vulnerability node
    vuln_id = None
    for node_id, node in pcg.nodes.items():
        if node.node_type == "vulnerability":
            vuln_id = node_id
            break
    
    if not vuln_id:
        return paths
    
    # Get all paths to vulnerability (simplified: just predecessors)
    predecessors = pcg.predecessors(vuln_id)
    for i, pred_id in enumerate(predecessors):
        pred_node = pcg.nodes.get(pred_id)
        if pred_node:
            paths.append(CausalPath(
                path_id=f"path_{i+1}",
                nodes=[pred_id, vuln_id],
                description=f"{pred_node.description} → vulnerability"
            ))
    
    return paths


def _generate_assertions(
    scm: StructuralCausalModel,
    pcg: ProgramCausalGraph,
    vuln_info: Dict[str, object]
) -> List[Assertion]:
    """Generate verification assertions from vulnerability condition"""
    assertions = []
    
    condition = scm.vulnerable_condition
    if condition and condition != "True":
        # Generate assertion to check vulnerability is prevented
        vuln_line = vuln_info.get("location", -1)
        location = f"line {vuln_line - 1}" if vuln_line > 0 else "before vulnerable operation"
        
        assertions.append(Assertion(
            expression=f"!({condition})",
            location=location,
            description=f"Ensure vulnerability condition is false at {location}"
        ))
    
    return assertions


def _parse_diff(diff: str) -> CodeDiff:
    """Parse unified diff into structured format"""
    added = []
    modified = []
    deleted = []
    
    if not diff:
        return CodeDiff(added, modified, deleted)
    
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added.append({"code": line[1:].strip()})
        elif line.startswith("-") and not line.startswith("---"):
            deleted.append({"code": line[1:].strip()})
    
    return CodeDiff(added, modified, deleted)


def _identify_intervention(
    patch_code: str,
    diff: str,
    scm: StructuralCausalModel,
    pcg: ProgramCausalGraph
) -> InterventionDescription:
    """Identify what causal intervention the patch performs"""
    affected_vars = []
    description_parts = []
    
    # Look for added checks or modifications
    for line in diff.splitlines():
        if line.startswith("+"):
            code = line[1:].strip()
            # Check if this affects any SCM variables
            for var_name in scm.variables.keys():
                node_id = var_name[2:] if var_name.startswith("V_") else var_name
                node = pcg.nodes.get(node_id)
                if node and node.description:
                    # Simple keyword matching
                    desc_words = node.description.lower().split()
                    if any(word in code.lower() for word in desc_words if len(word) > 3):
                        if var_name not in affected_vars:
                            affected_vars.append(var_name)
                            description_parts.append(f"modifies {node.description}")
    
    if not affected_vars:
        # Generic description
        formal_intervention = "do(Check = true)"
        description = "Adds security check or validation"
        affected_vars = ["V_check"]
    else:
        formal_intervention = f"do({affected_vars[0]} = safe_value)"
        description = "; ".join(description_parts)
    
    return InterventionDescription(
        formal=formal_intervention,
        affected_variables=affected_vars,
        description=description
    )


def _explain_effect(
    E_bug: FormalBugExplanation,
    intervention: InterventionDescription,
    effect_dict: Dict[str, object]
) -> str:
    """Explain how intervention affects vulnerability"""
    if effect_dict.get("vulnerability_removed"):
        return (
            f"With intervention {intervention.formal}, "
            f"the vulnerability condition becomes unsatisfiable because "
            f"{intervention.description}."
        )
    else:
        return (
            f"Intervention {intervention.formal} partially addresses the vulnerability "
            f"but may not cover all cases."
        )


def _classify_causes(
    E_bug: FormalBugExplanation,
    intervention: InterventionDescription,
    code_diff: CodeDiff
) -> tuple[List[str], List[str]]:
    """Classify which causes are addressed vs unaddressed"""
    addressed = []
    unaddressed = []
    
    # Simple heuristic: if intervention affects variables in a causal path, it's addressed
    for path in E_bug.causal_paths:
        path_addressed = False
        for var in intervention.affected_variables:
            if any(node_id in var or var in node_id for node_id in path.nodes):
                path_addressed = True
                break
        
        if path_addressed:
            addressed.append(path.description)
        else:
            # Check if it's justified (e.g., path is already safe)
            unaddressed.append(path.description)
    
    return addressed, unaddressed


def _analyze_disrupted_paths(
    E_bug: FormalBugExplanation,
    intervention: InterventionDescription,
    pcg: ProgramCausalGraph
) -> List[str]:
    """Analyze which causal paths are disrupted by the intervention"""
    disrupted = []
    
    for path in E_bug.causal_paths:
        # Check if intervention affects any node in the path
        for var in intervention.affected_variables:
            node_id = var[2:] if var.startswith("V_") else var
            if node_id in path.nodes:
                disrupted.append(
                    f"{path.description}: "
                    f"Path broken by {intervention.description}"
                )
                break
    
    return disrupted
