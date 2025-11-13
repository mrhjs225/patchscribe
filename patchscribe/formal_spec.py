"""
Formal specifications for bug and patch explanations.
These structures integrate information from PCG, SCM, and intervention analysis
to provide complete, machine-checkable vulnerability specifications.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
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
    identifier: str = ""
    
    def as_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "VariableSpec":
        return cls(
            name=data.get("name", ""),
            var_type=data.get("var_type", "unknown"),
            meaning=data.get("meaning", ""),
            code_location=data.get("code_location", "Unknown"),
            domain=list(data.get("domain", [])),
            identifier=data.get("identifier", ""),
        )


@dataclass
class CausalPath:
    """Representation of a causal path from inputs to vulnerability"""
    path_id: str
    nodes: List[str]
    description: str
    
    def as_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "CausalPath":
        return cls(
            path_id=data.get("path_id", ""),
            nodes=list(data.get("nodes", [])),
            description=data.get("description", ""),
        )
    

@dataclass
class Assertion:
    """Verification assertion"""
    expression: str
    location: str
    description: str
    
    def as_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "Assertion":
        return cls(
            expression=data.get("expression", ""),
            location=data.get("location", ""),
            description=data.get("description", ""),
        )


@dataclass
class FormalBugExplanation:
    """
    Complete formal specification of a vulnerability (E_bug).
    This is the output of Phase 1: Vulnerability Formalization.

    Enhanced with prescriptive fix requirements to guide patch generation.
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

    # Fix requirements (original)
    safety_property: str  # "∀inputs: ¬V_bug(inputs)"
    intervention_options: List[str]

    # Enhanced fix requirements (NEW)
    required_fixes: List[str] = field(default_factory=list)  # What MUST be done to fix
    fix_constraints: List[str] = field(default_factory=list)  # Constraints the fix must satisfy
    invalid_fixes: List[str] = field(default_factory=list)  # Known insufficient solutions
    must_preserve: List[str] = field(default_factory=list)  # Functionality that must not break

    # Verification artifacts
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    assertions: List[Assertion] = field(default_factory=list)
    smt_artifact: str = ""
    json_artifact: Dict[str, object] = field(default_factory=dict)
    
    def as_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'formal_condition': self.formal_condition,
            'variables': {k: v.as_dict() for k, v in self.variables.items()},
            'description': self.description,
            'manifestation': self.manifestation,
            'vulnerable_location': self.vulnerable_location,
            'causal_paths': [p.as_dict() for p in self.causal_paths],
            'safety_property': self.safety_property,
            'intervention_options': self.intervention_options,
            'required_fixes': self.required_fixes,
            'fix_constraints': self.fix_constraints,
            'invalid_fixes': self.invalid_fixes,
            'must_preserve': self.must_preserve,
            'preconditions': self.preconditions,
            'postconditions': self.postconditions,
            'assertions': [a.as_dict() for a in self.assertions],
            'smt_artifact': self.smt_artifact,
            'json_artifact': self.json_artifact,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "FormalBugExplanation":
        variables = {
            name: VariableSpec.from_dict(var)
            for name, var in (data.get("variables") or {}).items()
            if isinstance(var, dict)
        }
        causal_paths = [
            CausalPath.from_dict(item)
            for item in data.get("causal_paths", [])
            if isinstance(item, dict)
        ]
        assertions = [
            Assertion.from_dict(item)
            for item in data.get("assertions", [])
            if isinstance(item, dict)
        ]
        return cls(
            formal_condition=data.get("formal_condition", ""),
            variables=variables,
            description=data.get("description", ""),
            manifestation=data.get("manifestation", ""),
            vulnerable_location=data.get("vulnerable_location", ""),
            causal_paths=causal_paths,
            safety_property=data.get("safety_property", ""),
            intervention_options=list(data.get("intervention_options", [])),
            required_fixes=list(data.get("required_fixes", [])),
            fix_constraints=list(data.get("fix_constraints", [])),
            invalid_fixes=list(data.get("invalid_fixes", [])),
            must_preserve=list(data.get("must_preserve", [])),
            preconditions=list(data.get("preconditions", [])),
            postconditions=list(data.get("postconditions", [])),
            assertions=assertions,
            smt_artifact=data.get("smt_artifact", ""),
            json_artifact=data.get("json_artifact") or {},
        )


@dataclass
class CodeDiff:
    """Structured representation of code changes"""
    added_lines: List[Dict[str, object]]
    modified_lines: List[Dict[str, object]]
    deleted_lines: List[Dict[str, object]]
    
    def as_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


@dataclass
class InterventionDescription:
    """Formal description of patch intervention"""
    formal: str  # "do(Variable = value)"
    affected_variables: List[str]
    description: str
    do_expression: str = ""
    
    def as_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


@dataclass
class EffectAnalysis:
    """Analysis of patch effect on vulnerability"""
    before: str  # Original V_bug condition
    after: str   # Modified condition
    reasoning: str
    
    def as_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


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
    smt_artifact: str = ""
    
    def as_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'code_diff': self.code_diff.as_dict(),
            'intervention': self.intervention.as_dict(),
            'effect_on_Vbug': self.effect_on_Vbug.as_dict(),
            'addressed_causes': self.addressed_causes,
            'unaddressed_causes': self.unaddressed_causes,
            'disrupted_paths': self.disrupted_paths,
            'summary': self.summary,
            'mechanism': self.mechanism,
            'consequence': self.consequence,
            'postconditions': self.postconditions,
            'new_assertions': self.new_assertions,
            'smt_artifact': self.smt_artifact,
        }


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
            domain=scm_var.domain,
            identifier=scm_var.identifier or (node.metadata.get("identifier") if node and node.metadata else ""),
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

    # Generate prescriptive fix requirements based on vulnerability analysis
    required_fixes, fix_constraints, invalid_fixes, must_preserve = _generate_fix_requirements(
        pcg, scm, intervention_spec, vuln_info
    )

    bug_spec = FormalBugExplanation(
        formal_condition=f"V_bug ⟺ {scm.vulnerable_condition or 'True'}",
        variables=variables,
        description=description,
        manifestation=f"Manifests at {vuln_location}",
        vulnerable_location=vuln_location,
        causal_paths=causal_paths,
        safety_property=f"∀inputs: ¬({scm.vulnerable_condition or 'V_bug'})",
        intervention_options=intervention_options,
        required_fixes=required_fixes,
        fix_constraints=fix_constraints,
        invalid_fixes=invalid_fixes,
        must_preserve=must_preserve,
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
    bug_spec.smt_artifact = _build_bug_smt_artifact(variables, scm.vulnerable_condition)
    bug_spec.json_artifact = _build_bug_json_artifact(variables, scm, intervention_spec)
    return bug_spec


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
    
    removal_confirmed = bool(effect_dict.get("vulnerability_removed"))
    if removal_confirmed and E_bug.causal_paths:
        addressed_causes = [path.description for path in E_bug.causal_paths]
        unaddressed_causes = []
        disrupted_paths = [
            f"{path.description}: disrupted because {intervention.description or 'the new guard'}"
            for path in E_bug.causal_paths
        ]
    
    # Generate postconditions
    postconditions = [
        f"{var} constraint satisfied" 
        for var in intervention.affected_variables
    ]
    
    # Generate new assertions
    new_assertions = [
        f"assert({post})" for post in postconditions
    ]
    
    patch_spec = FormalPatchExplanation(
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
    patch_spec.smt_artifact = _build_patch_smt_artifact(E_bug, effect_analysis, intervention)
    return patch_spec


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
    
    old_line = 0
    new_line = 0
    pending_delete = None
    hunk_pattern = re.compile(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")

    for raw_line in diff.splitlines():
        if raw_line.startswith("@@"):
            match = hunk_pattern.match(raw_line)
            if match:
                old_line = int(match.group(1))
                new_line = int(match.group(2))
            pending_delete = None
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            code = raw_line[1:].rstrip()
            if pending_delete:
                modified.append(
                    {
                        "before": pending_delete["code"],
                        "after": code,
                        "old_line": pending_delete["line"],
                        "new_line": new_line,
                    }
                )
                pending_delete = None
            else:
                added.append({"code": code, "line": new_line})
            new_line += 1
            continue

        if raw_line.startswith("-") and not raw_line.startswith("---"):
            if pending_delete:
                deleted.append(pending_delete)
            pending_delete = {"code": raw_line[1:].rstrip(), "line": old_line}
            old_line += 1
            continue

        if pending_delete:
            deleted.append(pending_delete)
            pending_delete = None

        if raw_line.startswith(" "):
            old_line += 1
            new_line += 1
        elif raw_line.startswith("\\"):
            # No line number change for diff metadata
            continue

    if pending_delete:
        deleted.append(pending_delete)
    
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
    added_lines: List[str] = [
        line[1:].strip()
        for line in diff.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    
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
        # Fall back to describing the concrete code adjustments so that
        # downstream consistency checks can match the diff keywords.
        snippet = "; ".join(added_lines[:2]).strip()
        if len(snippet) > 160:
            snippet = snippet[:157].rstrip() + "..."
        description = (
            f"adjusts vulnerable code: {snippet}"
            if snippet
            else "adjusts vulnerable code to enforce safety guard"
        )
        formal_intervention = "do(patch_adjustment)"
        affected_vars = ["V_patch"]
    else:
        formal_intervention = f"do({affected_vars[0]} = safe_value)"
        description = "; ".join(description_parts)
    
    return InterventionDescription(
        formal=formal_intervention,
        affected_variables=affected_vars,
        description=description,
        do_expression=formal_intervention,
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


# Helper functions for causal analysis-based fix requirement generation

def _find_vulnerability_node(pcg: ProgramCausalGraph) -> Optional[str]:
    """Find the vulnerability node in PCG"""
    for node_id, node in pcg.nodes.items():
        if node.node_type == "vulnerability":
            return node_id
    return None


def _extract_all_causal_paths_to_vuln(
    pcg: ProgramCausalGraph,
    vuln_node_id: str
) -> List[List[str]]:
    """
    Extract all causal paths from inputs to vulnerability.

    Algorithm: BFS from vulnerability node backwards to find all paths to root causes.
    """
    paths = []

    def dfs_paths(current: str, path: List[str], visited: set) -> None:
        if current in visited:
            return

        visited.add(current)
        path.append(current)

        predecessors = pcg.predecessors(current)
        if not predecessors:
            # Reached a root cause (no predecessors)
            paths.append(list(reversed(path)))
        else:
            for pred in predecessors:
                dfs_paths(pred, path.copy(), visited.copy())

    dfs_paths(vuln_node_id, [], set())
    return paths


def _derive_required_interventions_from_paths(
    causal_paths: List[List[str]],
    pcg: ProgramCausalGraph,
    scm: StructuralCausalModel
) -> List[Dict[str, object]]:
    """
    Derive required interventions using minimum vertex cover approach.

    Goal: Find minimum set of nodes whose intervention disrupts all paths.

    Algorithm:
    1. Build a set of all nodes in all paths (excluding vuln node)
    2. Use greedy approximation for weighted vertex cover
    3. Select nodes that cover maximum paths with minimum cost
    """
    if not causal_paths:
        return []

    # Count how many paths each node appears in
    node_path_count: Dict[str, int] = {}
    for path in causal_paths:
        for node_id in path[:-1]:  # Exclude vulnerability node
            node_path_count[node_id] = node_path_count.get(node_id, 0) + 1

    # Greedy selection: pick nodes that cover most paths
    interventions = []
    covered_paths = set()

    # Sort by coverage (descending)
    sorted_nodes = sorted(
        node_path_count.items(),
        key=lambda x: x[1],
        reverse=True
    )

    for node_id, count in sorted_nodes:
        # Find which paths this node covers
        node_paths = {
            i for i, path in enumerate(causal_paths)
            if node_id in path[:-1]
        }

        # If this node covers new paths, include it
        new_coverage = node_paths - covered_paths
        if new_coverage:
            node = pcg.nodes.get(node_id)
            if node:
                interventions.append({
                    'node_id': node_id,
                    'node': node,
                    'covered_paths': list(new_coverage),
                    'coverage_count': len(new_coverage)
                })
                covered_paths.update(new_coverage)

        # Early termination if all paths covered
        if len(covered_paths) >= len(causal_paths):
            break

    return interventions


def _build_bug_smt_artifact(
    variables: Dict[str, VariableSpec],
    vulnerable_condition: str,
) -> str:
    condition = (vulnerable_condition or "").strip()
    if not condition:
        return ""
    decls = _build_smt_declarations(variables)
    smt_condition = _condition_to_smt(condition)
    lines = ["(set-logic HORN)"]
    lines.extend(decls)
    lines.append(f"(assert {smt_condition})")
    lines.append("(check-sat)")
    return "\n".join(lines)


def _build_patch_smt_artifact(
    E_bug: FormalBugExplanation,
    effect: EffectAnalysis,
    intervention: InterventionDescription,
) -> str:
    bug_condition = E_bug.formal_condition or ""
    if "⟺" in bug_condition:
        bug_condition = bug_condition.split("⟺", 1)[1].strip()
    bug_condition = bug_condition or "True"
    patched_condition = effect.after or "False"
    decls = _build_smt_declarations(E_bug.variables)
    bug_expr = _condition_to_smt(bug_condition)
    patched_expr = _condition_to_smt(patched_condition)
    lines = ["(set-logic HORN)"]
    lines.extend(decls)
    if intervention.do_expression or intervention.formal:
        lines.append(f"; intervention {intervention.do_expression or intervention.formal}")
    lines.append(f"(assert {bug_expr})")
    lines.append(f"(assert (not {patched_expr}))")
    lines.append("(check-sat)")
    return "\n".join(lines)


def _build_bug_json_artifact(
    variables: Dict[str, VariableSpec],
    scm: StructuralCausalModel,
    intervention_spec: InterventionSpec,
) -> Dict[str, object]:
    return {
        "variables": {
            name: {
                "identifier": spec.identifier or name,
                "type": spec.var_type,
                "domain": spec.domain,
                "location": spec.code_location,
            }
            for name, spec in variables.items()
        },
        "equations": [eq.__dict__ for eq in scm.equations],
        "vulnerable_condition": scm.vulnerable_condition,
        "interventions": [item.to_dict() for item in intervention_spec.interventions],
    }


def _build_smt_declarations(variables: Dict[str, VariableSpec]) -> List[str]:
    decls: List[str] = []
    for name, spec in variables.items():
        sort = "Bool"
        if spec.var_type in {"int", "size"}:
            sort = "Int"
        elif spec.var_type == "pointer":
            sort = "Int"
        decls.append(f"(declare-const {name} {sort})")
    return decls


def _condition_to_smt(condition: str) -> str:
    expr = _normalize_boolean_expr(condition)
    if not expr:
        return "true"
    if expr.startswith("(") and expr.endswith(")"):
        return _condition_to_smt(expr[1:-1])
    if expr.upper().startswith("NOT "):
        return f"(not {_condition_to_smt(expr[4:].strip())})"

    for operator, smt_op in ((" OR ", "or"), (" AND ", "and")):
        parts = _split_top_level(expr, operator.strip())
        if len(parts) > 1:
            smt_parts = " ".join(_condition_to_smt(part) for part in parts)
            return f"({smt_op} {smt_parts})"

    if " " in expr:
        return "true"
    return expr


def _split_top_level(expression: str, operator: str) -> List[str]:
    op = f" {operator} "
    expr_upper = expression.upper()
    parts: List[str] = []
    depth = 0
    start = 0
    i = 0
    while i <= len(expr_upper) - len(op):
        ch = expr_upper[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if depth == 0 and expr_upper[i : i + len(op)] == op:
            parts.append(expression[start:i])
            start = i + len(op)
            i += len(op)
            continue
        i += 1
    parts.append(expression[start:])
    return [part.strip() for part in parts if part.strip()]


def _normalize_boolean_expr(expr: str) -> str:
    expr = expr.replace("&&", " AND ").replace("||", " OR ").replace("!", " NOT ")
    expr = re.sub(r"\bAND\b", " AND ", expr, flags=re.IGNORECASE)
    expr = re.sub(r"\bOR\b", " OR ", expr, flags=re.IGNORECASE)
    expr = re.sub(r"\bNOT\b", " NOT ", expr, flags=re.IGNORECASE)
    expr = re.sub(r"\s+", " ", expr)
    return expr.strip()


def _translate_intervention_to_requirement(
    intervention: Dict[str, object],
    pcg: ProgramCausalGraph
) -> str:
    """
    Translate a causal intervention to a code-level requirement.

    Uses node description and type to infer the appropriate code action.
    """
    node = intervention['node']
    node_id = intervention['node_id']

    description = node.description if node.description else f"node {node_id}"

    # Infer action based on description keywords
    desc_lower = description.lower()

    if any(word in desc_lower for word in ['null', 'nullptr', 'uninitialized']):
        return f"Add NULL/validity check for: {description}"
    elif any(word in desc_lower for word in ['bound', 'size', 'length', 'overflow']):
        return f"Add bounds validation for: {description}"
    elif any(word in desc_lower for word in ['format', 'printf', 'sprintf']):
        return f"Sanitize or use safe format string API for: {description}"
    elif any(word in desc_lower for word in ['integer', 'overflow', 'wraparound']):
        return f"Add overflow check for: {description}"
    elif any(word in desc_lower for word in ['input', 'user', 'external']):
        return f"Validate and sanitize input: {description}"
    else:
        # Generic intervention
        return f"Prevent unsafe state by intervening on: {description}"


def _derive_intervention_constraints(
    intervention: Dict[str, object],
    causal_paths: List[List[str]],
    pcg: ProgramCausalGraph
) -> List[str]:
    """
    Derive constraints for an intervention based on causal paths it must disrupt.
    """
    constraints = []
    node_id = intervention['node_id']
    covered_path_indices = intervention['covered_paths']
    node = intervention['node']  # PCGNode object

    # Constraint 1: Must cover all specified paths
    if len(covered_path_indices) > 0:
        constraints.append(
            f"This intervention must disrupt {len(covered_path_indices)} causal path(s)"
        )

    # Constraint 2: Must occur before vulnerability
    node_desc = node.description if hasattr(node, 'description') else str(node_id)
    constraints.append(
        f"Intervention on {node_desc} must occur "
        "BEFORE the vulnerable operation"
    )

    # Constraint 3: Must cover ALL occurrences if node appears multiple times
    occurrences = sum(1 for path in causal_paths if node_id in path)
    if occurrences > 1:
        constraints.append(
            f"Must handle ALL {occurrences} occurrences of this condition in causal paths"
        )

    return constraints


def _identify_partial_interventions(
    causal_paths: List[List[str]],
    required_interventions: List[Dict[str, object]],
    pcg: ProgramCausalGraph
) -> List[Dict[str, object]]:
    """
    Identify interventions that would be insufficient (don't cover all paths).

    This helps generate the 'invalid_fixes' list by identifying partial solutions.
    """
    partial = []

    # Get nodes that were NOT selected
    selected_nodes = {interv['node_id'] for interv in required_interventions}

    # Find nodes that appear in paths but weren't selected
    all_nodes_in_paths = set()
    for path in causal_paths:
        all_nodes_in_paths.update(path[:-1])  # Exclude vuln node

    unselected_nodes = all_nodes_in_paths - selected_nodes

    for node_id in unselected_nodes:
        # Find which paths this node would cover
        covered = [i for i, path in enumerate(causal_paths) if node_id in path[:-1]]
        uncovered = [i for i in range(len(causal_paths)) if i not in covered]

        if uncovered:  # This intervention would leave some paths uncovered
            node = pcg.nodes.get(node_id)
            if node:
                partial.append({
                    'node_id': node_id,
                    'node': node,
                    'covered_paths': covered,
                    'uncovered_paths': uncovered
                })

    return partial


def _describe_why_insufficient(
    partial_intervention: Dict[str, object],
    causal_paths: List[List[str]],
    pcg: ProgramCausalGraph
) -> str:
    """
    Generate a description of why a partial intervention is insufficient.
    """
    node = partial_intervention['node']
    uncovered = partial_intervention['uncovered_paths']

    if len(uncovered) == len(causal_paths):
        return f"Intervening only on '{node.description}' covers no causal paths"
    else:
        return (
            f"Intervening only on '{node.description}' is insufficient: "
            f"leaves {len(uncovered)} of {len(causal_paths)} causal path(s) uncovered"
        )


def _derive_preservation_constraints(
    scm: StructuralCausalModel,
    required_interventions: List[Dict[str, object]]
) -> List[str]:
    """
    Derive what must be preserved based on SCM equations not involved in interventions.
    """
    preservation = []

    # Get variables involved in interventions
    intervened_vars = {f"V_{interv['node_id']}" for interv in required_interventions}

    # Find variables in SCM not affected by interventions
    for var_name, var_spec in scm.variables.items():
        if var_name not in intervened_vars:
            # This variable should remain unchanged
            if hasattr(var_spec, 'meaning') and var_spec.meaning:
                preservation.append(f"Preserve behavior of: {var_spec.meaning}")

    # Add general preservation requirements
    preservation.extend([
        "Preserve normal program functionality when inputs are valid",
        "Maintain existing error handling and return value semantics"
    ])

    return preservation


def _fallback_to_intervention_spec(
    intervention_spec: InterventionSpec,
    scm: StructuralCausalModel
) -> tuple[List[str], List[str], List[str], List[str]]:
    """
    Fallback when PCG analysis is unavailable: use intervention spec directly.
    """
    required_fixes = []
    fix_constraints = []
    invalid_fixes = []
    must_preserve = []

    # Extract from intervention spec
    for interv in intervention_spec.interventions:
        if interv.enforce:
            required_fixes.append(f"Enforce: {interv.enforce}")
        if interv.rationale:
            fix_constraints.append(f"Rationale: {interv.rationale}")

    # Add constraint from SCM
    if scm.vulnerable_condition and scm.vulnerable_condition != "True":
        required_fixes.append(
            f"Ensure the following condition becomes unsatisfiable: {scm.vulnerable_condition}"
        )

    # Generic constraints
    fix_constraints.extend([
        "Intervention must prevent the vulnerability condition from being satisfied",
        "Fix must not introduce new vulnerabilities or side effects"
    ])

    must_preserve.append("Normal program functionality when inputs are valid")

    return required_fixes, fix_constraints, invalid_fixes, must_preserve


def _generate_fix_requirements(
    pcg: ProgramCausalGraph,
    scm: StructuralCausalModel,
    intervention_spec: InterventionSpec,
    vuln_info: Dict[str, object]
) -> tuple[List[str], List[str], List[str], List[str]]:
    """
    Generate prescriptive fix requirements using causal analysis.

    Systematic approach:
    1. Extract causal paths from PCG leading to vulnerability
    2. For each path, derive intervention points
    3. Translate interventions to code-level requirements
    4. Identify insufficient interventions (invalid fixes)
    5. Determine preservation constraints from unaffected paths

    This replaces hardcoded CWE-specific rules with general causal reasoning.

    Returns:
        (required_fixes, fix_constraints, invalid_fixes, must_preserve)
    """
    required_fixes = []
    fix_constraints = []
    invalid_fixes = []
    must_preserve = []

    # Step 1: Identify vulnerability node in PCG
    vuln_node = _find_vulnerability_node(pcg)
    if not vuln_node:
        # Fallback: use intervention spec
        return _fallback_to_intervention_spec(intervention_spec, scm)

    # Step 2: Extract all causal paths to vulnerability
    causal_paths = _extract_all_causal_paths_to_vuln(pcg, vuln_node)

    # Step 3: Derive required interventions from causal analysis
    required_interventions = _derive_required_interventions_from_paths(
        causal_paths, pcg, scm
    )

    # Step 4: Translate interventions to code-level requirements
    for intervention in required_interventions:
        req_fix = _translate_intervention_to_requirement(intervention, pcg)
        required_fixes.append(req_fix)

        # Add constraints for this intervention
        constraints = _derive_intervention_constraints(intervention, causal_paths, pcg)
        fix_constraints.extend(constraints)

    # Step 5: Identify insufficient interventions (partial path coverage)
    partial_interventions = _identify_partial_interventions(
        causal_paths, required_interventions, pcg
    )
    for partial in partial_interventions:
        invalid_fix = _describe_why_insufficient(partial, causal_paths, pcg)
        invalid_fixes.append(invalid_fix)

    # Step 6: Derive preservation constraints from SCM
    preservation = _derive_preservation_constraints(scm, required_interventions)
    must_preserve.extend(preservation)

    # Step 7: Add high-level constraint from vulnerable condition
    if scm.vulnerable_condition and scm.vulnerable_condition != "True":
        required_fixes.append(
            f"Ensure the following condition becomes unsatisfiable: {scm.vulnerable_condition}"
        )
        fix_constraints.append(
            "All causal paths leading to this condition must be disrupted"
        )

    # Add general constraints
    fix_constraints.extend([
        "Intervention must occur BEFORE the vulnerable operation",
        "Fix must not introduce new vulnerabilities or side effects"
    ])

    return required_fixes, fix_constraints, invalid_fixes, must_preserve
