"""
Structural Causal Model abstraction derived from Program Causal Graphs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List

from .pcg import ProgramCausalGraph


@dataclass
class SCMVariable:
    name: str
    var_type: str  # "bool", "int", "pointer"
    domain: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "SCMVariable":
        return cls(
            name=data.get("name", ""),
            var_type=data.get("var_type", "unknown"),
            domain=list(data.get("domain", [])),
        )


@dataclass
class StructuralEquation:
    target: str
    expression: str

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "StructuralEquation":
        return cls(
            target=data.get("target", ""),
            expression=data.get("expression", ""),
        )


@dataclass
class StructuralCausalModel:
    variables: Dict[str, SCMVariable] = field(default_factory=dict)
    equations: List[StructuralEquation] = field(default_factory=list)
    vulnerable_condition: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "variables": {name: var.__dict__ for name, var in self.variables.items()},
            "equations": [eq.__dict__ for eq in self.equations],
            "vulnerable_condition": self.vulnerable_condition,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "StructuralCausalModel":
        model = cls()
        for name, var in (data.get("variables") or {}).items():
            if isinstance(var, dict):
                model.variables[name] = SCMVariable.from_dict(
                    {"name": var.get("name", name), **var}
                )
        for eq in data.get("equations", []):
            if isinstance(eq, dict):
                model.equations.append(StructuralEquation.from_dict(eq))
        model.vulnerable_condition = data.get("vulnerable_condition", "")
        return model


class SCMBuilder:
    def __init__(self, graph: ProgramCausalGraph) -> None:
        self.graph = graph
        self.model = StructuralCausalModel()

    def derive(self) -> StructuralCausalModel:
        self._define_variables()
        self._create_equations()
        self._formalize_vulnerability()
        return self.model

    def _define_variables(self) -> None:
        for node in self.graph.nodes.values():
            var_name = self._variable_name(node.node_id)
            self.model.variables[var_name] = SCMVariable(
                name=var_name,
                var_type=self._infer_type(node.node_type),
            )

    def _create_equations(self) -> None:
        for node in self.graph.nodes.values():
            target = self._variable_name(node.node_id)
            parents = self.graph.predecessors(node.node_id)
            if not parents:
                expr = "exogenous"  # no parents, treat as external input
            else:
                parent_vars = [self._variable_name(pid) for pid in parents]
                expr = " AND ".join(parent_vars)
            description = node.description.replace("\"", "'")
            equation = StructuralEquation(
                target=target,
                expression=f"{expr}  # {description}",
            )
            self.model.equations.append(equation)

    def _formalize_vulnerability(self) -> None:
        vuln_nodes = [n for n in self.graph.nodes.values() if n.node_type == "vulnerability"]
        if not vuln_nodes:
            self.model.vulnerable_condition = "False"
            return
        vuln = vuln_nodes[0]
        parents = self.graph.predecessors(vuln.node_id)
        if not parents:
            condition = "True"
        else:
            condition = " AND ".join(self._variable_name(pid) for pid in parents)
        self.model.vulnerable_condition = condition

    @staticmethod
    def _variable_name(node_id: str) -> str:
        return f"V_{node_id}"

    @staticmethod
    def _infer_type(node_type: str) -> str:
        if node_type in {"predicate", "vulnerability"}:
            return "bool"
        if node_type == "assignment":
            return "int"
        return "unknown"

    @staticmethod
    def _find_nodes_of_type(graph: ProgramCausalGraph, node_type: str) -> Iterable[str]:
        return (node_id for node_id, node in graph.nodes.items() if node.node_type == node_type)
