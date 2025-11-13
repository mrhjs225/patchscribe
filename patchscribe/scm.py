"""
Structural Causal Model abstraction derived from Program Causal Graphs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List

from .pcg import ProgramCausalGraph


@dataclass
class SCMVariable:
    name: str
    var_type: str  # "bool", "int", "pointer"
    domain: List[str] = field(default_factory=list)
    identifier: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "SCMVariable":
        return cls(
            name=data.get("name", ""),
            var_type=data.get("var_type", "unknown"),
            domain=list(data.get("domain", [])),
            identifier=data.get("identifier", ""),
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
            var_name = self._variable_name_semantic(node)
            metadata = node.metadata or {}
            self.model.variables[var_name] = SCMVariable(
                name=var_name,
                var_type=metadata.get("datatype") or self._infer_type(node.node_type),
                domain=list(metadata.get("value_range") or []),
                identifier=metadata.get("identifier") or var_name,
            )

    def _create_equations(self) -> None:
        for node in self.graph.nodes.values():
            target = self._variable_name_semantic(node)
            parents = self.graph.predecessors(node.node_id)
            if not parents:
                expr = "exogenous"  # no parents, treat as external input
            else:
                parent_vars = [self._variable_name_semantic(self.graph.nodes[pid]) for pid in parents]
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
            condition = " AND ".join(
                self._variable_name_semantic(self.graph.nodes[pid]) for pid in parents
            )
        self.model.vulnerable_condition = condition

    @staticmethod
    def _variable_name(node_id: str) -> str:
        """Legacy variable naming: V_<node_id>"""
        return f"V_{node_id}"

    def _variable_name_semantic(self, node) -> str:
        """Generate semantic variable name from node description"""
        if not node:
            return f"V_{node.node_id if hasattr(node, 'node_id') else 'unknown'}"

        # Extract semantic meaning from node description
        desc = node.description.lower() if node.description else ""

        # Pattern matching for common predicates
        semantic_name = self._extract_semantic_name(desc, node.node_type)

        # Combine semantic name with node ID for uniqueness
        # Format: <semantic_name>_<node_id>
        return f"{semantic_name}_{node.node_id}"

    def _extract_semantic_name(self, description: str, node_type: str) -> str:
        """Extract meaningful name from node description"""
        desc = description.strip()

        # NULL pointer checks
        if "null" in desc or ("!" in desc and any(ptr in desc for ptr in ["ptr", "pointer", "key", "buf", "data", "node", "obj"])):
            var_name = self._extract_variable_name(desc)
            return f"null_check_{var_name}" if var_name else "null_check"

        # Bounds checks
        if any(op in desc for op in ["<", ">", "<=", ">="]) and any(w in desc for w in ["size", "len", "count", "num", "max", "min"]):
            if "size" in desc:
                return "bounds_check_size"
            elif "len" in desc:
                return "bounds_check_len"
            else:
                return "bounds_check"

        # State validation
        if any(w in desc for w in ["state", "status", "valid", "ready", "init"]) and "==" in desc:
            return "state_valid"

        # Authentication/authorization
        if any(w in desc for w in ["auth", "perm", "cred", "key", "user", "owner"]):
            return "auth_check"

        # Lock/synchronization
        if any(w in desc for w in ["lock", "mutex", "sync", "atomic"]):
            return "sync_check"

        # Resource allocation
        if any(w in desc for w in ["alloc", "malloc", "calloc", "new", "create"]):
            return "resource_alloc"

        # Array/buffer access
        if "[" in desc and "]" in desc:
            return "array_access"

        # Function call checks
        if "(" in desc and ")" in desc and "==" in desc:
            return "call_result_check"

        # Error checking
        if any(w in desc for w in ["error", "err", "fail", "ret"]) and any(op in desc for op in ["==", "!=", "<"]):
            return "error_check"

        # Zero check
        if ("== 0" in desc or "!= 0" in desc) and node_type == "predicate":
            return "zero_check"

        # Generic predicate
        if node_type == "predicate":
            # Extract first meaningful word
            words = [w for w in desc.split() if len(w) > 2 and w not in ["if", "the", "and", "or", "not", "for", "while"]]
            if words:
                # Clean special characters
                clean_word = re.sub(r'[^\w]', '', words[0])
                return f"check_{clean_word[:12]}"

        # Vulnerability node
        if node_type == "vulnerability":
            return "vuln"

        # Assignment/operation
        if node_type == "assignment":
            return "assign"

        # Default
        return "condition"

    def _extract_variable_name(self, description: str) -> str:
        """Extract variable name from condition like '!authkey' or 'ptr == NULL'"""
        # Match patterns like: !var, var==NULL, var!=NULL, etc.
        patterns = [
            r'!\s*(\w+)',                # !authkey
            r'(\w+)\s*==\s*NULL',        # ptr == NULL
            r'(\w+)\s*!=\s*NULL',        # ptr != NULL
            r'if\s*\(\s*!?\s*(\w+)',     # if (!var) or if (var)
            r'(\w+)\s*==\s*0',           # var == 0
            r'(\w+)\s*!=\s*0',           # var != 0
        ]
        for pattern in patterns:
            match = re.search(pattern, description)
            if match:
                var = match.group(1)
                # Filter out common keywords
                if var not in ['if', 'for', 'while', 'return', 'NULL', 'null']:
                    return var[:12]  # Limit length
        return ""

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
