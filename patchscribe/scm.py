"""
Structural Causal Model abstraction derived from Program Causal Graphs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from .pcg import PCGNode, ProgramCausalGraph
from .scm_templates import SCMTemplateCatalog


@dataclass
class SCMVariable:
    name: str
    var_type: str  # "bool", "int", "pointer"
    domain: List[str] = field(default_factory=list)
    identifier: str = ""
    role: str = ""
    description: str = ""
    origin: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "SCMVariable":
        return cls(
            name=data.get("name", ""),
            var_type=data.get("var_type", "unknown"),
            domain=list(data.get("domain", [])),
            identifier=data.get("identifier", ""),
            role=data.get("role", ""),
            description=data.get("description", ""),
            origin=data.get("origin", ""),
        )


@dataclass
class StructuralEquation:
    target: str
    expression: str
    description: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "StructuralEquation":
        return cls(
            target=data.get("target", ""),
            expression=data.get("expression", ""),
            description=data.get("description", ""),
        )


@dataclass
class StructuralCausalModel:
    variables: Dict[str, SCMVariable] = field(default_factory=dict)
    equations: List[StructuralEquation] = field(default_factory=list)
    vulnerable_condition: str = ""
    metadata: Dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, object]:
        return {
            "variables": {name: var.__dict__ for name, var in self.variables.items()},
            "equations": [eq.__dict__ for eq in self.equations],
            "vulnerable_condition": self.vulnerable_condition,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "StructuralCausalModel":
        model = cls()
        for name, var in (data.get("variables") or {}).items():
            if isinstance(var, dict):
                payload = {"name": var.get("name", name), **var}
                model.variables[name] = SCMVariable.from_dict(payload)
        for eq in data.get("equations", []):
            if isinstance(eq, dict):
                model.equations.append(StructuralEquation.from_dict(eq))
        model.vulnerable_condition = data.get("vulnerable_condition", "")
        model.metadata = data.get("metadata") or {}
        return model


class SCMBuilder:
    def __init__(
        self,
        graph: ProgramCausalGraph,
        cwe_id: Optional[str] = None,
        template_catalog: Optional[SCMTemplateCatalog] = None,
    ) -> None:
        self.graph = graph
        self.model = StructuralCausalModel()
        self.cwe_id = (cwe_id or "Unknown").strip()
        self.metrics: Dict[str, object] = {}

        if template_catalog is not None:
            self.template_catalog = template_catalog
        else:
            try:
                self.template_catalog = SCMTemplateCatalog.load_default()
            except FileNotFoundError:
                self.template_catalog = None
        self.template = (
            self.template_catalog.match(self.cwe_id)
            if self.template_catalog
            else None
        )
        self.template_bindings: Dict[str, str] = {}
        self.node_template_bindings: Dict[str, str] = {}

    def derive(self) -> StructuralCausalModel:
        if self.template:
            self._bind_template_variables()
            self._inject_template_variables()
        self._define_variables()
        self._create_equations()
        self._formalize_vulnerability()
        self._record_template_metrics()
        return self.model

    def _inject_template_variables(self) -> None:
        assert self.template is not None
        for variable in self.template.variables.values():
            self.model.variables.setdefault(
                variable.name,
                SCMVariable(
                    name=variable.name,
                    var_type=variable.var_type,
                    domain=list(variable.domain),
                    identifier=variable.name,
                    role=variable.role,
                    description=variable.description,
                    origin="template",
                ),
            )
        if self.template.interventions:
            self.model.metadata["canonical_interventions"] = list(self.template.interventions)

    def _define_variables(self) -> None:
        for node in self.graph.nodes.values():
            var_name = self._variable_name_semantic(node)
            metadata = node.metadata or {}
            inferred = SCMVariable(
                name=var_name,
                var_type=metadata.get("datatype") or self._infer_type(node.node_type),
                domain=list(metadata.get("value_range") or []),
                identifier=metadata.get("identifier") or self._infer_identifier(node),
                role="endogenous",
                description=node.description or "",
                origin="pcg",
            )
            existing = self.model.variables.get(var_name)
            if existing:
                if not existing.identifier or existing.identifier == existing.name:
                    existing.identifier = inferred.identifier
                if not existing.domain and inferred.domain:
                    existing.domain = inferred.domain
                if not existing.description and inferred.description:
                    existing.description = inferred.description
                if not existing.role:
                    existing.role = inferred.role
                if not existing.origin:
                    existing.origin = inferred.origin
                continue
            self.model.variables[var_name] = inferred

    def _create_equations(self) -> None:
        if self.template:
            for template_eq in self.template.equations:
                self.model.equations.append(
                    StructuralEquation(
                        target=template_eq.target,
                        expression=template_eq.expression,
                        description=template_eq.description,
                    )
                )

        for node in self.graph.nodes.values():
            target = self._variable_name_semantic(node)
            parents = self.graph.predecessors(node.node_id)
            if not parents:
                expr = "exogenous"  # no parents, treat as external input
            else:
                parent_vars = [
                    self._variable_name_semantic(self.graph.nodes[pid])
                    for pid in parents
                ]
                expr = " AND ".join(parent_vars)
            description = (node.description or "").replace("\"", "'")
            equation = StructuralEquation(
                target=target,
                expression=f"{expr}  # {description}",
                description=description,
            )
            self.model.equations.append(equation)

    def _formalize_vulnerability(self) -> None:
        vuln_nodes = [
            n for n in self.graph.nodes.values() if n.node_type == "vulnerability"
        ]
        if not vuln_nodes:
            self.model.vulnerable_condition = "False"
            return
        vuln = vuln_nodes[0]
        parents = self.graph.predecessors(vuln.node_id)
        if not parents:
            condition = "True"
        else:
            condition = " AND ".join(
                self._variable_name_semantic(self.graph.nodes[pid])
                for pid in parents
            )
        if self.template and self.template.vulnerable_condition:
            self.model.metadata["graph_vulnerable_condition"] = condition
            self.model.vulnerable_condition = self.template.vulnerable_condition
        else:
            self.model.vulnerable_condition = condition

    @staticmethod
    def _variable_name(node_id: str) -> str:
        """Legacy variable naming: V_<node_id>"""
        return f"V_{node_id}"

    def _variable_name_semantic(self, node: Optional[PCGNode]) -> str:
        """Generate semantic variable name from node description"""
        if not node:
            return f"V_{node.node_id if hasattr(node, 'node_id') else 'unknown'}"
        if node.node_id in self.node_template_bindings:
            return self.node_template_bindings[node.node_id]

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
    def _infer_identifier(node: PCGNode) -> str:
        metadata = node.metadata or {}
        if metadata.get("identifier"):
            return metadata["identifier"]
        description = node.description or ""
        tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", description)
        if tokens:
            return tokens[0]
        return node.node_id

    def _bind_template_variables(self) -> None:
        if not self.template:
            return
        used_nodes: set[str] = set()
        for var_name, keywords in self.template.bindings.items():
            candidate = self._match_binding_candidate(
                (node for node in self.graph.nodes.values() if node.node_id not in used_nodes),
                keywords,
            )
            if not candidate:
                continue
            self.template_bindings[var_name] = candidate.node_id
            self.node_template_bindings[candidate.node_id] = var_name
            used_nodes.add(candidate.node_id)

    def _match_binding_candidate(
        self,
        nodes: Iterable[PCGNode],
        keywords: List[str],
    ) -> Optional[PCGNode]:
        best_score = 0
        best_node: Optional[PCGNode] = None
        lowered_keywords = [kw.lower() for kw in keywords]
        for node in nodes:
            desc = (node.description or "").lower()
            meta_blob = " ".join(
                str(value).lower()
                for value in (node.metadata or {}).values()
                if isinstance(value, str)
            )
            score = 0
            for keyword in lowered_keywords:
                if keyword in desc:
                    score += 2
                elif keyword in meta_blob:
                    score += 1
            if score > best_score:
                best_score = score
                best_node = node
        return best_node if best_score else None

    def _record_template_metrics(self) -> None:
        if not self.template:
            self.metrics = {
                "template_id": None,
                "cwe_id": self.cwe_id,
                "template_coverage": 0.0,
                "bindings": {},
            }
            return
        total_bindable = len(self.template.bindings)
        bound = len(self.template_bindings)
        coverage = bound / total_bindable if total_bindable else 1.0
        missing = sorted(
            set(self.template.bindings.keys()) - set(self.template_bindings.keys())
        )
        self.metrics = {
            "template_id": self.template.template_id,
            "cwe_id": self.cwe_id,
            "template_coverage": coverage,
            "bound_variables": sorted(self.template_bindings.keys()),
            "missing_variables": missing,
        }
        self.model.metadata["template_id"] = self.template.template_id
        self.model.metadata["template_bindings"] = dict(self.template_bindings)
        self.model.metadata["template_coverage"] = coverage
        self.model.metadata["cwe_id"] = self.cwe_id
        if missing:
            self.model.metadata["missing_template_variables"] = missing

    @staticmethod
    def _find_nodes_of_type(graph: ProgramCausalGraph, node_type: str) -> Iterable[str]:
        return (node_id for node_id, node in graph.nodes.items() if node.node_type == node_type)
