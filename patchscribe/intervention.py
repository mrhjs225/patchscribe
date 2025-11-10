"""
Simplified intervention planning that targets vulnerable causal conditions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations, product
from typing import Dict, Iterable, List, Set

from .pcg import ProgramCausalGraph
from .scm import StructuralCausalModel

try:  # pragma: no cover - optional solver
    from z3 import And as z3And
    from z3 import Bool, BoolVal, Not as z3Not, Or as z3Or, Solver, unsat
except Exception:  # pragma: no cover - absence of z3
    Bool = None


@dataclass
class Intervention:
    target_line: int
    enforce: str
    rationale: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "target_line": self.target_line,
            "enforce": self.enforce,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "Intervention":
        return cls(
            target_line=int(data.get("target_line", -1)),
            enforce=data.get("enforce", ""),
            rationale=data.get("rationale", ""),
        )


@dataclass
class InterventionSpec:
    interventions: List[Intervention] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "summary": self.summary,
            "interventions": [item.to_dict() for item in self.interventions],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "InterventionSpec":
        interventions = [
            Intervention.from_dict(item)
            for item in data.get("interventions", [])
            if isinstance(item, dict)
        ]
        return cls(interventions=interventions, summary=data.get("summary", ""))


class InterventionPlanner:
    def __init__(self, graph: ProgramCausalGraph, model: StructuralCausalModel) -> None:
        self.graph = graph
        self.model = model

    def compute(self) -> InterventionSpec:
        vuln_node = self._find_vulnerability_node()
        if not vuln_node:
            return InterventionSpec(summary="No vulnerability node present")
        condition = self.model.vulnerable_condition or "True"
        blockers = self._minimal_blockers(condition)
        if not blockers:
            return InterventionSpec(summary="No causal blockers identified")
        interventions: List[Intervention] = []
        for blocker in blockers:
            for variable in sorted(blocker):
                node_id = self._node_from_variable(variable)
                if node_id not in self.graph.nodes:
                    continue
                parent = self.graph.nodes[node_id]
                enforce = f"ENFORCE NOT {variable}"
                rationale = f"Prevent {parent.description} from triggering vulnerability"
                interventions.append(
                    Intervention(
                        target_line=parent.location or -1,
                        enforce=enforce,
                        rationale=rationale,
                    )
                )
        interventions = _deduplicate_interventions(interventions)
        summary = "SMT-derived minimal interventions to break causal chain"
        return InterventionSpec(interventions=interventions, summary=summary)

    def _find_vulnerability_node(self):
        for node in self.graph.nodes.values():
            if node.node_type == "vulnerability":
                return node
        return None

    def _minimal_blockers(self, expression: str) -> List[Set[str]]:
        ast = _parse_expression(expression)
        blockers: List[Set[str]] = []
        if Bool is not None:
            blockers = _compute_blockers_with_z3(ast)
        if not blockers:
            blockers = _compute_blockers(ast)
        return _prune_supersets(blockers)

    @staticmethod
    def _node_from_variable(variable: str) -> str:
        return variable[2:] if variable.startswith("V_") else variable


class _Expr:
    pass


class _Var(_Expr):
    def __init__(self, name: str) -> None:
        self.name = name


class _Not(_Expr):
    def __init__(self, operand: _Expr) -> None:
        self.operand = operand


class _And(_Expr):
    def __init__(self, terms: List[_Expr]) -> None:
        self.terms = terms


class _Or(_Expr):
    def __init__(self, terms: List[_Expr]) -> None:
        self.terms = terms


def _tokenize(expr: str) -> List[str]:
    spaced = expr.replace("(", " ( ").replace(")", " ) ")
    return spaced.split()


def _parse_expression(expr: str) -> _Expr:
    tokens = _tokenize(expr)
    if not tokens:
        return _Var("True")
    position = 0

    def parse_or() -> _Expr:
        nonlocal position
        node = parse_and()
        terms = [node]
        while position < len(tokens) and tokens[position] == "OR":
            position += 1
            terms.append(parse_and())
        if len(terms) == 1:
            return terms[0]
        return _Or(terms)

    def parse_and() -> _Expr:
        nonlocal position
        node = parse_not()
        terms = [node]
        while position < len(tokens) and tokens[position] == "AND":
            position += 1
            terms.append(parse_not())
        if len(terms) == 1:
            return terms[0]
        return _And(terms)

    def parse_not() -> _Expr:
        nonlocal position
        if position < len(tokens) and tokens[position] == "NOT":
            position += 1
            return _Not(parse_not())
        return parse_primary()

    def parse_primary() -> _Expr:
        nonlocal position
        if position >= len(tokens):
            return _Var("True")
        token = tokens[position]
        position += 1
        if token == "(":
            node = parse_or()
            if position < len(tokens) and tokens[position] == ")":
                position += 1
            return node
        if token in {"True", "False"}:
            return _Var(token)
        return _Var(token)

    return parse_or()


def _compute_blockers(expr: _Expr) -> List[Set[str]]:
    if isinstance(expr, _Var):
        if expr.name == "True":
            return [set()]
        if expr.name == "False":
            return []
        return [{expr.name}]
    if isinstance(expr, _Not):
        # To make NOT A false, A must be true. We approximate by returning empty set to
        # signal no intervention handles this in the current PoC.
        return []
    if isinstance(expr, _And):
        blockers: List[Set[str]] = []
        for term in expr.terms:
            blockers.extend(_compute_blockers(term))
        return blockers
    if isinstance(expr, _Or):
        term_blockers = [_compute_blockers(term) for term in expr.terms]
        if not all(term_blockers):
            return []
        blockers: List[Set[str]] = []
        for combination in product(*term_blockers):
            merged: Set[str] = set().union(*combination)
            blockers.append(merged)
        return blockers
    return []


def _prune_supersets(sets: Iterable[Set[str]]) -> List[Set[str]]:
    minimal: List[Set[str]] = []
    for candidate in sets:
        if not candidate:
            continue
        if any(existing <= candidate for existing in minimal):
            continue
        minimal = [existing for existing in minimal if not candidate <= existing]
        minimal.append(candidate)
    return minimal


def _deduplicate_interventions(interventions: Iterable[Intervention]) -> List[Intervention]:
    seen = set()
    unique: List[Intervention] = []
    for intervention in interventions:
        key = (intervention.target_line, intervention.enforce)
        if key in seen:
            continue
        seen.add(key)
        unique.append(intervention)
    return unique


def refine_intervention(spec: InterventionSpec, feedback: str) -> InterventionSpec:
    if not feedback:
        return spec
    interventions = list(spec.interventions)
    if "guard" in feedback.lower():
        interventions.append(
            Intervention(target_line=-1, enforce="INSERT GUARD", rationale="Auto-added from feedback")
        )
    elif "signature" in feedback.lower():
        interventions.append(
            Intervention(
                target_line=-1,
                enforce="ENSURE SIGNATURE PRESERVED",
                rationale="Add check to preserve original signature",
            )
        )
    return InterventionSpec(interventions=_deduplicate_interventions(interventions), summary=spec.summary)


def _compute_blockers_with_z3(expr: _Expr) -> List[Set[str]]:
    if Bool is None:
        return []
    variables = sorted(_collect_variables(expr))
    if not variables:
        return []
    var_symbols = {name: Bool(name) for name in variables}
    formula = _to_z3(expr, var_symbols)
    base_solver = Solver()
    base_solver.add(formula)
    if base_solver.check() == unsat:
        return [set()]
    minimal: List[Set[str]] = []
    for size in range(1, len(variables) + 1):
        for subset in combinations(variables, size):
            solver = Solver()
            solver.add(formula)
            for name in subset:
                solver.add(var_symbols[name] == BoolVal(False))
            if solver.check() == unsat:
                minimal.append(set(subset))
        if minimal:
            break
    return minimal


def _collect_variables(expr: _Expr) -> Set[str]:
    if isinstance(expr, _Var):
        if expr.name in {"True", "False"}:
            return set()
        return {expr.name}
    if isinstance(expr, _Not):
        return _collect_variables(expr.operand)
    if isinstance(expr, (_And, _Or)):
        variables: Set[str] = set()
        for term in expr.terms:
            variables.update(_collect_variables(term))
        return variables
    return set()


def _to_z3(expr: _Expr, symbols: Dict[str, object]):
    if isinstance(expr, _Var):
        if expr.name == "True":
            return BoolVal(True)
        if expr.name == "False":
            return BoolVal(False)
        return symbols[expr.name]
    if isinstance(expr, _Not):
        return z3Not(_to_z3(expr.operand, symbols))
    if isinstance(expr, _And):
        return z3And(*[_to_z3(term, symbols) for term in expr.terms])
    if isinstance(expr, _Or):
        return z3Or(*[_to_z3(term, symbols) for term in expr.terms])
    return BoolVal(True)
