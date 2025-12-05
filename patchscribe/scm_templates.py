"""
Loader for Structural Causal Model (SCM) templates referenced in the paper.

The appendix of `doc/paper/patchscribe.tex` enumerates canonical templates for
major CWE families. This module exposes those templates as structured Python
objects so `SCMBuilder` can instantiate them during Phase-1 formalization.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Dict, Iterable, List, Optional, Sequence

from .data import PACKAGE_NAME, SCM_TEMPLATE_FILENAME


@dataclass
class TemplateVariable:
    """Definition of a template variable."""

    name: str
    var_type: str
    role: str
    description: str
    domain: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "TemplateVariable":
        return cls(
            name=data.get("name", ""),
            var_type=data.get("var_type", "unknown"),
            role=data.get("role", "endogenous"),
            description=data.get("description", ""),
            domain=list(data.get("domain", [])),
        )


@dataclass
class TemplateEquation:
    """Canonical structural equation from a template."""

    target: str
    expression: str
    description: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "TemplateEquation":
        return cls(
            target=data.get("target", ""),
            expression=data.get("expression", ""),
            description=data.get("description", ""),
        )


@dataclass
class SCMTemplate:
    """Fully parsed SCM template."""

    template_id: str
    cwes: List[str]
    description: str
    variables: Dict[str, TemplateVariable]
    equations: List[TemplateEquation]
    vulnerable_condition: str
    bindings: Dict[str, List[str]]
    interventions: List[Dict[str, str]]

    @classmethod
    def from_payload(cls, template_id: str, payload: Dict[str, object]) -> "SCMTemplate":
        variables = {
            item["name"]: TemplateVariable.from_dict(item)
            for item in payload.get("variables", [])
            if isinstance(item, dict) and item.get("name")
        }
        equations = [
            TemplateEquation.from_dict(item)
            for item in payload.get("equations", [])
            if isinstance(item, dict)
        ]
        bindings = {
            name: [keyword.lower() for keyword in keywords]
            for name, keywords in (payload.get("bindings") or {}).items()
        }
        interventions = [
            item
            for item in payload.get("interventions", [])
            if isinstance(item, dict)
        ]
        cwes = [cwe.upper() for cwe in payload.get("cwes", [])]
        return cls(
            template_id=template_id,
            cwes=cwes,
            description=payload.get("description", ""),
            variables=variables,
            equations=equations,
            vulnerable_condition=payload.get("vulnerable_condition", ""),
            bindings=bindings,
            interventions=interventions,
        )

    def keywords_for(self, variable_name: str) -> List[str]:
        return list(self.bindings.get(variable_name, []))


class SCMTemplateCatalog:
    """Registry of SCM templates keyed by CWE identifier."""

    def __init__(self, templates: Sequence[SCMTemplate]) -> None:
        self.templates = list(templates)
        self._index: Dict[str, SCMTemplate] = {}
        for template in self.templates:
            for cwe in template.cwes:
                self._index.setdefault(cwe.upper(), template)

    def match(self, cwe_id: Optional[str]) -> Optional[SCMTemplate]:
        if not cwe_id:
            return None
        normalized = cwe_id.upper().strip()
        if ":" in normalized:
            normalized = normalized.split(":", 1)[0]
        return self._index.get(normalized)

    def describe(self) -> Dict[str, object]:
        return {
            template.template_id: {
                "cwes": template.cwes,
                "description": template.description,
                "variables": list(template.variables.keys()),
                "equation_count": len(template.equations),
            }
            for template in self.templates
        }

    @classmethod
    @lru_cache(maxsize=1)
    def load_default(cls) -> "SCMTemplateCatalog":
        """Load the packaged templates from disk exactly once."""
        with resources.as_file(
            resources.files(PACKAGE_NAME).joinpath(SCM_TEMPLATE_FILENAME)
        ) as path:
            payload = json.loads(path.read_text(encoding="utf-8"))
        templates = [
            SCMTemplate.from_payload(template_id, data)
            for template_id, data in payload.items()
        ]
        return cls(templates)


def list_supported_cwes() -> List[str]:
    """Helper for debugging and documentation."""
    catalog = SCMTemplateCatalog.load_default()
    seen: List[str] = []
    for template in catalog.templates:
        seen.extend(template.cwes)
    return sorted(set(seen))
