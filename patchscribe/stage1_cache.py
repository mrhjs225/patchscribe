"""
Utilities for caching Stage-1 (pre-LLM) artifacts so later runs can skip the
expensive static/dynamic analyses and formalization steps.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from .formal_spec import FormalBugExplanation
from .intervention import InterventionSpec
from .pcg import ProgramCausalGraph
from .scm import StructuralCausalModel


@dataclass
class Stage1Data:
    pcg: ProgramCausalGraph
    diagnostics: Dict[str, object]
    scm: StructuralCausalModel
    intervention: InterventionSpec
    e_bug: FormalBugExplanation

    def to_serializable(self) -> Dict[str, object]:
        return {
            "pcg": {
                "graph": self.pcg.to_dict(),
                "diagnostics": self.diagnostics,
            },
            "scm": self.scm.as_dict(),
            "intervention": self.intervention.to_dict(),
            "E_bug": self.e_bug.as_dict(),
        }


class Stage1Cache:
    def __init__(self, base_dir: str | Path | None = None) -> None:
        self.base_dir = Path(base_dir) if base_dir else None
        if self.base_dir:
            self.base_dir.mkdir(parents=True, exist_ok=True)

    def enabled(self) -> bool:
        return self.base_dir is not None

    def _path_for(self, case_id: str) -> Path:
        assert self.base_dir is not None
        safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", case_id or "unknown")
        return self.base_dir / f"{safe_id}.json"

    def load(self, case_id: str, source_sha: str) -> Optional[Stage1Data]:
        if not self.enabled():
            return None
        path = self._path_for(case_id)
        if not path.exists():
            return None
        try:
            with path.open("r", encoding="utf-8") as fp:
                payload = json.load(fp)
        except (OSError, json.JSONDecodeError):
            return None
        if payload.get("source_sha") != source_sha:
            return None
        return self._deserialize(payload)

    def store(
        self,
        case_id: str,
        source_sha: str,
        data: Stage1Data,
        *,
        metadata: Optional[Dict[str, object]] = None,
    ) -> None:
        if not self.enabled():
            return
        path = self._path_for(case_id)
        serializable = data.to_serializable()
        serializable.update(
            {
                "case_id": case_id,
                "source_sha": source_sha,
                "metadata": metadata or {},
                "cached_at": datetime.utcnow().isoformat() + "Z",
            }
        )
        with path.open("w", encoding="utf-8") as fp:
            json.dump(serializable, fp, indent=2)

    @staticmethod
    def _deserialize(payload: Dict[str, object]) -> Optional[Stage1Data]:
        pcg_section = payload.get("pcg") or {}
        graph_payload = pcg_section.get("graph") or {
            "nodes": pcg_section.get("nodes", []),
            "edges": pcg_section.get("edges", []),
        }
        try:
            graph = ProgramCausalGraph.from_dict(graph_payload)
            diagnostics = pcg_section.get("diagnostics") or payload.get("diagnostics", {})
            scm = StructuralCausalModel.from_dict(payload.get("scm") or {})
            intervention = InterventionSpec.from_dict(payload.get("intervention") or {})
            e_bug = FormalBugExplanation.from_dict(payload.get("E_bug") or {})
        except Exception:
            return None
        return Stage1Data(
            pcg=graph,
            diagnostics=diagnostics,
            scm=scm,
            intervention=intervention,
            e_bug=e_bug,
        )
