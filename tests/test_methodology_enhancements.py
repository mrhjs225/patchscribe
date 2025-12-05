from __future__ import annotations

import pytest

from patchscribe.analysis.absence_analysis import AbsenceAnalyzer
from patchscribe.effect_model import PatchEffectAnalyzer
from patchscribe.formal_spec import FormalBugExplanation
from patchscribe.intervention import InterventionSpec
from patchscribe.pcg import PCGEdge, PCGNode, ProgramCausalGraph
from patchscribe.pcg_builder import PCGBuilderConfig
from patchscribe.scm import SCMBuilder, StructuralCausalModel
from patchscribe.stage1_cache import Stage1Data


def test_absence_analyzer_reports_metrics():
    vulnerable_code = """
    void copy(char *input) {
        char buf[8];
        strcpy(buf, input);
    }
    """.strip()
    analyzer = AbsenceAnalyzer(
        vulnerable_code,
        vuln_line=3,
        expected_patterns=["missing_bounds_check_copy"],
    )
    result = analyzer.run()
    assert any(f.pattern == "missing_bounds_check_copy" for f in result.findings)
    metrics = result.metrics
    assert metrics["true_positive"] == 1
    assert metrics["false_positive"] >= 0
    assert metrics["recall"] == pytest.approx(1.0)


def test_scm_builder_binds_template_variables():
    graph = ProgramCausalGraph()
    graph.add_node(
        PCGNode(
            node_id="p1",
            node_type="predicate",
            description="if (idx < len)",
            location=5,
        )
    )
    graph.add_node(
        PCGNode(
            node_id="v1",
            node_type="vulnerability",
            description="strcpy(buf, input)",
            location=6,
        )
    )
    graph.add_edge(
        PCGEdge(
            source="p1",
            target="v1",
            edge_type="control_flow",
            rationale="guard controls copy",
        )
    )
    builder = SCMBuilder(graph, cwe_id="CWE-787")
    model = builder.derive()

    assert builder.metrics["template_id"] == "oob_memory"
    assert builder.metrics["template_coverage"] > 0
    bindings = model.metadata.get("template_bindings")
    assert bindings and bindings["C_bounds_check"] == "p1"
    assert "C_bounds_check" in model.variables


def test_patch_effect_analyzer_detects_guard_resolution():
    baseline_stage1 = Stage1Data(
        pcg=ProgramCausalGraph(),
        diagnostics={},
        scm=StructuralCausalModel(vulnerable_condition="C_bounds_check"),
        intervention=InterventionSpec(),
        e_bug=FormalBugExplanation(
            formal_condition="V_bug",
            variables={},
            description="",
            manifestation="",
            vulnerable_location="line 3",
            causal_paths=[],
            safety_property="",
            intervention_options=[],
        ),
        analysis_stats={
            "absence_findings": [{"pattern": "missing_bounds_check_copy"}],
        },
    )
    patched_code = """
    #include <string.h>
    int handle(char *input) {
        char buf[8];
        size_t len = strlen(input);
        if (len >= sizeof(buf)) {
            return -1;
        }
        strcpy(buf, input);
        return 0;
    }
    """.strip()
    config = PCGBuilderConfig(
        use_llvm_slicing=False,
        strict_dependencies=False,
        require_precise_static=False,
    )
    analyzer = PatchEffectAnalyzer(config)
    effect = analyzer.analyze(
        original_condition="missing_bounds_check_copy",
        patched_code=patched_code,
        signature="strcpy(buf, input)",
        baseline_stage1=baseline_stage1,
        vuln_info={"location": 6, "cwe_id": "CWE-787"},
    )
    assert effect.vulnerability_removed
    assert effect.diagnostics["remaining_missing_guards"] == {}
    assert effect.diagnostics["absence_resolution_rate"] == pytest.approx(1.0)
