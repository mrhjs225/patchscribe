import textwrap

from patchscribe.formal_spec import CausalPath, FormalBugExplanation, VariableSpec
from patchscribe.intervention import InterventionSpec
from patchscribe.patch import PatchResult
from patchscribe.pipeline import PatchScribePipeline
from patchscribe.pcg import PCGNode, ProgramCausalGraph
from patchscribe.scm import StructuralCausalModel
from patchscribe.stage1_cache import Stage1Data


def test_ground_truth_builder_merges_metadata_and_reference_patch():
    pipeline = PatchScribePipeline(enable_consistency_check=False)

    graph = ProgramCausalGraph()
    graph.add_node(
        PCGNode(
            node_id="n1",
            node_type="predicate",
            description="len(input) > 32",
            location=5,
        )
    )
    scm = StructuralCausalModel(vulnerable_condition="bounds_check_n1")
    e_bug = FormalBugExplanation(
        formal_condition="V_bug ⟺ bounds_check_n1",
        variables={
            "n1": VariableSpec(
                name="n1",
                var_type="bool",
                meaning="length compare",
                code_location="line 5",
            )
        },
        description="missing bounds check",
        manifestation="overflow",
        vulnerable_location="line 5",
        causal_paths=[CausalPath(path_id="cp1", nodes=["n1"], description="missing bounds check")],
        safety_property="",
        intervention_options=[],
    )
    stage1 = Stage1Data(
        pcg=graph,
        diagnostics={},
        scm=scm,
        intervention=InterventionSpec(),
        e_bug=e_bug,
    )

    reference_patch = textwrap.dedent(
        """
        void foo(char *input) {
            char buf[32];
            if (strlen(input) >= sizeof(buf)) {
                return;
            }
            strcpy(buf, input);
        }
        """
    ).strip()
    patch = PatchResult(
        patched_code=reference_patch,
        diff="",
        applied_guards=[],
        method="heuristic_transform",
    )
    effect = {"vulnerability_removed": True}
    vuln_case = {
        "id": "case-1",
        "cwe_id": "CWE-120",
        "vuln_line": 5,
        "ground_truth": reference_patch,
    }

    context = pipeline._build_consistency_ground_truth(
        vuln_case=vuln_case,
        stage1=stage1,
        patch=patch,
        effect=effect,
    )

    assert context is not None
    assert context["vulnerability_location"].endswith("line 5")
    assert context["vulnerability_type"] == "CWE-120"
    assert context["vulnerability_removed"] is True
    assert context["expected_causes"] == ["missing bounds check"]
    assert "reference_patch_similarity" in context
    assert context["patch_correct"] is True
    assert context["has_side_effects"] is False
