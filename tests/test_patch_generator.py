import textwrap
from types import SimpleNamespace

from patchscribe.intervention import Intervention, InterventionSpec
from patchscribe.patch import PatchGenerator
from patchscribe.pcg import PCGNode, ProgramCausalGraph
from patchscribe.llm import LLMUnavailable


class DummyLLM:
    """LLM stub that always fails, forcing heuristic fallbacks."""

    def __init__(self) -> None:
        self.config = SimpleNamespace(endpoint="mock://noop", model="mock")

    def generate_patch(self, *args, **kwargs):
        raise LLMUnavailable("disabled for tests")


def _graph_with_node(node_id: str, description: str, location: int) -> ProgramCausalGraph:
    graph = ProgramCausalGraph()
    graph.add_node(
        PCGNode(
            node_id=node_id,
            node_type="predicate",
            description=description,
            location=location,
        )
    )
    return graph


def test_patch_generator_guard_fallback_inserts_guard():
    program = textwrap.dedent(
        """
        int foo(char *input) {
            char buf[8];
            strcpy(buf, input);
            return 0;
        }
        """
    ).strip()
    graph = _graph_with_node("p1", "input == NULL", 3)
    spec = InterventionSpec(
        interventions=[
            Intervention(
                target_line=3,
                enforce="ENFORCE NOT V_p1",
                rationale="Prevent null dereference",
            )
        ]
    )
    generator = PatchGenerator(
        graph,
        program,
        vuln_line=3,
        signature="strcpy(buf, input)",
        llm_client=DummyLLM(),
    )

    patch = generator.generate(spec)

    assert patch.method == "heuristic_guard"
    assert "return -1" in patch.patched_code
    assert "if (" in patch.patched_code.splitlines()[2]


def test_patch_generator_known_mitigation_handles_common_apis():
    program = textwrap.dedent(
        """
        #include <stdio.h>
        int main(void) {
            char buf[32];
            gets(buf);
            return puts(buf);
        }
        """
    ).strip()
    graph = _graph_with_node("p1", "gets(buf)", 4)
    generator = PatchGenerator(
        graph,
        program,
        vuln_line=4,
        signature="gets(buf)",
        llm_client=DummyLLM(),
    )

    patch = generator.generate(InterventionSpec())

    assert patch.method == "heuristic_transform"
    assert "fgets" in patch.patched_code
