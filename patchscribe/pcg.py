"""
Program Causal Graph primitives used throughout the PatchScribe PoC.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class PCGNode:
    """Minimal node representation capturing causal information."""

    node_id: str
    node_type: str
    description: str
    location: Optional[int] = None
    metadata: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.metadata.setdefault("causal_parents", [])
        self.metadata.setdefault("causal_children", [])


@dataclass
class PCGEdge:
    """Directed edge capturing causal dependency."""

    source: str
    target: str
    edge_type: str  # "control" | "data" | "symbolic"
    rationale: str


@dataclass
class ProgramCausalGraph:
    """Container aggregating nodes and edges for downstream modelling."""

    nodes: Dict[str, PCGNode] = field(default_factory=dict)
    edges: List[PCGEdge] = field(default_factory=list)

    def add_node(self, node: PCGNode) -> None:
        self.nodes[node.node_id] = node

    def add_edge(self, edge: PCGEdge) -> None:
        self.edges.append(edge)
        parent_list = self.nodes[edge.source].metadata.setdefault("causal_children", [])
        if edge.target not in parent_list:
            parent_list.append(edge.target)
        child_list = self.nodes[edge.target].metadata.setdefault("causal_parents", [])
        if edge.source not in child_list:
            child_list.append(edge.source)

    def predecessors(self, node_id: str) -> List[str]:
        return list(self.nodes[node_id].metadata.get("causal_parents", []))

    def successors(self, node_id: str) -> List[str]:
        return list(self.nodes[node_id].metadata.get("causal_children", []))

    def to_dict(self) -> Dict[str, object]:
        """Serialize the graph to a plain-Python structure."""
        return {
            "nodes": [
                {
                    "node_id": node.node_id,
                    "node_type": node.node_type,
                    "description": node.description,
                    "location": node.location,
                    "metadata": node.metadata,
                }
                for node in self.nodes.values()
            ],
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "edge_type": edge.edge_type,
                    "rationale": edge.rationale,
                }
                for edge in self.edges
            ],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "ProgramCausalGraph":
        """Reconstruct a graph from to_dict output."""
        graph = cls()
        for node_info in data.get("nodes", []):
            node = PCGNode(
                node_id=node_info.get("node_id") or node_info.get("id"),
                node_type=node_info.get("node_type") or node_info.get("type"),
                description=node_info.get("description", ""),
                location=node_info.get("location"),
                metadata=node_info.get("metadata") or {},
            )
            graph.add_node(node)
        for edge_info in data.get("edges", []):
            edge = PCGEdge(
                source=edge_info.get("source"),
                target=edge_info.get("target"),
                edge_type=edge_info.get("edge_type", "data"),
                rationale=edge_info.get("rationale", ""),
            )
            if edge.source in graph.nodes and edge.target in graph.nodes:
                graph.add_edge(edge)
        return graph


NodeIdSequence = Dict[str, int]


def next_node_id(seq: NodeIdSequence, prefix: str) -> str:
    seq[prefix] = seq.get(prefix, 0) + 1
    return f"{prefix}{seq[prefix]}"
