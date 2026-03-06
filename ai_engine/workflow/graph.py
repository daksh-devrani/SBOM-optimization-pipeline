"""
LangGraph graph definition.

Wires the three agent nodes into a sequential pipeline:
    fix_node → summary_node → sbom_node

Each node reads from shared PipelineState and writes
its own output fields back into it.
"""

from langgraph.graph import StateGraph, START, END

from nodes.fix_node     import fix_node
from nodes.summary_node import summary_node
from nodes.sbom_node    import sbom_node
from schemas.pipeline_state import PipelineState


def build_graph():
    """
    Build and compile the LangGraph pipeline.

    Returns:
        A compiled LangGraph app ready to invoke with .invoke(state_dict)
    """

    # Initialise the graph with PipelineState as the shared state schema
    graph = StateGraph(PipelineState)

    # ── Register nodes ────────────────────────────────────────────────────────
    graph.add_node("fix_node",     fix_node)
    graph.add_node("summary_node", summary_node)
    graph.add_node("sbom_node",    sbom_node)

    # ── Define edges (execution order) ────────────────────────────────────────
    # START → fix_node → summary_node → sbom_node → END
    graph.add_edge(START,          "fix_node")
    graph.add_edge("fix_node",     "summary_node")
    graph.add_edge("summary_node", "sbom_node")
    graph.add_edge("sbom_node",    END)

    return graph.compile()