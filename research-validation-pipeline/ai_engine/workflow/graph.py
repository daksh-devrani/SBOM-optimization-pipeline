from pathlib import Path
from nodes.validation_node import validation_node

graph = Graph()

# Existing nodes
graph.add_node("fix_node", fix_node)
graph.add_node("summary_node", summary_node)
graph.add_node("sbom_node", sbom_node)

# New validation node
graph.add_node("validation_node", validation_node)
graph.add_edge("sbom_node", "validation_node")
graph.add_edge("validation_node", END)

# Original edge removed
# graph.add_edge("sbom_node", END)