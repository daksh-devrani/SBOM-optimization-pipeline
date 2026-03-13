"""
graph_state package.
State initialization lives here — loads scanner outputs,
parses them, and builds the initial PipelineState
before the graph runs.
"""

from .initializer import build_initial_state

__all__ = ["build_initial_state"]