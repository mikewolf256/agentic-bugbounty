#!/usr/bin/env python3
"""Graph Visualizer

Generates attack graph visualizations in multiple formats.
"""

from typing import Dict, Any, List


def generate_mermaid_graph(graph: Dict[str, Any]) -> str:
    """Generate Mermaid diagram
    
    Args:
        graph: Attack graph
        
    Returns:
        Mermaid diagram string
    """
    mermaid = "graph TD\n"
    
    # Add nodes
    for node in graph.get("nodes", []):
        node_id = node.get("id", "")
        finding = node.get("finding", {})
        name = finding.get("name", node_id)
        mermaid += f'    {node_id}["{name}"]\n'
    
    # Add edges
    for edge in graph.get("edges", []):
        from_node = edge.get("from", "")
        to_node = edge.get("to", "")
        mermaid += f"    {from_node} --> {to_node}\n"
    
    return mermaid


def generate_dot_graph(graph: Dict[str, Any]) -> str:
    """Generate DOT graph
    
    Args:
        graph: Attack graph
        
    Returns:
        DOT graph string
    """
    dot = "digraph AttackGraph {\n"
    
    # Add nodes
    for node in graph.get("nodes", []):
        node_id = node.get("id", "")
        finding = node.get("finding", {})
        name = finding.get("name", node_id)
        dot += f'    {node_id} [label="{name}"];\n'
    
    # Add edges
    for edge in graph.get("edges", []):
        from_node = edge.get("from", "")
        to_node = edge.get("to", "")
        dot += f"    {from_node} -> {to_node};\n"
    
    dot += "}\n"
    return dot


def visualize_graph(graph: Dict[str, Any], format: str = "mermaid") -> str:
    """Generate graph visualization
    
    Args:
        graph: Attack graph
        format: Output format (mermaid, dot, html)
        
    Returns:
        Visualization string
    """
    if format == "mermaid":
        return generate_mermaid_graph(graph)
    elif format == "dot":
        return generate_dot_graph(graph)
    else:
        return generate_mermaid_graph(graph)

