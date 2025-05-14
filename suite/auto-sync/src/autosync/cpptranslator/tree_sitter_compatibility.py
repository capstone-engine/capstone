from tree_sitter import Node, Query

# Queries for the given pattern and converts the query back to the tree-siter v22.3 format.
# Which is: A list of tuples where the first element is the
# Node of the capture and the second one is the name.
def query_captures_22_3(query: Query, node: Node) -> list[tuple[Node, str]]:
    result = list()
    captures = query.captures(node)
    while len(captures) != 0:
        for name, nodes in captures.items():
            node = nodes.pop(0)
            result.append((node, name))
        captures = {k: l for k, l in captures.items() if len(l) != 0}
    return result
