# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text, get_text_from_node
from autosync.cpptranslator.patches.Patch import Patch


class StreamOperations(Patch):
    """
    Patch   OS << ...
    to      SStream_concat(OS, ...)
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(expression_statement"
            "   (binary_expression"
            "       ((binary_expression)"
            '       "<<"'
            "       (_))*"
            "   ) @bin_expr"
            ") @stream"
        )

    def get_main_capture_name(self) -> str:
        return "stream"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        bin_expr = captures[1][0]
        # Extract operands passed to the stream into a list.
        ops = list()
        while bin_expr.type == "binary_expression":
            ops.append(bin_expr.named_children[1])
            bin_expr = bin_expr.named_children[0]
        s_name = get_text(src, bin_expr.start_byte, bin_expr.end_byte)
        # We added the operands from right to left.
        # We reversing it so the left most operand comes first.
        ops.reverse()

        res = b""
        # Capstone uses the following functions to copy the strings to a buffer:
        # SStream_concat  - Copies multiple strings.
        # SStream_concat1 - Copies a char.
        # SStream_concat0 - Copies a string and null terminates the buffer.
        last_op: Node = ops[-1]
        op: Node = ops[0]
        string_ops = list()
        i = 0
        while op != last_op:
            if op.type == "char_literal":
                if len(string_ops) != 0:
                    # Make a SStream_concat call with all string literals collected before.
                    res += (
                        b"SStream_concat("
                        + s_name
                        + b', "'
                        + b"%s" * len(string_ops)
                        + b'", '
                        + b", ".join(
                            [
                                get_text(src, o.start_byte, o.end_byte)
                                for o in string_ops
                            ]
                        )
                        + b");\n"
                    )
                    string_ops.clear()
                res += (
                    b"SStream_concat1("
                    + s_name
                    + b", "
                    + get_text(src, op.start_byte, op.end_byte)
                    + b");\n"
                )
            else:
                string_ops.append(op)
            i += 1
            op = ops[i]

        if len(string_ops) != 0:
            res += (
                b"SStream_concat("
                + s_name
                + b', "'
                + b"%s" * len(string_ops)
                + b'", '
                + b", ".join(
                    [get_text(src, o.start_byte, o.end_byte) for o in string_ops]
                )
                + b");\n"
            )
            string_ops.clear()

        last_op_text = get_text(src, last_op.start_byte, last_op.end_byte)
        if last_op.type == "char_literal":
            res += (
                b"SStream_concat0("
                + s_name
                + b", "
                + last_op_text.replace(b"'", b'"')
                + b");\n"
            )
        elif last_op.type == "identifier":
            queue_str = f"""
                (declaration (
                    (primitive_type) @typ
                    (init_declarator 
                        (identifier) @ident (#eq? @ident "{last_op_text.decode("utf8")}")
                    )
                )) @decl
"""
            query = kwargs["ts_cpp_lang"].query(queue_str)
            root_node = kwargs["tree"].root_node
            query_result = list(
                filter(
                    lambda x: "typ" in x[1],
                    query.matches(root_node),
                )
            )
            if len(query_result) == 0:
                res += b"SStream_concat0(" + s_name + b", " + last_op_text + b");"
            else:
                typ = get_text_from_node(src, query_result[0][1]["typ"][-1])
                match typ:
                    case b"int":
                        res += b"printInt32(" + s_name + b", " + last_op_text + b");"
                    case b"int64_t":
                        res += b"printInt64(" + s_name + b", " + last_op_text + b");"
                    case _:
                        res += (
                            b"SStream_concat0(" + s_name + b", " + last_op_text + b");"
                        )
        else:
            res += b"SStream_concat0(" + s_name + b", " + last_op_text + b");"
        stream = captures[0][0]
        if len(ops) > 1 and stream.parent.type in ["if_statement"]:
            # If statements without {} brackets might execute a single line `OS << ...;` statement.
            # Which we then translate into multiple lines. For this case we need to add the brackets.
            res = b"{ " + res + b" }"
        return res
