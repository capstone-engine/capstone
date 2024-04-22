# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_capture_node, get_text
from autosync.cpptranslator.patches.Patch import Patch


class DeclarationInConditionalClause(Patch):
    """
    Patch   if (DECLARATION) ...
    to      DECLARATION
            if (VAR) ...
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(if_statement"
            "   (condition_clause"
            "       (declaration"
            "           (_)"
            "           ((identifier) @id)"
            "           (_)"
            "       ) @decl"
            "   )"
            "   (_) @if_body"
            ") @condition_clause"
        )

    def get_main_capture_name(self) -> str:
        return "condition_clause"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        cond = get_capture_node(captures, "condition_clause")
        for nc in cond.named_children:
            if nc.type == "if_statement":
                # Skip if statements with else if
                return get_text(src, cond.start_byte, cond.end_byte)
        declaration = get_capture_node(captures, "decl")
        identifier = get_capture_node(captures, "id")
        if_body = get_capture_node(captures, "if_body")
        identifier = get_text(src, identifier.start_byte, identifier.end_byte)
        declaration = get_text(src, declaration.start_byte, declaration.end_byte)
        if_body = get_text(src, if_body.start_byte, if_body.end_byte)
        res = declaration + b";\nif (" + identifier + b")\n" + if_body
        return res
