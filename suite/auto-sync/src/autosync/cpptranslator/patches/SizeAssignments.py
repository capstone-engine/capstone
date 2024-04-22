# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import re

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_function_params_of_node, get_text
from autosync.cpptranslator.patches.Patch import Patch


class SizeAssignment(Patch):
    """
    Patch   Size = <num>
    to      *Size = <num>

    if Size is a reference.
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(assignment_expression"
            '    ((identifier) @id (#eq? @id "Size"))'
            ") @assign"
        )

    def get_main_capture_name(self) -> str:
        return "assign"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        assign = captures[0][0]
        assign_text = get_text(src, assign.start_byte, assign.end_byte)

        param_list = get_function_params_of_node(assign)
        if not param_list:
            return assign_text

        for p in param_list.named_children:
            p_text = get_text(src, p.start_byte, p.end_byte)
            if b"&Size" in p_text:
                return re.sub(b"Size", b"*Size", assign_text)

        return assign_text
