# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class STIArgument(Patch):
    """
    Patch   printSomeOperand(MI, NUM, STI, NUM)
    to      printSomeOperand(MI, NUM, NUM)
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return '(argument_list (_) (_) (_)? ((identifier) @id (#eq? @id "STI")) (_)) @sti_arg'

    def get_main_capture_name(self) -> str:
        return "sti_arg"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        param_list = list()
        for param in captures[0][0].named_children:
            p_text = get_text(src, param.start_byte, param.end_byte)
            if b"STI" in p_text:
                continue
            param_list.append(p_text)
        res = b"(" + b", ".join(param_list) + b")"
        return res
