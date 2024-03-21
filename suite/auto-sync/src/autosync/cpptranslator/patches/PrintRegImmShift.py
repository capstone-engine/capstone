# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_MCInst_var_name, get_text
from autosync.cpptranslator.patches.Patch import Patch


class PrintRegImmShift(Patch):
    """
    Patch   printRegImmShift(...)
    to      printRegImmShift(MI, ...)
    """

    def __init__(self, priority: int):
        super().__init__(priority)
        self.apply_only_to = {"files": ["ARMInstPrinter.cpp"], "archs": list()}

    def get_search_pattern(self) -> str:
        return (
            "(call_expression ("
            '   (identifier) @fcn_name (#eq? @fcn_name "printRegImmShift")'
            "   ((argument_list) @arg_list)"
            ")) @print_call"
        )

    def get_main_capture_name(self) -> str:
        return "print_call"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        call: Node = captures[0][0]
        mcinst_var = get_MCInst_var_name(src, call)
        params = captures[2][0]
        params = get_text(src, params.start_byte, params.end_byte)
        return b"printRegImmShift(" + mcinst_var + b", " + params.strip(b"(")
