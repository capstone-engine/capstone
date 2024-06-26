# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class DecodeInstruction(Patch):
    """
    Patch   decodeInstruction(..., this, STI)
    to      decodeInstruction_<instr_width>(..., NULL)

    It also removes the arguments `this, STI`.
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(call_expression ("
            '   (identifier) @fcn_name (#eq? @fcn_name "decodeInstruction")'
            "   ((argument_list) @arg_list)"
            ")) @decode_instr"
        )

    def get_main_capture_name(self) -> str:
        return "decode_instr"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        arg_list = captures[2][0]
        args_text = get_text(src, arg_list.start_byte, arg_list.end_byte).strip(b"()")

        table, mi_inst, opcode_var, address, this, sti = args_text.split(b",")
        is_32bit = (
            table[-2:].decode("utf8") == "32" or opcode_var[-2:].decode("utf8") == "32"
        )
        is_16bit = (
            table[-2:].decode("utf8") == "16" or opcode_var[-2:].decode("utf8") == "16"
        )
        args = (
            table + b", " + mi_inst + b", " + opcode_var + b", " + address + b",  NULL"
        )

        if is_16bit and not is_32bit:
            return b"decodeInstruction_2(" + args + b")"
        elif is_32bit and not is_16bit:
            return b"decodeInstruction_4(" + args + b")"
        else:
            # Cannot determine instruction width easily. Only update the calls arguments.
            return b"decodeInstruction(" + args + b")"
