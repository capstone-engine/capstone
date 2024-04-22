# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import logging as log
import re

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_function_params_of_node, get_text
from autosync.cpptranslator.patches.Patch import Patch


class FieldFromInstr(Patch):
    """
    Patch   fieldFromInstruction(...)
    to      fieldFromInstruction_<instr_width>(...)
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        # Search for fieldFromInstruction() calls.
        return (
            "(call_expression"
            '   ((identifier) @fcn_name (#eq? @fcn_name "fieldFromInstruction"))'
            "   (argument_list ((identifier) @first_arg) (_) (_))"
            ") @field_from_instr"
        )

    def get_main_capture_name(self) -> str:
        return "field_from_instr"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        ffi_call: Node = captures[0][0]
        ffi_first_arg: Node = captures[2][0]
        param_list_caller = get_function_params_of_node(ffi_call)
        ffi_first_arg_text = get_text(
            src, ffi_first_arg.start_byte, ffi_first_arg.end_byte
        ).decode("utf8")

        # Determine width of instruction by the variable name.
        if ffi_first_arg_text[-2:] == "32":
            inst_width = 4
        elif ffi_first_arg_text[-2:] == "16":
            inst_width = 2
        else:
            # Get the Val/Inst parameter.
            # Its type determines the instruction width.
            inst_param: Node = param_list_caller.named_children[1]
            inst_param_text = get_text(src, inst_param.start_byte, inst_param.end_byte)

            # Search for the 'Inst' parameter and determine its type
            # and with it the width of the instruction.
            inst_type = inst_param_text.split(b" ")[0]
            if inst_type:
                if inst_type in [b"unsigned", b"uint32_t"]:
                    inst_width = 4
                elif inst_type in [b"uint16_t"]:
                    inst_width = 2
                else:
                    log.fatal(f"Type {inst_type} no handled.")
                    exit(1)
            else:
                # Needs manual fix
                return get_text(src, ffi_call.start_byte, ffi_call.end_byte)
        return re.sub(
            rb"fieldFromInstruction",
            b"fieldFromInstruction_%d" % inst_width,
            get_text(src, ffi_call.start_byte, ffi_call.end_byte),
        )
