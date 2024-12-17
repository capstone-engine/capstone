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
            inst_width = b"4"
        elif ffi_first_arg_text[-2:] == "16":
            inst_width = b"2"
        else:
            # Get the Val/Inst parameter.
            # Its type determines the instruction width.
            if len(param_list_caller.named_children) == 1:
                # If function just return fieldFromInstruction(...)
                inst_param: Node = param_list_caller.named_children[0]
            else:
                inst_param = param_list_caller.named_children[1]
            inst_param_text = get_text(src, inst_param.start_byte, inst_param.end_byte)

            # Search for the 'Inst' parameter and determine its type
            # and with it the width of the instruction.
            inst_type = inst_param_text.split(b" ")[0]
            if inst_type:
                if inst_type in [b"uint64_t"]:
                    inst_width = b"8"
                elif inst_type in [b"unsigned", b"uint32_t"]:
                    inst_width = b"4"
                elif inst_type in [b"uint16_t"]:
                    inst_width = b"2"
                elif inst_type in [b"InsnType"]:
                    # Case means the decode function inherits the type from
                    # a template argument InsnType. The InsnType template argument
                    # is the type of integer holding the instruction bytes.
                    # This type is defined in ARCHDisassembler on calling the right macro.
                    # Hence, we do not know at this point of patching which type it might be.
                    # It needs to call fieldOfInstruction_X() which detects dynamically which
                    # integer type might hold the bytes (e.g. a uint32_t or uint16_t).
                    # You can check it manually in ARCHDisassembler.c, but the script can't.
                    #
                    # Here we just create a function with the postfix fieldFromInstruction_w (for width).
                    # This function must be implemented by hand, and check MCInst for the actual bit width.
                    # The bit width must be set in the ARCHDisassembler.c. Just add the code there by hand.
                    # Then call fieldFromInstruction_4, fieldFromInstruction_2 appropriately.
                    log.warning(
                        "Variable fieldFromInstruction width detected.\n"
                        "Please implement fieldFromInstruction_w() and call "
                        "fieldFromInstruction_4, fieldFromInstruction_2 appropriately.\n"
                        "In fieldFromInstruction_w() check MCInst for the actual bit width.\n"
                        "The bit width must be set in the ARCHDisassembler.c. Just add the code there by hand."
                    )
                    inst_width = b"w"
                else:
                    raise ValueError(f"Type {inst_type} not handled.")
            else:
                # Needs manual fix
                return get_text(src, ffi_call.start_byte, ffi_call.end_byte)
        return re.sub(
            rb"fieldFromInstruction",
            b"fieldFromInstruction_%s" % inst_width,
            get_text(src, ffi_call.start_byte, ffi_call.end_byte),
        )
