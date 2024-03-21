# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_MCInst_var_name, get_text
from autosync.cpptranslator.patches.Patch import Patch


class GetSubReg(Patch):
    """
    Patch   MRI.getSubReg(...);
    to      MCRegisterInfo_getSubReg(MI->MRI, ...)
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(call_expression"
            "    (field_expression ("
            "        (identifier)"
            '        ((field_identifier) @field_id (#eq? @field_id "getSubReg")))'
            "     )"
            "    (argument_list) @arg_list"
            ") @get_sub_reg"
        )

    def get_main_capture_name(self) -> str:
        return "get_sub_reg"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        # Get arg list
        op_create_args: Node = captures[2][0]

        args = get_text(src, op_create_args.start_byte, op_create_args.end_byte).strip(
            b"()"
        )
        mcinst_var_name = get_MCInst_var_name(src, op_create_args)
        return b"MCRegisterInfo_getSubReg(" + mcinst_var_name + b"->MRI, " + args + b")"
