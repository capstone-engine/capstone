# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import re

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class CreateOperand0(Patch):
    """
    Patch   Inst.addOperand(MCOperand::createReg(...));
    to      MCOperand_CreateReg0(...)
    (and equivalent for CreateImm)

    This is the `0` variant of the CS `CreateReg`/`CreateImm` functions. It is used if the
    operand is added via `addOperand()`.
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(call_expression "
            "    (field_expression ((identifier) @inst_var"
            '                        (field_identifier) @field_id (#eq? @field_id "addOperand")))'
            "    (argument_list (call_expression "
            "                        (qualified_identifier ((_) (identifier) @create_fcn))"
            "                        (argument_list) @arg_list"
            "                    )"
            "    )"
            ") @create_operand0"
        )

    def get_main_capture_name(self) -> str:
        return "create_operand0"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        # Get name of instruction variable
        inst_var: Node = captures[1][0]
        # Get 'create[Reg/Imm]'
        op_create_fcn: Node = captures[3][0]
        # Get arg list
        op_create_args: Node = captures[4][0]

        # Capstone spells the function with capital letter 'C' for whatever reason.
        fcn = re.sub(
            b"create",
            b"Create",
            get_text(src, op_create_fcn.start_byte, op_create_fcn.end_byte),
        )
        inst = get_text(src, inst_var.start_byte, inst_var.end_byte)
        args = get_text(src, op_create_args.start_byte, op_create_args.end_byte)
        if args[0] == b"(" and args[-1] == b")":
            args = args
        return b"MCOperand_" + fcn + b"0(" + inst + b", " + args + b")"
