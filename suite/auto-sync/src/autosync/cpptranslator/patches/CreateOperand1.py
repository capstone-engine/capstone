# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import re

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_MCInst_var_name, get_text
from autosync.cpptranslator.patches.Patch import Patch


class CreateOperand1(Patch):
    """
    Patch   MI.insert(..., MCOperand::createReg(...));
    to      MCInst_insert0(..., MCOperand_createReg1(...));
    (and equivalent for CreateImm)

    This is the `1` variant of the CS `CreateReg`/`CreateImm` functions. It is used if the
    operand is added via `insert()`.
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(call_expression "
            "    (field_expression ((identifier) @MC_id"
            '                       ((field_identifier) @field_id (#match? @field_id "insert")))'
            "    )"
            "    (argument_list"
            "        ((identifier) @inst_var"
            "         (call_expression"
            "            (qualified_identifier ((_) (identifier) @create_fcn))"
            "            (argument_list) @arg_list)"
            "        )"
            "    )"
            ") @create_operand1"
        )

    def get_main_capture_name(self) -> str:
        return "create_operand1"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        # Get instruction variable
        inst_var: Node = captures[1][0]
        # Get argument of .insert() call
        insert_arg: Node = captures[3][0]
        # Get 'create[Reg/Imm]'
        op_create_fcn: Node = captures[4][0]
        # CreateReg/Imm args
        op_create_args: Node = captures[5][0]

        insert_arg_t = get_text(src, insert_arg.start_byte, insert_arg.end_byte)
        # Capstone spells the function with capital letter 'C' for whatever reason.
        fcn = re.sub(
            b"create",
            b"Create",
            get_text(src, op_create_fcn.start_byte, op_create_fcn.end_byte),
        )
        inst = get_text(src, inst_var.start_byte, inst_var.end_byte)
        args = get_text(src, op_create_args.start_byte, op_create_args.end_byte)
        return (
            b"MCInst_insert0("
            + inst
            + b", "
            + insert_arg_t
            + b", "
            + b"MCOperand_"
            + fcn
            + b"1("
            + inst
            + b", "
            + args
            + b"))"
        )
