# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_MCInst_var_name, get_text
from autosync.cpptranslator.patches.Patch import Patch


class PredicateBlockFunctions(Patch):
    """
    Patch   VPTBlock.instrInVPTBlock()
    to      VPTBlock_instrInVPTBlock(&(MI->csh->VPTBlock))

    And other functions of VPTBlock and ITBlock
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(call_expression "
            "   (field_expression"
            '       ((identifier) @block_var (#match? @block_var "[VI][PT]T?Block"))'
            "       ((field_identifier) @field_id)"
            "   )"
            "   ((argument_list) @arg_list)"
            ") @block_fcns"
        )

    def get_main_capture_name(self) -> str:
        return "block_fcns"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        block_var = captures[1][0]
        fcn_id = captures[2][0]
        args = captures[3][0]
        block_var_text = get_text(src, block_var.start_byte, block_var.end_byte)
        fcn_id_text = get_text(src, fcn_id.start_byte, fcn_id.end_byte)
        args_text = get_text(src, args.start_byte, args.end_byte)
        mcinst_var: bytes = get_MCInst_var_name(src, block_var)

        a = b"&(" + mcinst_var + b"->csh->" + block_var_text + b")"
        args_text = args_text.strip(b"()")
        if args_text:
            a += b"," + args_text
        return block_var_text + b"_" + fcn_id_text + b"(" + a + b")"
