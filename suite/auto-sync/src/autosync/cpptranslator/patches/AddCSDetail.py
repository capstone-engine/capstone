# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import logging as log
import re

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import (
    get_MCInst_var_name,
    get_text,
    template_param_list_to_dict,
)
from autosync.cpptranslator.patches.Patch import Patch


class AddCSDetail(Patch):
    """
    Adds calls to `<ARCH>_add_cs_detail_<n>()` for printOperand functions in <ARCH>InstPrinter.c

    Patch   void printThumbLdrLabelOperand(MCInst *MI, unsigned OpNo, SStream *O) {...}
    to      void printThumbLdrLabelOperand(MCInst *MI, unsigned OpNo, SStream *O) {
                <ARCH>_add_cs_detail_<n>(MI, ARM_OP_GROUP_ThumbLdrLabelOperand, ...);
                ...
            }
    """

    # TODO Simply checking for the passed types would be so much nicer.
    # Parameter lists of printOperand() functions we need to add `<ARCH>_add_cs_detail_<n>()` to.
    # Spaces are removed, so we only need to check the letters.
    valid_param_lists = [
        b"(MCInst*MI,unsignedOpNum,SStream*O)",  # Default printOperand parameters.
        b"(MCInst*MI,unsignedOpNo,SStream*O)",  # ARM - printComplexRotationOp / PPC default
        b"(MCInst*MI,intopNum,SStream *O)",  # Mips - printMemOperandEA and others
        b"(SStream*O,ARM_AM::ShiftOpcShOpc,unsignedShImm,boolgetUseMarkup())",  # ARM - printRegImmShift
        b"(MCInst*MI,unsignedOpNo,SStream*O,constchar*Modifier)",  # PPC - printPredicateOperand
        b"(MCInst*MI,uint64_tAddress,unsignedOpNo,SStream*O)",  # PPC - printBranchOperand
        b"(MCInst*MI,intOpNum,SStream*O)",  # SystemZ
        b"(MCInst*MI,intOpNum,SStream*O)",  # Xtensa printOperand parameters.
        b"(MCInst*MI,intOpNum,SStream*OS)",  # Xtensa printOperand parameters.
        b"(MCInst*MI,intopNum,SStream*O)",  # Sparc printOperand parameters.
    ]

    def __init__(self, priority: int, arch: str):
        super().__init__(priority)
        self.arch = arch

    def get_search_pattern(self) -> str:
        return (
            "(function_definition"
            "   (_)+"
            "   (function_declarator"
            '       ((identifier) @fcn_id (#match? @fcn_id "print.*"))'
            "       ((parameter_list) @p_list)"
            "   )"
            "   (compound_statement) @comp_stmt"
            ") @print_op"
        )

    def get_main_capture_name(self) -> str:
        return "print_op"

    def get_patch(
        self, captures: list[tuple[Node, str]], src: bytes, **kwargs
    ) -> bytes:
        fcn_def: Node = captures[0][0]
        params = captures[2][0]
        params = get_text(src, params.start_byte, params.end_byte)
        if re.sub(b"[\n \t]", b"", params) not in self.valid_param_lists:
            return get_text(src, fcn_def.start_byte, fcn_def.end_byte)

        fcn_id = captures[1][0]
        fcn_id = get_text(src, fcn_id.start_byte, fcn_id.end_byte)

        add_cs_detail = self.get_add_cs_detail(src, fcn_def, fcn_id, params)

        comp = captures[3][0]
        comp = get_text(src, comp.start_byte, comp.end_byte)
        return (
            b"static inline void "
            + fcn_id
            + params
            + b"{ "
            + add_cs_detail
            + comp.strip(b"{")
        )

    def get_add_cs_detail(
        self, src: bytes, fcn_def: Node, fcn_id: bytes, params: bytes
    ) -> bytes:
        op_group_enum = (
            self.arch.encode("utf8") + b"_OP_GROUP_" + fcn_id[5:]
        )  # Remove "print" from function id

        is_template = fcn_def.prev_sibling.type == "template_parameter_list"
        if b"OpNum" in params:
            op_num_var_name = b"OpNum"
        elif b"OpNo" in params:
            op_num_var_name = b"OpNo"
        elif b"opNum" in params:
            op_num_var_name = b"opNum"
        else:
            raise ValueError("OpNum parameter could not be identified.")

        if not is_template and op_num_var_name in params:
            # Standard printOperand() parameters
            mcinst_var = get_MCInst_var_name(src, fcn_def)
            return (
                f"{self.arch}_add_cs_detail_0(".encode()
                + mcinst_var
                + b", "
                + op_group_enum
                + b", "
                + op_num_var_name
                + b");"
            )
        elif op_group_enum == b"ARM_OP_GROUP_RegImmShift":
            return (
                f"{self.arch}_add_cs_detail_1(MI, ".encode()
                + op_group_enum
                + b", ShOpc, ShImm);"
            )
        elif is_template and op_num_var_name in params:
            mcinst_var = get_MCInst_var_name(src, fcn_def)
            templ_p = template_param_list_to_dict(fcn_def.prev_sibling)
            cs_args = b""
            for tp in templ_p:
                op_group_enum = (
                    b"CONCAT(" + op_group_enum + b", " + tp["identifier"] + b")"
                )
                cs_args += b", " + tp["identifier"]
            return (
                f"{self.arch}_add_cs_detail_{len(templ_p)}(".encode()
                + mcinst_var
                + b", "
                + op_group_enum
                + b", "
                + op_num_var_name
                + b" "
                + cs_args
                + b");"
            )
        log.fatal(f"Case {op_group_enum} not handled.")
        exit(1)
