# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import logging as log

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class TemplateParamDecl(Patch):
    """
    Example:

    Patch   ArrayRef<uint8_t> x
    to      const uint8_t *x, size_t xLen
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(parameter_declaration"
            "   (template_type"
            "       (type_identifier) @templ_type"
            "       (template_argument_list) @arg_list"
            "   )"
            "   (identifier) @param_id"
            ") @template_param_decl"
        )

    def get_main_capture_name(self) -> str:
        return "template_param_decl"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        template_type = captures[1][0]
        arg_list = captures[2][0]
        param_id = captures[3][0]
        templ_type = get_text(src, template_type.start_byte, template_type.end_byte)
        args = get_text(src, arg_list.start_byte, arg_list.end_byte)
        p_id = get_text(src, param_id.start_byte, param_id.end_byte)

        if templ_type == b"ArrayRef":
            res = (
                b"const "
                + args.strip(b"<>")
                + b" *"
                + p_id
                + b", size_t "
                + p_id
                + b"Len"
            )
            return res
        log.fatal(f"Template type {templ_type} not handled as parameter")
        exit(1)
