import logging as log
import re

from tree_sitter import Node

from Patches.HelperMethods import get_text
from Patches.Patch import Patch
from TemplateCollector import TemplateRefInstance, TemplateCollector


class SignExtend32(Patch):
    """
    Patch   SignExtend32<A>(...)
    to      SignExtend32(..., A)
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(call_expression"
            "     (template_function"
            '         ((identifier) @name (#eq? @name "SignExtend32"))'
            "         ((template_argument_list) @templ_args)"
            "     )"
            "     ((argument_list) @fcn_args)"
            ") @sign_extend"
        )

    def get_main_capture_name(self) -> str:
        return "sign_extend"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        se32: Node = captures[1][0]
        templ_args: Node = captures[2][0]
        fcn_args: Node = captures[3][0]

        name = get_text(src, se32.start_byte, se32.end_byte)
        t_args = get_text(src, templ_args.start_byte, templ_args.end_byte)
        t_args = b", ".join(TemplateCollector.templ_params_to_list(t_args))
        f_args = get_text(src, fcn_args.start_byte, fcn_args.end_byte)
        return name + b"(" + f_args + b", " + t_args + b")"
