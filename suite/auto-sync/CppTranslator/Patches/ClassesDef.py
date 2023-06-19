import logging as log
import re

from tree_sitter import Node

from Patches.HelperMethods import get_text
from Patches.Patch import Patch


class ClassesDef(Patch):
    """
    Patch   Class definitions
    to      Removes class but extracts method declarations.
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return "(class_specifier (_)* ((field_declaration_list) @decl_list)*) @class_specifier"

    def get_main_capture_name(self) -> str:
        return "class_specifier"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        field_decl_list = captures[1][0]
        functions = list()
        for field_decl in field_decl_list.named_children:
            if (
                field_decl.type in "field_declaration"
                and ("function_declarator" in [t.type for t in field_decl.named_children])
            ) or field_decl.type == "template_declaration":
                # Keep comments
                sibling = field_decl.prev_named_sibling
                while sibling.type == "comment":
                    functions.append(sibling)
                    sibling = sibling.prev_named_sibling
                functions.append(field_decl)
        fcn_decl_text = b""
        for f in functions:
            fcn_decl_text += get_text(src, f.start_byte, f.end_byte) + b"\n"
        return fcn_decl_text
