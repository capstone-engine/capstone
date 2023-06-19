import logging as log
import re

from tree_sitter import Node

from Patches.HelperMethods import get_text
from Patches.Patch import Patch


class MethodToFunction(Patch):
    """
    Removes the qualified identifier of the class from method definitions.
    Translating them to functions.

    Patch   void CLASS::METHOD_NAME(...) {...}
    to      void METHOD_NAME(...) {...}

    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(function_declarator"
            "   (qualified_identifier"
            "       (namespace_identifier)"
            "       (identifier) @method_name"
            "   )"
            "   (parameter_list) @param_list"
            ") @method_def"
        )

    def get_main_capture_name(self) -> str:
        return "method_def"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        name = captures[1][0]
        parameter_list = captures[2][0]
        name = get_text(src, name.start_byte, name.end_byte)
        parameter_list = get_text(src, parameter_list.start_byte, parameter_list.end_byte)
        res = name + parameter_list
        return res
