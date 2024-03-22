# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class OutStreamParam(Patch):
    """
    Patches the parameter list only:

    Patch   void function(int a, raw_ostream &OS)
    to      void function(int a, SStream *OS)
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(parameter_list"
            "   (_)*"
            "   (parameter_declaration"
            '       ((type_identifier) @tid (#eq? @tid "raw_ostream"))'
            "       (_)"
            "   )"
            "   (_)*"
            ") @ostream_param"
        )

    def get_main_capture_name(self) -> str:
        return "ostream_param"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        param_list = list()
        for param in captures[0][0].named_children:
            p_text = get_text(src, param.start_byte, param.end_byte)
            if b"raw_ostream" in p_text:
                p_text = p_text.replace(b"raw_ostream", b"SStream").replace(b"&", b"*")
            param_list.append(p_text)
        res = b"(" + b", ".join(param_list) + b")"
        return res
