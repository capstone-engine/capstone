# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Patch import Patch


class DecoderCast(Patch):
    """
    Patch   Removes casts like `const MCDisassembler *Dis = static_cast<const MCDisassembler*>(Decoder);`
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(declaration"
            "   (type_qualifier)*"
            '   ((type_identifier) @tid (#eq? @tid "MCDisassembler"))'
            "   (init_declarator"
            "       (pointer_declarator)"
            "       (call_expression"
            "           (template_function)"  # static_cast<const MCDisassembler>
            "           (argument_list"
            '               ((identifier) @id (#eq? @id "Decoder"))'
            "           )"
            "       )"
            "   )"
            ") @decoder_cast"
        )

    def get_main_capture_name(self) -> str:
        return "decoder_cast"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        return b""
