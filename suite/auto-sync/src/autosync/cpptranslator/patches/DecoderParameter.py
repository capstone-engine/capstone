# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Patch import Patch


class DecoderParameter(Patch):
    """
    Patch   const MCDisassembler *Decoder
    to      const void *Decoder
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(parameter_declaration"
            "   ((type_qualifier) @type_qualifier)"
            '   ((type_identifier) @type_id (#eq? @type_id "MCDisassembler"))'
            "   (pointer_declarator) @ptr_decl"
            ") @decoder_param"
        )

    def get_main_capture_name(self) -> str:
        return "decoder_param"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        return b"const void *Decoder"
