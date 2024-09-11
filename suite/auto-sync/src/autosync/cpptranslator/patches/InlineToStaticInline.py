# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class InlineToStaticInline(Patch):
    """
    Removes the qualified identifier of the class from method definitions.
    Translating them to functions.

    Patch   inline void FUNCTION(...) {...}
    to      static inline void FUNCTION(...) {...}

    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(function_definition"
            '   ((storage_class_specifier) @scs (#eq? @scs "inline"))'
            "   (_)+"
            ") @inline_def"
        )

    def get_main_capture_name(self) -> str:
        return "inline_def"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        inline_def = captures[0][0]
        inline_def = get_text(src, inline_def.start_byte, inline_def.end_byte)
        return b"static " + inline_def
