# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Patch import Patch


class FallThrough(Patch):
    """
    Patch   [[fallthrough]]
    to      // fall through
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return '(attributed_statement) @attr (#match? @attr "fallthrough")'

    def get_main_capture_name(self) -> str:
        return "attr"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        return b"// fall through"
