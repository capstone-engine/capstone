# Copyright © 2022 Rot127 <unisono@quyllur.org>
# Copyright © 2024 Billow <billow.fun@gmail.com>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class LLVM_DEBUG(Patch):
    """
    Patch   LLVM_DEBUG(dbgs() << "Error msg")
    to      ""
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return """
            (call_expression (
               (identifier) @fcn_name (#eq? @fcn_name "LLVM_DEBUG")
               (argument_list (
                   (binary_expression (
                       (call_expression)
                       (string_literal) @err_msg
                   ))
               ))
            )) @llvm_debug"""

    def get_main_capture_name(self) -> str:
        return "llvm_debug"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        return b""
