# Copyright © 2024 Dmitry Sibitsev <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Patch import Patch


class LLVMDebug(Patch):
    """
    Patch   Remove LLVM_DEBUG("Debug message")
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(call_expression ("
            '   (identifier) @fcn_name (#eq? @fcn_name "LLVM_DEBUG")'
            "   (argument_list) @dbg_msg"
            ")) @llvm_debug"
        )

    def get_main_capture_name(self) -> str:
        return "llvm_debug"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        return b""
