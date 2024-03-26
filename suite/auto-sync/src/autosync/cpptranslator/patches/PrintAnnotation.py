# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Patch import Patch


class PrintAnnotation(Patch):
    """
    Removes printAnnotation(...) calls.
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(call_expression ("
            '   (identifier) @fcn_name (#eq? @fcn_name "printAnnotation")'
            "   (argument_list)"
            ")) @print_annotation"
        )

    def get_main_capture_name(self) -> str:
        return "print_annotation"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        return b""
