# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class NamespaceAnon(Patch):
    """
    Patch   namespace {CONTENT}
    to      CONTENT

    Only for anonymous or llvm namespaces
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(namespace_definition"
            "   (declaration_list) @decl_list"
            ") @namespace_def"
        )

    def get_main_capture_name(self) -> str:
        return "namespace_def"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        decl_list = captures[1][0]
        dl = get_text(src, decl_list.start_byte, decl_list.end_byte).strip(b"{}")
        return dl
