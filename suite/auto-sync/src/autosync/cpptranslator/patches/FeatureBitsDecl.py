# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Patch import Patch


class FeatureBitsDecl(Patch):
    """
    Patch   ... featureBits = ...
    to      REMOVED
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        # Search for featureBits declarations.
        return (
            "(declaration (init_declarator (reference_declarator "
            '((identifier) @id (#match? @id "[fF]eatureBits"))))) @feature_bits_decl'
        )

    def get_main_capture_name(self) -> str:
        return "feature_bits_decl"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        # Remove declaration
        return b""
