# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_MCInst_var_name, get_text
from autosync.cpptranslator.patches.Patch import Patch


class FeatureBits(Patch):
    """
    Patch   featureBits[FLAG]
    to      ARCH_getFeatureBits(Inst->csh->mode, FLAG)
    """

    def __init__(self, priority: int, arch: bytes):
        self.arch = arch
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        # Search for featureBits usage.
        return (
            "(subscript_expression "
            '   ((identifier) @id (#match? @id "[fF]eatureBits"))'
            "   (subscript_argument_list ((qualified_identifier) @qid))"
            ") @feature_bits"
        )

    def get_main_capture_name(self) -> str:
        return "feature_bits"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        # Get flag name of feature bit.
        qualified_id: Node = captures[2][0]
        flag = get_text(src, qualified_id.start_byte, qualified_id.end_byte)
        mcinst_var_name = get_MCInst_var_name(src, qualified_id)
        return (
            self.arch
            + b"_getFeatureBits("
            + mcinst_var_name
            + b"->csh->mode, "
            + flag
            + b")"
        )
