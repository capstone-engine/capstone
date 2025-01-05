# Copyright © 2024 Dmitry Sibitsev <sibirtsevdl@gmail.com>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Patch import Patch


class BadConditionCode(Patch):
    """
    Patch   return BadConditionCode
    to      CS_ASSERT(0 && "Unknown condition code passed")
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(return_statement "
            "    (call_expression "
            '        (identifier) @fcn_name (#eq? @fcn_name "BadConditionCode")'
            "        (argument_list)"
            "    )"
            ") @bad_condition_code"
        )

    def get_main_capture_name(self) -> str:
        return "bad_condition_code"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        return b'CS_ASSERT(0 && "Unknown condition code passed");'
