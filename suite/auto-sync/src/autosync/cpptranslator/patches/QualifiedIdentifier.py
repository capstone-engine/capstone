# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class QualifiedIdentifier(Patch):
    """
    Patch   NAMESPACE::ID
    to      NAMESPACE_ID
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return "(qualified_identifier) @qualified_id"

    def get_main_capture_name(self) -> str:
        return "qualified_id"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        if len(captures[0][0].named_children) > 1:
            identifier = captures[0][0].named_children[1]
            identifier = get_text(src, identifier.start_byte, identifier.end_byte)
            namespace = captures[0][0].named_children[0]
            namespace = get_text(src, namespace.start_byte, namespace.end_byte)
        else:
            # The namespace can be omitted. E.g. std::transform(..., ::tolower)
            namespace = b""
            identifier = captures[0][0].named_children[0]
            identifier = get_text(src, identifier.start_byte, identifier.end_byte)
        match (namespace, identifier):
            case (b"std", b"size"):
                return b"sizeof"
            case _:
                return namespace + b"_" + identifier
