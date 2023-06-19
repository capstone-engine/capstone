import logging as log
import re

from tree_sitter import Node

from Patches.HelperMethods import get_text
from Patches.Patch import Patch


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
        namespace = captures[0][0].named_children[0]
        identifier = captures[0][0].named_children[1]
        namespace = get_text(src, namespace.start_byte, namespace.end_byte)
        identifier = get_text(src, identifier.start_byte, identifier.end_byte)
        return namespace + b"_" + identifier
