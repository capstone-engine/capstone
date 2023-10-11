from tree_sitter import Node

from CppTranslator.Patches.Patch import Patch


class LLVMFallThrough(Patch):
    """
    Patch   Remove LLVM_FALLTHROUGH
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return "(expression_statement" '   ((identifier) @id (#eq? @id "LLVM_FALLTHROUGH"))' ") @llvm_fall_through"

    def get_main_capture_name(self) -> str:
        return "llvm_fall_through"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        return b""
