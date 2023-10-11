from tree_sitter import Node

from Patches.HelperMethods import get_text
from Patches.Patch import Patch


class LLVMUnreachable(Patch):
    """
    Patch   llvm_unreachable("Error msg")
    to      assert(0 && "Error msg")
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(call_expression ("
            '   (identifier) @fcn_name (#eq? @fcn_name "llvm_unreachable")'
            "   (argument_list) @err_msg"
            ")) @llvm_unreachable"
        )

    def get_main_capture_name(self) -> str:
        return "llvm_unreachable"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        err_msg = captures[2][0]
        err_msg = get_text(src, err_msg.start_byte, err_msg.end_byte).strip(b"()")
        res = b"assert(0 && " + err_msg + b")"
        return res
