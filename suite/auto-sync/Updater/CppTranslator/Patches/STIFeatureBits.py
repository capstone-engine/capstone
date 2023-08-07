from tree_sitter import Node

from CppTranslator.Patches.HelperMethods import get_text
from CppTranslator.Patches.Patch import Patch


class STIFeatureBits(Patch):
    """
    Patch   STI.getFeatureBits()[FLAG]
    to      ARCH_getFeatureBits(Inst->csh->mode, ...)
    """

    def __init__(self, priority: int, arch: bytes):
        self.arch = arch
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        # Search for featureBits usage.
        return (
            "(subscript_expression "
            "   (call_expression"
            "       (field_expression"
            "           (identifier)"
            '           ((field_identifier) @fid (#eq? @fid "getFeatureBits"))'
            "       )"
            "       (argument_list)"
            "   )"
            "   ((qualified_identifier) @flag)"
            ") @sti_feature_bits"
        )

    def get_main_capture_name(self) -> str:
        return "sti_feature_bits"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        # Get flag name of feature bit.
        qualified_id: Node = captures[2][0]
        flag = get_text(src, qualified_id.start_byte, qualified_id.end_byte)
        return self.arch + b"_getFeatureBits(Inst->csh->mode, " + flag + b")"
