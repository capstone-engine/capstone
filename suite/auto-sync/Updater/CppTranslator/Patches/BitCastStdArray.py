from tree_sitter import Node

from CppTranslator.Patches.HelperMethods import get_text
from CppTranslator.Patches.Patch import Patch


class BitCastStdArray(Patch):
    """
    Patch   auto S = bit_cast<std::array<int32_t, 2>>(Imm);
    to      int32_t *S = ((int32_t *)(&Imm)); // Array length = 2
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(declaration"
            "   (placeholder_type_specifier)"
            "   (init_declarator"
            "       (identifier) @arr_name"
            "       (call_expression"
            "           (template_function"
            '               ((identifier) @tfid (#eq @tfid "bit_cast"))'
            "               (template_argument_list"
            '                   ((type_descriptor) @td (#match @td "std::array<.*>"))'
            "                )"
            "           )"
            "           (argument_list) @cast_target"
            "       )"
            "   )"
            ") @array_bit_cast"
        )

    def get_main_capture_name(self) -> str:
        return "array_bit_cast"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        arr_name: bytes = captures[1][0].text
        array_type: Node = captures[3][0]
        cast_target: bytes = captures[4][0].text
        array_templ_args: bytes = array_type.named_children[0].named_children[1].named_children[1].text.strip(b"<>")
        arr_type = array_templ_args.split(b",")[0]
        arr_len = array_templ_args.split(b",")[1]
        return arr_type + b" *" + arr_name + b" = (" + arr_type + b"*)(&" + cast_target + b"); // arr len = " + arr_len
