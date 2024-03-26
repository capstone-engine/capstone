# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class BitCastStdArray(Patch):
    """
    Patch   auto S = bit_cast<std::array<int32_t, 2>>(Imm);
    to      union {
                typeof(Imm) In;
                int32_t Out[2];
            } U_S;
            U_S.In = Imm;
            int32_t *S = U_S.Out;

            MSVC doesn't support typeof so it has to be resolved manually.
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
        cast_target: bytes = captures[4][0].text.strip(b"()")
        array_templ_args: bytes = (
            array_type.named_children[0]
            .named_children[1]
            .named_children[1]
            .text.strip(b"<>")
        )
        arr_type = array_templ_args.split(b",")[0]
        arr_len = array_templ_args.split(b",")[1]
        return (
            b"union {\n"
            + b"    typeof("
            + cast_target
            + b") In;\n"
            + b"    "
            + arr_type
            + b" Out["
            + arr_len
            + b"];\n"
            + b"} U_"
            + arr_name
            + b";\n"
            + b"U_"
            + arr_name
            + b".In = "
            + cast_target
            + b";\n"
            + arr_type
            + b" *"
            + arr_name
            + b" = U_"
            + arr_name
            + b".Out;"
        )
