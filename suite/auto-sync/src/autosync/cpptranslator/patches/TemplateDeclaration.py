# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import logging as log

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import parse_function_capture
from autosync.cpptranslator.patches.Patch import Patch
from autosync.cpptranslator.TemplateCollector import (
    TemplateCollector,
    TemplateRefInstance,
)


class TemplateDeclaration(Patch):
    """
    Patch   template<A, B>
            RET_TYPE TemplateFunction(...);

    to      #define DECLARE_TemplateFunction_A_B \
            RET_TYPE CONCAT(TemplateFunction, CONCAT(A, B))(...);
    """

    def __init__(self, priority: int, template_collector: TemplateCollector):
        self.collector: TemplateCollector = template_collector
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(template_declaration"
            "     ((template_parameter_list) @templ_params)"
            "     (declaration"
            "        ((storage_class_specifier)* @storage_class_id)"
            "        ([(type_identifier)(primitive_type)] @type_id)"
            "        (function_declarator"
            "            ((identifier) @fcn_name)"
            "            ((parameter_list) @fcn_params)"
            "        )"
            "     )"
            ") @template_decl"
        )

    def get_main_capture_name(self) -> str:
        return "template_decl"

    def get_patch(
        self, captures: list[tuple[Node, str]], src: bytes, **kwargs
    ) -> bytes:
        t_params, sc, tid, f_name, f_params, _ = parse_function_capture(captures, src)
        if f_name in self.collector.templates_with_arg_deduction:
            return sc + tid + b" " + f_name + f_params + b";"

        declaration = (
            b"#define DECLARE_" + f_name + b"(" + b", ".join(t_params) + b")\n"
        )
        declaration += (
            sc
            + b" "
            + tid
            + b" "
            + TemplateCollector.get_macro_c_call(f_name, t_params, f_params)
            + b";"
        )
        declaration = declaration.replace(b"\n", b" \\\n") + b"\n"

        template_instance: TemplateRefInstance
        declared_implementations = list()
        if f_name not in self.collector.template_refs:
            self.collector.log_missing_ref_and_exit(f_name)

        for template_instance in self.collector.template_refs[f_name]:
            d = (
                b"DECLARE_"
                + f_name
                + b"("
                + b", ".join(template_instance.get_args_for_decl())
                + b");\n"
            )
            if d in declared_implementations:
                continue
            declared_implementations.append(d)
            declaration += d
        return declaration
