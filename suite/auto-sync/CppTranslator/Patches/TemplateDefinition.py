import logging as log
import re

from tree_sitter import Node

from Patches.HelperMethods import get_text
from Patches.Patch import Patch
from TemplateCollector import TemplateCollector, TemplateRefInstance


class TemplateDefinition(Patch):
    """
    Patch   template<A, B>
            RET_TYPE TemplateFunction(...) {...}

    to      #define DEFINE_TemplateFunction_A_B \
            RET_TYPE CONCAT(TemplateFunction, CONCAT(A, B))(...) {...}
    """

    def __init__(self, priority: int, template_collector: TemplateCollector):
        self.collector: TemplateCollector = template_collector
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(template_declaration"
            "     ((template_parameter_list) @templ_params)"
            "     (function_definition"
            "        ((storage_class_specifier)* @storage_class_id)"
            "        ([(type_identifier)(primitive_type)] @type_id)"
            "        (function_declarator"
            "            ((identifier) @fcn_name)"
            "            ((parameter_list) @fcn_params)"
            "        )"
            "        ((compound_statement) @compound)"
            "     )"
            ") @template_def"
        )

    def get_main_capture_name(self) -> str:
        return "template_def"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        has_storage_class_id = any([c[1] == "storage_class_id" for c in captures])
        templ_params: Node = captures[1][0]
        if has_storage_class_id:
            sc_id: Node = captures[2][0]
            type_id: Node = captures[3][0]
            fcn_name: Node = captures[4][0]
            fcn_params: Node = captures[5][0]
            compound: Node = captures[6][0]
        else:
            sc_id = None
            type_id: Node = captures[2][0]
            fcn_name: Node = captures[3][0]
            fcn_params: Node = captures[4][0]
            compound: Node = captures[5][0]

        t_params: list = TemplateCollector.templ_params_to_list(
            get_text(src, templ_params.start_byte, templ_params.end_byte)
        )
        sc = get_text(src, sc_id.start_byte, sc_id.end_byte) + b" " if has_storage_class_id else b""
        tid = get_text(src, type_id.start_byte, type_id.end_byte)
        f_name = get_text(src, fcn_name.start_byte, fcn_name.end_byte)
        f_params = get_text(src, fcn_params.start_byte, fcn_params.end_byte)
        f_compound = get_text(src, compound.start_byte, compound.end_byte)
        if f_name in self.collector.templates_with_arg_deduction:
            return sc + tid + b" " + f_name + f_params + f_compound

        definition = b"#define DEFINE_" + f_name + b"(" + b", ".join(t_params) + b")\n"
        definition += sc + tid + b" " + TemplateCollector.get_macro_c_call(f_name, t_params, f_params) + f_compound
        # Remove // comments
        definition = re.sub(b" *//.*", b"", definition)
        definition = definition.replace(b"\n", b" \\\n") + b"\n"

        template_instance: TemplateRefInstance
        declared_implementations = list()
        if f_name not in self.collector.template_refs:
            log.fatal(
                f"Template collector has no reference for {f_name}. "
                f"Make sure to add all source files to the config file "
                f"which use this template function."
            )
            exit(1)
        for template_instance in self.collector.template_refs[f_name]:
            d = b"DEFINE_" + f_name + b"(" + b", ".join(template_instance.args_list) + b")\n"
            if d in declared_implementations:
                continue
            declared_implementations.append(d)
            definition += d
        return definition
