from tree_sitter import Node

from Patches.HelperMethods import get_text
from Patches.Patch import Patch
from TemplateCollector import TemplateCollector


class TemplateRefs(Patch):
    """
    Patch   TemplateFunction<A, B>
    to      CONCAT(TemplateFunction, CONCAT(A, B))
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(template_function"
            "     ((identifier) @name)"
            "     ((template_argument_list) @templ_args)"
            ") @template_refs"
        )

    def get_main_capture_name(self) -> str:
        return "template_refs"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        tc: Node = captures[1][0]
        templ_args: Node = captures[2][0]

        name = get_text(src, tc.start_byte, tc.end_byte)
        t_params = get_text(src, templ_args.start_byte, templ_args.end_byte)
        if name == b"static_cast":
            return t_params.replace(b"<", b"(").replace(b">", b")")
        t_params_list = TemplateCollector.templ_params_to_list(t_params)
        res = TemplateCollector.get_macro_c_call(name, t_params_list)
        return res
