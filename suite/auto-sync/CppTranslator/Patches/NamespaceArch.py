from tree_sitter import Node

from Patches.HelperMethods import get_text, namespace_enum, namespace_fcn_def, namespace_struct
from Patches.Patch import Patch


class NamespaceArch(Patch):
    """
    Patch   namespace ArchSpecificNamespace {CONTENT}
    to      CONTENT

    Patches namespaces specific to architecture. This needs to patch enums and functions within this namespace.
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return "(namespace_definition" "   (identifier)" "   (declaration_list) @decl_list" ") @namespace_def"

    def get_main_capture_name(self) -> str:
        return "namespace_def"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        namespace = captures[0][0]
        decl_list = captures[1][0]
        namespace_id = get_text(src, namespace.named_children[0].start_byte, namespace.named_children[0].end_byte)

        # We need to prepend the namespace id to all enum members, function declarators and struct types.
        # Because in the generated files they are accessed via NAMESPACE::X which becomes NAMESPACE_X.
        res = b""
        for d in decl_list.named_children:
            match d.type:
                case "enum_specifier":
                    res += namespace_enum(src, namespace_id, d) + b";\n\n"
                case "declaration" | "function_definition":
                    res += namespace_fcn_def(src, namespace_id, d) + b"\n\n"
                case "struct_specifier":
                    res += namespace_struct(src, namespace_id, d) + b";\n\n"
                case _:
                    res += get_text(src, d.start_byte, d.end_byte) + b"\n"
        return res
