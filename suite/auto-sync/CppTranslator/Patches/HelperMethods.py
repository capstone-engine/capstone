import re

from tree_sitter import Node
import logging as log


def get_function_params_of_node(n: Node) -> Node:
    """
    Returns for a given node the parameters of the function this node is a children from.
    Or None if the node is not part of a function definition.
    """
    fcn_def: Node = n
    while fcn_def.type != "function_definition":
        if fcn_def.parent == None:
            # root node reached
            return None
        fcn_def = fcn_def.parent

    # Get parameter list of the function definition
    param_list: Node = None
    for child in fcn_def.children:
        if child.type == "function_declarator":
            param_list = child.children[1]
            break
    if not param_list:
        log.warning(f"Could not find the functions parameter list for {n.text}")
    return param_list


def get_MCInst_var_name(src: bytes, n: Node) -> bytes:
    """Searches for the name of the parameter of type MCInst and returns it."""
    params = get_function_params_of_node(n)
    mcinst_var_name = b""
    for p in params.named_children:
        p_text = get_text(src, p.start_byte, p.end_byte)
        if b"MCInst" in p_text:
            mcinst_var_name = p_text.split((b"&" if b"&" in p_text else b"*"))[1]
            break
    if mcinst_var_name == b"":
        log.debug("Could not find `MCInst` variable name. Defaulting to `Inst`.")
        mcinst_var_name = b"Inst"
    return mcinst_var_name


def template_param_list_to_dict(param_list: Node) -> [dict]:
    if param_list.type != "template_parameter_list":
        log.fatal(f"Node of type {param_list.type} given. Not 'template_parameter_list'.")
    pl = list()
    for c in param_list.named_children:
        pl.append(parameter_declaration_to_dict(c))
    return pl


def parameter_declaration_to_dict(param_decl: Node) -> dict:
    if param_decl.type != "parameter_declaration":
        log.fatal(f"Node of type {param_decl.type} given. Not 'parameter_declaration'.")
    return {
        "prim_type": param_decl.children[0].type == "primitive_type",
        "type": param_decl.children[0].text,
        "identifier": param_decl.children[1].text,
    }


def get_text(src: bytes, start_byte: int, end_byte: int) -> bytes:
    """Workaround for https://github.com/tree-sitter/py-tree-sitter/issues/122"""
    return src[start_byte:end_byte]


def namespace_enum(src: bytes, ns_id: bytes, enum: Node) -> bytes:
    """
    Alters an enum in the way that it prepends the namespace id to every enum member.
    Example: naemspace_id = "ARM"
             enum { X } -> enum { ARM_X }
    """
    enumerator_list: Node = None
    for c in enum.named_children:
        if c.type == "enumerator_list":
            enumerator_list = c
            break

    if not enumerator_list:
        log.fatal("Could not find enumerator_list.")
        exit(1)

    res = get_text(src, enum.start_byte, enum.end_byte)
    for e in enumerator_list.named_children:
        if e.type == "enumerator":
            enum_entry_text = get_text(src, e.start_byte, e.end_byte)
            res = res.replace(enum_entry_text, ns_id + b"_" + enum_entry_text)
    return res


def namespace_fcn_def(src: bytes, ns_id: bytes, fcn_def: Node) -> bytes:
    fcn_id: Node = None
    for c in fcn_def.named_children:
        if c.type == "function_declarator":
            fcn_id = c.named_children[0]
            break
        elif c.named_children and c.named_children[0].type == "function_declarator":
            fcn_id = c.named_children[0].named_children[0]
            break
    if not fcn_id:
        log.fatal("Could not find function declarator in one of the first children.")
        exit(1)
    fcn_id_text = get_text(src, fcn_id.start_byte, fcn_id.end_byte)
    fcn_def_text = get_text(src, fcn_def.start_byte, fcn_def.end_byte)
    res = re.sub(fcn_id_text, ns_id + b"_" + fcn_id_text, fcn_def_text)
    return res


def parse_function_capture(
    capture: list[tuple[Node, str]], src: bytes
) -> tuple[list[bytes], bytes, bytes, bytes, bytes, bytes]:
    """
    Parses the capture of a (template) function definition or declaration and returns the byte strings
    for each node in the following order:

    list[template_args], storage_class_identifiers, return_type_id, function_name, function_params, compound_stmt

    If any of those is not present it returns an empty byte string for this position.
    """
    temp_args = b""
    st_class_ids = b""
    ret_type = b""
    func_name = b""
    func_params = b""
    comp_stmt = b""
    for node, node_name in capture:
        t = get_text(src, node.start_byte, node.end_byte)
        match node.type:
            case "template_declaration":
                continue
            case "template_parameter_list":
                temp_args += t if not temp_args else b" " + t
            case "storage_class_specifier":
                st_class_ids += b" " + t
            case "type_identifier" | "primitive_type":
                ret_type += b" " + t
            case "identifier":
                func_name += t if not func_name else b" " + t
            case "parameter_list":
                func_params += t if not func_params else b" " + t
            case "compound_statement":
                comp_stmt += t if not comp_stmt else b" " + t
            case _:
                raise NotImplementedError(f"Node type {node.type} not handled.")

    from TemplateCollector import TemplateCollector

    return TemplateCollector.templ_params_to_list(temp_args), st_class_ids, ret_type, func_name, func_params, comp_stmt
