# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import logging as log
import re

from tree_sitter import Node

from autosync.Helper import fail_exit


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

    if params:
        for p in params.named_children:
            p_text = get_text(src, p.start_byte, p.end_byte)
            if b"MCInst" not in p_text:
                continue
            mcinst_var_name = p_text.split((b"&" if b"&" in p_text else b"*"))[1]
            break
    if mcinst_var_name == b"":
        log.debug("Could not find `MCInst` variable name. Defaulting to `Inst`.")
        mcinst_var_name = b"Inst"
    return mcinst_var_name


def template_param_list_to_dict(param_list: Node) -> [dict]:
    if param_list.type != "template_parameter_list":
        log.fatal(
            f"Wrong node type '{param_list.type}'. Not 'template_parameter_list'."
        )
        exit(1)
    pl = list()
    for c in param_list.named_children:
        if c.type == "type_parameter_declaration":
            type_decl = {
                "prim_type": False,
                "type": "",
                "identifier": c.children[1].text,
            }
            pl.append(type_decl)
        else:
            pl.append(parameter_declaration_to_dict(c))
    return pl


def parameter_declaration_to_dict(param_decl: Node) -> dict:
    if param_decl.type != "parameter_declaration":
        log.fatal(
            f"Wrong node type '{param_decl.type}'. Should be 'parameter_declaration'."
        )
        exit(1)
    return {
        "prim_type": param_decl.children[0].type == "primitive_type",
        "type": param_decl.children[0].text,
        "identifier": param_decl.children[1].text,
    }


def get_text(src: bytes, start_byte: int, end_byte: int) -> bytes:
    """Workaround for https://github.com/tree-sitter/py-tree-sitter/issues/122"""
    return src[start_byte:end_byte]


def get_text_from_node(src: bytes, node: Node) -> bytes:
    return src[node.start_byte : node.end_byte]


def namespace_enum(src: bytes, ns_id: bytes, enum: Node) -> bytes:
    """
    Alters an enum in the way that it prepends the namespace id to every enum member.
    And defines it as a type.
    Example: naemspace_id = "ARM"
             enum { X } -> typedef enum { ARM_X } ARM_enum
    """
    enumerator_list: Node = None
    type_id: Node = None
    primary_tid_set = False
    for c in enum.named_children:
        if c.type == "enumerator_list":
            enumerator_list = c
        elif c.type == "type_identifier" and not primary_tid_set:
            type_id = c
            primary_tid_set = True

    if not enumerator_list and not type_id:
        log.fatal("Could not find enumerator_list or enum type_identifier.")
        exit(1)

    tid = get_text(src, type_id.start_byte, type_id.end_byte) if type_id else None
    elist = get_text(src, enumerator_list.start_byte, enumerator_list.end_byte)
    for e in enumerator_list.named_children:
        if e.type == "enumerator":
            enum_entry_text = get_text(src, e.start_byte, e.end_byte)
            elist = elist.replace(enum_entry_text, ns_id + b"_" + enum_entry_text)

    if tid:
        new_enum = b"typedef enum " + tid + b" " + elist + b"\n " + ns_id + b"_" + tid
    else:
        new_enum = b"enum " + b" " + elist + b"\n"
    return new_enum


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
        # Not a function declaration
        return get_text(src, fcn_def.start_byte, fcn_def.end_byte)
    fcn_id_text = get_text(src, fcn_id.start_byte, fcn_id.end_byte)
    fcn_def_text = get_text(src, fcn_def.start_byte, fcn_def.end_byte)
    res = re.sub(fcn_id_text, ns_id + b"_" + fcn_id_text, fcn_def_text)
    return res


def namespace_struct(src: bytes, ns_id: bytes, struct: Node) -> bytes:
    """
    Defines a struct as a type.
    Example: naemspace_id = "ARM"
             struct id { X } -> typedef struct {  } ARM_id
    """
    type_id: Node = None
    field_list: Node = None
    for c in struct.named_children:
        if c.type == "type_identifier":
            type_id = c
        elif c.type == "base_class_clause":
            # Inheritances should be fixed manually.
            return get_text(src, struct.start_byte, struct.end_byte)
        elif c.type == "field_declaration_list":
            field_list = c

    if not (type_id and field_list):
        log.fatal("Could not find struct type_identifier or field declaration list.")
        exit(1)

    tid = get_text(src, type_id.start_byte, type_id.end_byte)
    fields = get_text(src, field_list.start_byte, field_list.end_byte)

    typed_struct = (
        b"typedef struct " + tid + b" " + fields + b"\n " + ns_id + b"_" + tid
    )
    return typed_struct


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

    from autosync.cpptranslator.TemplateCollector import TemplateCollector

    return (
        TemplateCollector.templ_params_to_list(temp_args),
        st_class_ids,
        ret_type,
        func_name,
        func_params,
        comp_stmt,
    )


def get_capture_node(captures: [(Node, str)], name: str) -> Node:
    """
    Returns the captured node with the given name.
    """
    for c in captures:
        if c[1] == name:
            return c[0]
    fail_exit(f'Capture "{name}" is not in captures:\n{captures}')
