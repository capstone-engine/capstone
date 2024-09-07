# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import logging as log
import re
from pathlib import Path

from tree_sitter import Language, Node, Parser, Query

from autosync.cpptranslator.patches.Helper import get_text


class TemplateRefInstance:
    """
    Represents a concrete instance of a template function reference.
    E.g. DecodeT2Imm7<shift, 2>
    """

    name: bytes
    args: bytes
    args_list: list
    dependent_calls = list()

    # Holds the indices of the caller template parameters which set the templ. parameters
    # of this TemplateCallInstance.
    # Structure: {caller_name: i, "self_i": k}
    #
    # Only used if this is an incomplete TemplateInstance
    # (parameters are set by the template parameters of the calling function).
    caller_param_indices: [{str: int}] = list()

    def __init__(
        self, name: bytes, args: bytes, start_point, start_byte, end_point, end_byte
    ):
        self.name = name
        self.args = args
        self.start_point = start_point
        self.start_byte = start_byte
        self.end_point = end_point
        self.end_byte = end_byte
        self.args_list = TemplateCollector.templ_params_to_list(args)
        self.templ_name = name + args

    def __eq__(self, other):
        return (
            self.name == other.name
            and self.args == other.args
            and any(
                [
                    a == b
                    for a, b in zip(
                        self.caller_param_indices, other.caller_param_indices
                    )
                ]
            )
            and self.start_byte == other.start_byte
            and self.start_point == other.start_point
            and self.end_byte == other.end_byte
            and self.end_point == other.end_point
        )

    def set_dep_calls(self, deps: list):
        self.dependent_calls = deps

    def get_c_name(self):
        return b"_".join([self.name] + self.args_list)

    def get_args_for_decl(self) -> list[bytes]:
        """Returns the list of arguments, but replaces all characters which
        can not be part of a C identifier with _
        """
        args_list = [re.sub(b"'", b"", a) for a in self.args_list]
        return args_list


class TemplateCollector:
    """
    Searches through the given files for calls to template functions.
    And creates a list with concrete template instances.
    """

    # List of completed template instances indexed by their name.
    # One function can have multiple template instances. Depending on the template arguments
    template_refs: {bytes: [TemplateRefInstance]} = dict()
    # List of incomplete template instances indexed by the **function name they depend on**!
    incomplete_template_refs: {bytes: [TemplateRefInstance]} = dict()
    sources: [{str: bytes}] = list()

    def __init__(
        self,
        ts_parser: Parser,
        ts_cpp: Language,
        searchable_files: [Path],
        temp_arg_deduction: [bytes],
    ):
        self.parser = ts_parser
        self.lang_cpp = ts_cpp
        self.searchable_files = searchable_files
        self.templates_with_arg_deduction = temp_arg_deduction

    def collect(self):
        self.read_files()
        for x in self.sources:
            path = x["path"]
            src = x["content"]
            log.debug(f"Search for template references in {path}")

            tree = self.parser.parse(src, keep_text=True)
            query: Query = self.lang_cpp.query(self.get_template_pattern())
            capture_bundles = self.get_capture_bundles(query, tree)

            for cb in capture_bundles:
                templ_name: Node = cb[1][0]
                templ_args: Node = cb[2][0]
                name = get_text(src, templ_name.start_byte, templ_name.end_byte)
                args = get_text(src, templ_args.start_byte, templ_args.end_byte)

                ti = TemplateRefInstance(
                    name,
                    args,
                    cb[0][0].start_point,
                    cb[0][0].start_byte,
                    cb[0][0].end_point,
                    cb[0][0].end_byte,
                )

                log.debug(
                    f"Found new template ref: {name.decode('utf8')}{args.decode('utf8')}"
                )

                if not self.contains_template_dependent_param(src, ti, cb[0]):
                    if name not in self.template_refs:
                        self.template_refs[name] = list()
                    # The template function has no parameter which is part of a previous
                    # template definition. So all template parameters are well-defined.
                    # Add it to the well-defined list.
                    if ti not in self.template_refs[name]:
                        self.template_refs[name].append(ti)
        self.resolve_dependencies()

    def resolve_dependencies(self):
        # Resolve dependencies of templates until nothing new was resolved.
        prev_len = 0
        while (
            len(self.incomplete_template_refs) > 0
            and len(self.incomplete_template_refs) != prev_len
        ):
            # Dict with new template calls which were previously incomplete
            # because one or more parameters were unknown.
            new_completed_tcs: {str: list} = dict()
            tc_instance_list: [TemplateRefInstance]
            for caller_name, tc_instance_list in self.template_refs.items():
                # Check if this caller has a dependent template call.
                # In other words: If a template parameter of this caller is given
                # to another template call in the callers body.
                if caller_name not in self.incomplete_template_refs:
                    # Not in the dependency list. Skip it.
                    continue
                # For each configuration of template parameters we complete a template reference.
                for caller_template in tc_instance_list:
                    incomplete_tc: TemplateRefInstance
                    for incomplete_tc in self.incomplete_template_refs[caller_name]:
                        new_tc: TemplateRefInstance = self.get_completed_tc(
                            caller_template, incomplete_tc
                        )
                        callee_name = new_tc.name
                        if callee_name not in new_completed_tcs:
                            new_completed_tcs[callee_name] = list()
                        if new_tc not in new_completed_tcs[callee_name]:
                            new_completed_tcs[callee_name].append(new_tc)
                del self.incomplete_template_refs[caller_name]

            for templ_name, tc_list in new_completed_tcs.items():
                if templ_name in self.template_refs:
                    self.template_refs[templ_name] += tc_list
                else:
                    self.template_refs[templ_name] = tc_list
            prev_len = len(self.incomplete_template_refs)
        if prev_len > 0:
            log.info(
                f"Unresolved template calls: {self.incomplete_template_refs.keys()}. Patch them by hand!"
            )

    @staticmethod
    def get_completed_tc(
        tc: TemplateRefInstance, itc: TemplateRefInstance
    ) -> TemplateRefInstance:
        new_tc = TemplateRefInstance(
            itc.name,
            itc.args,
            itc.start_byte,
            itc.start_byte,
            itc.end_point,
            itc.end_byte,
        )
        for indices in itc.caller_param_indices:
            if tc.name not in indices:
                # Index of other caller function. Skip.
                continue
            caller_i = indices[tc.name]
            self_i = indices["self_i"]
            new_tc.args_list[self_i] = tc.args_list[caller_i]
            new_tc.args = TemplateCollector.list_to_templ_params(new_tc.args_list)
        new_tc.templ_name = new_tc.name + new_tc.args
        return new_tc

    def contains_template_dependent_param(
        self, src, ti: TemplateRefInstance, parse_tree: (Node, str)
    ) -> bool:
        """Here we check if one of the template parameters of the given template call,
        is a parameter of the callers template definition.

        Let's assume we find the template call `func_B<X>()`.
        Now look at the context `func_B<X>` is in:

        template<X>
        void func_A() {
            func_B<X>(a)
        }

        Since `X` is a template parameter of `func_A` we have to wait until we see a call
        to `func_A<X>` where `X` gets properly defined.

        Until then we save the TemplateInstance of `func_B<X>` in a list of incomplete
        template calls and note that it depends on `func_A`.
        If later a call to function `func_A` is found (with a concrete value for `X`) we can add
        a concrete TemplateInstance of `func_B`.

        :param: src The current source code to operate on.
        :param: ti The TemplateInstance for which to check dependencies.
        :param: parse_tree The parse tree of the template call.
        :return: True if a dependency was found. False otherwise.
        """

        # Search up to the function definition this call belongs to
        node: Node = parse_tree[0]
        while node.type != "function_definition":
            node = node.parent
        if not node.prev_named_sibling.type == "template_parameter_list":
            # Caller is a normal function definition.
            # Nothing to do here.
            return False

        caller_fcn_id = node.named_children[2].named_children[0]
        caller_fcn_name = get_text(
            src, caller_fcn_id.start_byte, caller_fcn_id.end_byte
        )
        caller_templ_params = get_text(
            src, node.prev_sibling.start_byte, node.prev_sibling.end_byte
        )
        pl = TemplateCollector.templ_params_to_list(caller_templ_params)
        has_parameter_dependency = False
        for i, param in enumerate(pl):
            if param in ti.args_list:
                has_parameter_dependency = True
                ti.caller_param_indices.append(
                    {caller_fcn_name: i, "self_i": ti.args_list.index(param)}
                )

        if not has_parameter_dependency:
            return False

        if caller_fcn_name not in self.incomplete_template_refs:
            self.incomplete_template_refs[caller_fcn_name] = list()
        if ti not in self.incomplete_template_refs[caller_fcn_name]:
            self.incomplete_template_refs[caller_fcn_name].append(ti)
        return True

    def read_files(self):
        for sf in self.searchable_files:
            if not Path.exists(sf):
                log.fatal(f"TemplateCollector: Could not find '{sf}' for search.")
                exit(1)
            log.debug(f"TemplateCollector: Read {sf}")
            with open(sf) as f:
                file = {"path": sf, "content": bytes(f.read(), "utf8")}
                self.sources.append(file)

    @staticmethod
    def get_capture_bundles(query, tree):
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(tree.root_node):
            if q[1] == "templ_ref":
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        return captures_bundle

    @staticmethod
    def get_template_pattern():
        """
        :return: A pattern which finds either a template function calls or references.
        """
        return (
            "(template_function"
            "     ((identifier) @name)"
            "     ((template_argument_list) @templ_args)"
            ") @templ_ref"
        )

    @staticmethod
    def templ_params_to_list(templ_params: bytes) -> list[bytes]:
        if not templ_params:
            return list()

        params = templ_params.strip(b"<>").split(b",")
        params = [p.strip() for p in params]
        res = list()
        for p in params:
            if len(p.split(b" ")) == 2:
                # Typename specified for parameter. Remove it.
                # If it was more than one space, it is likely an operation like `size + 1`
                p = p.split(b" ")[1]
            # true and false get resolved to 1 and 0
            if p == "true":
                p = "1"
            elif p == "false":
                p = "0"
            res.append(p)
        return res

    @staticmethod
    def list_to_templ_params(temp_param_list: list) -> bytes:
        return b"<" + b", ".join(temp_param_list) + b">"

    @staticmethod
    def get_macro_c_call(name: bytes, arg_param_list: [bytes], fcn_args: bytes = b""):
        res = b""
        fa = [name] + arg_param_list
        for x in fa[:-1]:
            res += b"CONCAT(" + x + b", "
        res += fa[-1]
        return res + (b")" * (len(fa) - 1)) + fcn_args

    @staticmethod
    def log_missing_ref_and_exit(func_ref: bytes) -> None:
        log.fatal(
            f"Template collector has no reference for {func_ref}.\n\n"
            f"The possible reasons are:\n"
            "\t\t\t- Not all C++ source files which call this function are listed in the config.\n"
            "\t\t\t- You removed the C++ template syntax from the .td file for this function.\n"
            "\t\t\t- The function is a template with argument deduction and has no `template<...>` preamble. "
            "Add it in the config as exception in this case."
        )
        exit(1)
