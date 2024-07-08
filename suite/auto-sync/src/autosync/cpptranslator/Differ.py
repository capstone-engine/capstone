#!/usr/bin/env python3

# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import argparse
import difflib as dl
import json
import logging as log
import subprocess
import sys
import tempfile
from enum import StrEnum
from pathlib import Path
from shutil import copy2

from tree_sitter import Language, Node, Parser, Tree

from autosync.cpptranslator.Configurator import Configurator
from autosync.Helper import (
    bold,
    colored,
    convert_loglevel,
    find_id_by_type,
    get_path,
    get_sha256,
    print_prominent_info,
    print_prominent_warning,
    run_clang_format,
    separator_line_1,
    separator_line_2,
)


class PatchCoord:
    """Holds the coordinate information of tree-sitter nodes."""

    start_byte: int
    end_byte: int
    start_point: tuple[int, int]
    end_point: tuple[int, int]

    def __init__(
        self,
        start_byte: int,
        end_byte: int,
        start_point: tuple[int, int],
        end_point: tuple[int, int],
    ):
        self.start_byte = start_byte
        self.end_byte = end_byte
        self.start_point = start_point
        self.end_point = end_point

    def __lt__(self, other):
        if not (
            (self.start_byte <= other.start_byte and self.end_byte <= other.end_byte)
            or (self.start_byte >= other.start_byte and self.end_byte >= other.end_byte)
        ):
            raise IndexError(
                f"Coordinates overlap. No comparison possible.\n"
                f"a.start_byte = {self.start_byte} a.end_byte = {self.end_byte}\n"
                f"b.start_byte = {other.start_byte} b.end_byte = {other.end_byte}\n"
            )
        return self.end_byte < other.start_byte

    def __str__(self) -> str:
        return f"s: {self.start_byte} e: {self.end_byte}"

    @staticmethod
    def get_coordinates_from_node(node: Node):
        return PatchCoord(
            node.start_byte, node.end_byte, node.start_point, node.end_point
        )


class ApplyType(StrEnum):
    OLD = "OLD"  # Apply version from old file
    NEW = "NEW"  # Apply version from new file (leave unchanged)
    SAVED = "SAVED"  # Use saved resolution
    EDIT = "EDIT"  # Edit patch and apply
    SHOW_EDIT = "SHOW_EDIT"  # Show the saved edited text.
    OLD_ALL = "OLD_ALL"  # Apply all versions from old file.
    PREVIOUS = "PREVIOUS"  # Ignore diff and go to previous


class Patch:
    node_id: str
    coord: PatchCoord
    apply: ApplyType
    old: bytes
    new: bytes
    edit: bytes
    old_hash: str
    new_hash: str

    def __init__(
        self,
        node_id: str,
        old: bytes,
        new: bytes,
        coord: PatchCoord,
        apply: ApplyType,
        edit: bytes = None,
    ) -> None:
        if apply == ApplyType.SAVED:
            raise NotImplementedError("Not yet implemented.")
        self.node_id = node_id
        self.apply = apply
        self.coord = coord
        self.old = old
        self.new = new
        self.edit = edit
        self.old_hash = ""
        self.new_hash = ""
        if self.old:
            self.old_hash = get_sha256(self.old)
        if self.new:
            self.new_hash = get_sha256(self.new)

    def get_persist_info(self) -> dict:
        """Returns a dictionary with the relevant information to back up this patch."""
        backup = dict()
        backup[self.node_id] = dict()
        backup[self.node_id]["apply_type"] = str(self.apply)
        backup[self.node_id]["old_hash"] = self.old_hash
        backup[self.node_id]["new_hash"] = self.new_hash
        backup[self.node_id]["edit"] = self.edit.decode("utf8") if self.edit else ""
        return backup

    def merge(self, other) -> None:
        """
        Merge two patches to one. Necessary if two old nodes are not present in the new file.
        And therefore share PatchCoordinates.
        """
        if other.new:
            raise ValueError("This patch should not have a .new set.")
        if not other.old:
            raise ValueError("No data in .old")
        self.old = other.old + self.old
        self.old_hash = get_sha256(self.old)

    def __lt__(self, other):
        try:
            return self.coord < other.coord
        except IndexError:
            raise IndexError(f"Nodes overlap: {self} - {other}")

    def __str__(self) -> str:
        return f"{self.node_id} @ {self.coord}"


class Differ:
    """
    Diffs the newly translated C++ files against the old version.

    The general diffing works like this:

    The old and the new file get parsed with tree sitter into an AST.
    Then, we extract all nodes of a specific type out of this AST.
    Which nodes specifically is defined in "arch_config.json::General::nodes_to_diff".

    These nodes (old and new separately) are than sorted descending by their coordinates.
    Meaning, nodes at the end in the file come first.
    The identifiers of those nodes are saved in a single list.
    Now we iterate over this list of identifiers. Now we make decisions:

    The node id is present as:
        old node & new node     => Text matches?
                                    yes => Continue
                                    no  => Add new node as Patch (see below)
        only old node           => We save all consecutive old nodes, which have _no_ equivalent new node
                                    and add them as single patch
        only new node           => Add patch

    Now we have the patch. We have a persistence file which saved previous decisions, on which patch to choose.
    We take the node text of the old and new node (or only from a single one) and compare them to our previous decision.
    If the text of the nodes didn't change since the last run, we auto-apply the patch.
    Otherwise, the user decides:
        - Choose the old node text
        - Choose the new node text
        - Open the editor to edit the patch and apply it.
        - Use the stored previous decision.
        - Select always the old nodes.
        - Go back and decide on node before.

    Each decision is saved to the persistence file for later.

    Last (optional) step is to write the patches to the new file.
    Please note that we always write to the new file in the current version.
    """

    ts_cpp_lang: Language = None
    parser: Parser = None
    translated_files: [Path]
    diff_dest_files: [Path] = list()
    old_files: [Path]
    conf_arch: dict
    conf_general: dict
    tree: Tree = None
    persistence_filepath: Path
    saved_patches: dict = None
    patches: list[Patch]

    current_patch: Patch
    cur_old_node: Node | None = None
    cur_new_node: Node | None = None
    cur_nid: str = None

    def __init__(
        self,
        configurator: Configurator,
        no_auto_apply: bool,
        testing: bool = False,
        check_saved: bool = False,
    ):
        self.configurator = configurator
        self.no_auto_apply = no_auto_apply
        self.arch = self.configurator.get_arch()
        self.conf_arch = self.configurator.get_arch_config()
        self.conf_general = self.configurator.get_general_config()
        self.ts_cpp_lang = self.configurator.get_cpp_lang()
        self.parser = self.configurator.get_parser()
        self.differ = dl.Differ()
        self.testing = testing
        self.check_saved = check_saved

        self.diff_out_dir = get_path("{CPP_TRANSLATOR_DIFF_OUT_DIR}")
        if self.testing:
            t_out_dir: Path = get_path("{DIFFER_TEST_NEW_SRC_DIR}")
            self.translated_files = [
                t_out_dir.joinpath(sp["out"])
                for sp in self.conf_arch["files_to_translate"]
            ]
            self.old_files = [
                get_path("{DIFFER_TEST_OLD_SRC_DIR}").joinpath(sp["out"])
                for sp in self.conf_arch["files_to_translate"]
            ]
            self.load_persistence_file()
        else:
            t_out_dir: Path = get_path("{CPP_TRANSLATOR_TRANSLATION_OUT_DIR}")
            self.translated_files = [
                t_out_dir.joinpath(sp["out"])
                for sp in self.conf_arch["files_to_translate"]
            ]
            cs_arch_src: Path = get_path("{CS_ARCH_MODULE_DIR}")
            cs_arch_src = cs_arch_src.joinpath(
                self.arch if self.arch != "PPC" else "PowerPC"
            )
            self.old_files = [
                cs_arch_src.joinpath(f"{cs_arch_src}/" + sp["out"])
                for sp in self.conf_arch["files_to_translate"]
            ]
            self.load_persistence_file()
        if check_saved:
            self.check_saved_patches()
            print("Save file is up-to-date.")

    def load_persistence_file(self) -> None:
        if self.testing:
            self.persistence_filepath = get_path("{DIFFER_TEST_PERSISTENCE_FILE}")
        else:
            self.persistence_filepath = get_path("{DIFFER_PERSISTENCE_FILE}")
        if not self.persistence_filepath.exists():
            self.saved_patches = dict()
            return

        with open(self.persistence_filepath, "rb") as f:
            try:
                self.saved_patches = json.load(f)
            except json.decoder.JSONDecodeError as e:
                log.fatal(
                    f"Persistence file {bold(self.persistence_filepath.name)} corrupt."
                )
                log.fatal("Delete it or fix it by hand.")
                log.fatal(f"JSON Exception: {e}")
                exit(1)

    def save_to_persistence_file(self) -> None:
        print("\nSave choices...\n")
        with open(self.persistence_filepath, "w") as f:
            json.dump(self.saved_patches, f, indent=2)

    def persist_patch(self, filename: Path, patch: Patch) -> None:
        """
        :param filename: The filename this patch is saved for.
        :param patch: The patch to apply.
        """
        if filename.name not in self.saved_patches:
            self.saved_patches[filename.name] = dict()
        log.debug(f"Save: {patch.get_persist_info()}")
        self.saved_patches[filename.name].update(patch.get_persist_info())

    def copy_files(self) -> None:
        """
        Copy translated files to diff directory for editing.
        """
        log.info("Copy files for editing")
        diff_dir: Path = self.diff_out_dir
        for f in self.translated_files:
            dest = diff_dir.joinpath(f.name)
            copy2(f, dest)
            self.diff_dest_files.append(dest)

    def get_diff_intro_msg(
        self,
        old_filename: Path,
        new_filename: Path,
        current: int,
        total: int,
        num_diffs: int,
    ) -> str:
        color_new = self.conf_general["diff_color_new"]
        color_old = self.conf_general["diff_color_old"]
        return (
            f"{bold(f'Diffing files - {current}/{total}')} \n\n"
            + f"{bold('NEW FILE: ', color_new)} {str(new_filename)}\n"
            + f"{bold('OLD FILE: ', color_old)} {str(old_filename)}\n\n"
            + f"{bold('Diffs to process: ')} {num_diffs}\n\n"
            + f"{bold('Changes get written to: ')} {bold('NEW FILE', color_new)}\n"
        )

    def get_diff_node_id(self, node: Node) -> bytes:
        """
        Searches in the nodes children for the identifier node and returns its text.
        """
        id_types = [""]
        for n in self.conf_general["nodes_to_diff"]:
            if n["node_type"] == node.type:
                id_types = n["identifier_node_type"]
        if not id_types:
            log.fatal(
                f"Diffing: Node of type {node.type} has not identifier type specified."
            )
            exit(1)
        identifier = ""
        for id_type in id_types:
            identifier = find_id_by_type(node, id_type.split("/"), False)
            if identifier:
                break
        if not identifier:
            log.fatal(f'Diffing: Cannot find node type "{id_types}" in named-children.')
            exit(1)
        return identifier

    def parse_file(self, file: Path) -> dict[str:Node]:
        """
        Parse a files and return all nodes which should be diffed.
        Nodes are indexed by a unique identifier.
        """
        with open(file) as f:
            content = bytes(f.read(), "utf8")

        tree: Tree = self.parser.parse(content, keep_text=True)

        node_types_to_diff = [
            n["node_type"] for n in self.conf_general["nodes_to_diff"]
        ]
        content = None
        if file.suffix == ".h":
            # Header file. Get the content in between the include guard
            for n in tree.root_node.named_children:
                if n.type == "preproc_ifdef":
                    content = n
                    break
        if not content:
            content = tree.root_node
        duplicates = list()
        nodes_to_diff = dict()
        node: Node
        # Get diff candidates and add them to the dict.
        for node in content.named_children:
            if node.type not in node_types_to_diff:
                continue
            identifier = self.get_diff_node_id(node).decode("utf8")
            if identifier in nodes_to_diff.keys() or identifier in duplicates:
                # This happens if the chosen identifier is not unique.
                log.info(f"Duplicate {bold(identifier)}: Nodes will not be diffed!")
                if identifier in nodes_to_diff.keys():
                    nodes_to_diff.pop(identifier)
                duplicates.append(identifier)
                continue
            log.debug(f"Add node to diff: {identifier}")
            nodes_to_diff[identifier] = node
        return nodes_to_diff

    def print_diff(self, diff_lines: list[str], node_id: str, current: int, total: int):
        new_color = self.conf_general["diff_color_new"]
        old_color = self.conf_general["diff_color_old"]
        print(separator_line_2())
        print(f"{bold('Patch:')} {current}/{total}\n")
        print(f"{bold('Node:')} {node_id}")
        print(f"{bold('Color:')} {colored('NEW FILE - (Just translated)', new_color)}")
        print(
            f"{bold('Color:')} {colored('OLD FILE - (Currently in Capstone)', old_color)}\n"
        )
        print(separator_line_1())
        for line in diff_lines:
            if line[0] == "+":
                print(colored(line, new_color))
            elif line[0] == "-":
                print(colored(line, old_color))
            elif line[0] == "?":
                continue
            else:
                print(line)
        print(separator_line_2())

    @staticmethod
    def no_difference(diff_lines: list[str]) -> bool:
        for line in diff_lines:
            if line[0] != " ":
                return False
        return True

    def print_prompt(
        self, saved_diff_present: bool = False, saved_choice: ApplyType = None
    ) -> str:
        new_color = self.conf_general["diff_color_new"]
        old_color = self.conf_general["diff_color_old"]
        edited_color = self.conf_general["diff_color_edited"]
        saved_selection = self.get_saved_choice_prompt(saved_diff_present, saved_choice)

        choice = input(
            f"Choice: {colored('O', old_color)}, {bold('o', old_color)}, {bold('n', new_color)}, "
            f"{saved_selection}, {colored('e', edited_color)}, {colored('E', edited_color)}, p, q, ? > "
        )
        return choice

    def get_saved_choice_prompt(
        self, saved_diff_present: bool = False, saved_choice: ApplyType = None
    ):
        new_color = self.conf_general["diff_color_new"]
        old_color = self.conf_general["diff_color_old"]
        edited_color = self.conf_general["diff_color_edited"]
        saved_color = (
            self.conf_general["diff_color_saved"] if saved_diff_present else "dark_grey"
        )
        saved_selection = f"{bold('s', saved_color)}"
        if saved_choice == ApplyType.OLD:
            saved_selection += f" ({colored('old', old_color)}) "
        elif saved_choice == ApplyType.NEW:
            saved_selection += f" ({colored('new', new_color)}) "
        elif saved_choice == ApplyType.EDIT:
            saved_selection += f" ({colored('edited', edited_color)}) "
        elif not saved_choice:
            saved_selection += f" ({colored('none', 'dark_grey')}) "
        return saved_selection

    def print_prompt_help(
        self, saved_diff_present: bool = False, saved_choice: ApplyType = None
    ) -> None:
        new_color = self.conf_general["diff_color_new"]
        old_color = self.conf_general["diff_color_old"]
        edited_color = self.conf_general["diff_color_edited"]
        saved_choice = self.get_saved_choice_prompt(saved_diff_present, saved_choice)

        print(
            f"{colored('O', old_color)}\t\t- Accept ALL old diffs\n"
            f"{bold('o', old_color)}\t\t- Accept old diff\n"
            f"{bold('n', new_color)}\t\t- Accept new diff\n"
            f"{colored('e', edited_color)}\t\t- Edit diff (not yet implemented)\n"
            f"{saved_choice}\t- Select saved choice\n"
            f"p\t\t- Ignore and go to previous diff\n"
            f"q\t\t- Quit (previous selections will be saved)\n"
            f"?\t\t- Show this help\n\n"
        )

    def get_user_choice(
        self, saved_diff_present: bool, saved_choice: ApplyType
    ) -> ApplyType:
        while True:
            choice = self.print_prompt(saved_diff_present, saved_choice)
            if choice not in ["O", "o", "n", "e", "E", "s", "p", "q", "?", "help"]:
                print(f"{bold(choice)} is not valid.")
                self.print_prompt_help(saved_diff_present, saved_choice)
                continue

            if choice == "q":
                print(f"{bold('Quit...')}")
                self.save_to_persistence_file()
                exit(0)
            elif choice == "o":
                return ApplyType.OLD
            elif choice == "n":
                return ApplyType.NEW
            elif choice == "O":
                return ApplyType.OLD_ALL
            elif choice == "e":
                return ApplyType.EDIT
            elif choice == "E":
                return ApplyType.SHOW_EDIT
            elif choice == "s":
                return ApplyType.SAVED
            elif choice in ["?", "help"]:
                self.print_prompt_help(saved_diff_present, saved_choice)
                continue
            elif choice == "p":
                return ApplyType.PREVIOUS

    def saved_patch_matches(self, saved: dict) -> bool:
        if self.cur_old_node:
            old_hash = get_sha256(self.cur_old_node.text)
        else:
            old_hash = ""
        if self.cur_new_node:
            new_hash = get_sha256(self.cur_new_node.text)
        else:
            new_hash = ""
        return saved["old_hash"] == old_hash and saved["new_hash"] == new_hash

    def create_patch(
        self,
        coord: PatchCoord,
        choice: ApplyType,
        saved_patch: dict = None,
        edited_text: bytes = None,
    ):
        old = self.cur_old_node.text if self.cur_old_node else b""
        new = self.cur_new_node.text if self.cur_new_node else b""
        return Patch(
            self.cur_nid,
            old,
            new,
            coord,
            saved_patch["apply_type"] if saved_patch else choice,
            edit=edited_text,
        )

    def add_patch(
        self,
        apply_type: ApplyType,
        consec_old: int,
        old_filepath: Path,
        patch_coord: PatchCoord,
        saved_patch: dict | None = None,
        edited_text: bytes | None = None,
    ) -> None:
        self.current_patch = self.create_patch(
            patch_coord, apply_type, saved_patch, edited_text
        )
        self.persist_patch(old_filepath, self.current_patch)
        if consec_old > 1:
            # Two or more old nodes are not present in the new file.
            # Merge them to one patch.
            self.patches[-1].merge(self.current_patch)
        else:
            self.patches.append(self.current_patch)

    def diff_nodes(
        self,
        old_filepath: Path,
        new_nodes: dict[bytes, Node],
        old_nodes: dict[bytes, Node],
    ) -> list[Patch]:
        """
        Asks the user for each different node, which version should be written.
        It writes the choice to a file, so the previous choice can be applied again if nothing changed.
        """
        # Sort list of nodes descending.
        # This is necessary because
        #   a) we need to apply the patches backwards (starting from the end of the file,
        #      so the coordinates in the file don't change, when replace text).
        #   b) If there is an old node, which is not present in the new file, we search for
        #      a node which is adjacent (random node order wouldn't allow this).
        new_nodes = {
            k: v
            for k, v in sorted(
                new_nodes.items(), key=lambda item: item[1].start_byte, reverse=True
            )
        }
        old_nodes = {
            k: v
            for k, v in sorted(
                old_nodes.items(), key=lambda item: item[1].start_byte, reverse=True
            )
        }

        # Collect all node ids of this file
        node_ids = set()
        for new_node_id, old_node_id in zip(new_nodes.keys(), old_nodes.keys()):
            node_ids.add(new_node_id)
            node_ids.add(old_node_id)

        # The initial patch coordinates point after the last node in the file.
        n0 = new_nodes[list(new_nodes.keys())[0]]
        PatchCoord(n0.end_byte, n0.end_byte, n0.end_point, n0.end_point)

        node_ids = sorted(node_ids)
        self.patches = list()
        matching_nodes_count = 0
        # Counts the number of _consecutive_ old nodes which have no equivalent new node.
        # They will be merged to a single patch later
        consec_old = 0
        choice: ApplyType | None = None
        idx = 0
        while idx < len(node_ids):
            self.cur_nid = node_ids[idx]
            self.cur_new_node = (
                None if self.cur_nid not in new_nodes else new_nodes[self.cur_nid]
            )
            self.cur_old_node = (
                None if self.cur_nid not in old_nodes else old_nodes[self.cur_nid]
            )

            n = (
                self.cur_new_node.text.decode("utf8").splitlines()
                if self.cur_new_node
                else [""]
            )
            o = (
                self.cur_old_node.text.decode("utf8").splitlines()
                if self.cur_old_node
                else [""]
            )

            diff_lines = list(self.differ.compare(o, n))
            if self.no_difference(diff_lines):
                log.info(
                    f"{bold('Patch:')} {idx + 1}/{len(node_ids)} - Nodes {bold(self.cur_nid)} match."
                )
                matching_nodes_count += 1
                idx += 1
                continue

            if self.cur_new_node:
                consec_old = 0
                # We always write to the new file. So we always take he coordinates form it.
                patch_coord = PatchCoord.get_coordinates_from_node(self.cur_new_node)
            else:
                consec_old += 1
                # If the old node has no equivalent new node,
                # we search for the next adjacent old node which exist also in new nodes.
                # The single old node is insert before the found new one.
                old_node_ids = list(old_nodes.keys())
                j = old_node_ids.index(self.cur_nid)
                while j >= 0 and (old_node_ids[j] not in new_nodes.keys()):
                    j -= 1
                ref_new: Node = (
                    new_nodes[old_node_ids[j]]
                    if old_node_ids[j] in new_nodes.keys()
                    else new_nodes[0]
                )
                ref_end_byte = ref_new.start_byte
                # We always write to the new file. So we always take he coordinates form it.
                patch_coord = PatchCoord(
                    ref_end_byte - 1,
                    ref_end_byte - 1,
                    ref_new.start_point,
                    ref_new.start_point,
                )

            save_exists = False
            saved: dict | None = None
            if (
                old_filepath.name in self.saved_patches
                and self.cur_nid in self.saved_patches[old_filepath.name]
            ):
                saved = self.saved_patches[old_filepath.name][self.cur_nid]
                save_exists = True
                if self.saved_patch_matches(saved) and not self.no_auto_apply:
                    apply_type = ApplyType(saved["apply_type"])
                    self.add_patch(apply_type, consec_old, old_filepath, patch_coord)
                    log.info(
                        f"{bold('Patch:')} {idx + 1}/{len(node_ids)} - Auto apply patch for {bold(self.cur_nid)}"
                    )
                    idx += 1
                    continue

            if choice == ApplyType.OLD_ALL:
                self.add_patch(ApplyType.OLD, consec_old, old_filepath, patch_coord)
                idx += 1
                continue

            self.print_diff(diff_lines, self.cur_nid, idx + 1, len(node_ids))
            choice = self.get_user_choice(
                save_exists, None if not saved else saved["apply_type"]
            )
            if choice == ApplyType.OLD:
                if not self.cur_old_node:
                    # No data in old node. Skip
                    idx += 1
                    continue
                self.add_patch(ApplyType.OLD, consec_old, old_filepath, patch_coord)
            elif choice == ApplyType.NEW:
                # Already in file. Only save patch.
                self.persist_patch(old_filepath, self.create_patch(patch_coord, choice))
            elif choice == ApplyType.SAVED:
                if not save_exists:
                    print(bold("Save does not exist."))
                    continue
                self.add_patch(
                    saved["apply_type"],
                    consec_old,
                    old_filepath,
                    patch_coord,
                    saved_patch=saved,
                    edited_text=saved["edit"].encode(),
                )
            elif choice == ApplyType.SHOW_EDIT:
                if not saved or not saved["edit"]:
                    print(bold("No edited text was saved before."))
                    input("Press enter to continue...\n")
                    continue
                saved_edited_text = colored(
                    f'\n{saved["edit"]}\n', self.conf_general["diff_color_edited"]
                )
                print(saved_edited_text)
                input("Press enter to continue...\n")
                continue
            elif choice == ApplyType.OLD_ALL:
                self.add_patch(ApplyType.OLD, consec_old, old_filepath, patch_coord)
            elif choice == ApplyType.EDIT:
                edited_text = self.edit_patch(diff_lines)
                if not edited_text:
                    continue
                self.persist_patch(
                    old_filepath,
                    self.create_patch(patch_coord, choice, edited_text=edited_text),
                )
            elif choice == ApplyType.PREVIOUS:
                if idx == 0:
                    print(bold(f"There is no previous diff for {old_filepath.name}!"))
                    input("Press enter...")
                    continue
                idx -= 1
                continue
            idx += 1
        log.info(f"Number of matching nodes = {matching_nodes_count}")
        return self.patches

    def diff(self) -> None:
        """
        Diffs certain nodes from the newly translated and old source files to each other.
        The user then selects which diff should be written to the new file.
        """

        # We do not write to the translated files directly.
        self.copy_files()
        new_file = dict()
        old_file = dict()
        i = 0
        for old_filepath, new_filepath in zip(self.old_files, self.diff_dest_files):
            new_file[i] = dict()
            new_file[i]["filepath"] = new_filepath
            new_file[i]["nodes"] = self.parse_file(new_filepath)

            old_file[i] = dict()
            old_file[i]["filepath"] = old_filepath
            old_file[i]["nodes"] = self.parse_file(old_filepath)
            i += 1

        patches = dict()
        # diff each file
        for k in range(i):
            old_filepath = old_file[k]["filepath"]
            new_filepath = new_file[k]["filepath"]
            diffs_to_process = max(len(new_file[k]["nodes"]), len(old_file[k]["nodes"]))
            print_prominent_info(
                self.get_diff_intro_msg(
                    old_filepath, new_filepath, k + 1, i, diffs_to_process
                )
            )
            if diffs_to_process == 0:
                continue
            patches[new_filepath] = self.diff_nodes(
                old_filepath, new_file[k]["nodes"], old_file[k]["nodes"]
            )
        self.patch_files(patches)
        self.save_to_persistence_file()
        log.info("Done")

    def patch_files(self, file_patches: dict[Path, list[Patch]]) -> None:
        log.info("Write patches...")
        for filepath, patches in file_patches.items():
            patches = sorted(patches, reverse=True)
            with open(filepath, "rb") as f:
                src = f.read()
            patch: Patch
            for patch in patches:
                start_byte = patch.coord.start_byte
                end_byte = patch.coord.end_byte
                if patch.apply == ApplyType.OLD:
                    data = patch.old
                elif patch.apply == ApplyType.NEW:
                    data = patch.new
                elif patch.apply == ApplyType.EDIT:
                    data = patch.edit
                else:
                    print_prominent_warning(f"No data for {patch.apply} defined.")
                    return
                src = src[:start_byte] + data + src[end_byte:]
            with open(filepath, "wb") as f:
                f.write(src)
        run_clang_format(list(file_patches.keys()))
        return

    def edit_patch(self, diff_lines: list[str]) -> bytes | None:
        tmp_file = tempfile.NamedTemporaryFile(suffix="c", delete=False)
        tmp_file_name = tmp_file.name
        tmp_file.writelines([line.encode() + b"\n" for line in diff_lines])
        tmp_file.write(self.get_edit_explanation())
        tmp_file.close()
        editor = self.conf_general["patch_editor"]
        try:
            subprocess.run([editor, tmp_file_name])
        except FileNotFoundError:
            log.error(f"Could not find editor '{editor}'")
            return None
        edited_text = b""
        with open(tmp_file_name, "rb") as tmp_file:
            for line in tmp_file.readlines():
                if self.get_separator_line() in line:
                    break
                edited_text += line
        tmp_file.close()
        return edited_text

    @staticmethod
    def get_separator_line() -> bytes:
        return f"// {'=' * 50}".encode()

    def get_edit_explanation(self) -> bytes:
        return (
            f"{self.get_separator_line().decode('utf8')}\n"
            "// Everything below this line will be deleted\n"
            "// Edit the file to your liking. The result will be written 'as is' to the source file.\n"
        ).encode()

    def check_saved_patches(self):
        new_file = dict()
        old_file = dict()
        i = 0
        for old_filepath, new_filepath in zip(self.old_files, self.translated_files):
            new_file[i] = {
                "filepath": new_filepath,
                "nodes": self.parse_file(new_filepath),
            }
            old_file[i] = {
                "filepath": old_filepath,
                "nodes": self.parse_file(old_filepath),
            }
            i += 1

        # diff each file
        for k in range(i):
            old_filepath = old_file[k]["filepath"]
            diffs_to_process = max(len(new_file[k]["nodes"]), len(old_file[k]["nodes"]))
            if diffs_to_process == 0:
                continue
            filename, node_id = self.all_choices_saved(
                old_filepath, new_file[k]["nodes"], old_file[k]["nodes"]
            )
            if filename or node_id:
                print(
                    f"{get_path('{DIFFER_PERSISTENCE_FILE}').name} is not up-to-date!\n"
                    f"{filename} still requires a user decision for node {node_id}.\n"
                    f"If the file is good as it is, "
                    f"commit any changes to it and run the Differ again and choose 'O' to save them."
                )
                exit(1)

    def all_choices_saved(
        self, old_filepath, new_nodes, old_nodes
    ) -> tuple[str, str] | tuple[None, None]:
        """Returns the a (filename, node_id) which is not saved in the save file. Or None, if everything is ok."""
        if old_filepath.name not in self.saved_patches:
            return old_filepath.name, None

        new_nodes = {
            k: v
            for k, v in sorted(
                new_nodes.items(), key=lambda item: item[1].start_byte, reverse=True
            )
        }
        old_nodes = {
            k: v
            for k, v in sorted(
                old_nodes.items(), key=lambda item: item[1].start_byte, reverse=True
            )
        }

        # Collect all node ids of this file
        node_ids = set()
        for new_node_id, old_node_id in zip(new_nodes.keys(), old_nodes.keys()):
            node_ids.add(new_node_id)
            node_ids.add(old_node_id)

        for self.cur_nid in node_ids:
            self.cur_new_node = (
                None if self.cur_nid not in new_nodes else new_nodes[self.cur_nid]
            )
            self.cur_old_node = (
                None if self.cur_nid not in old_nodes else old_nodes[self.cur_nid]
            )
            if (
                old_filepath.name in self.saved_patches
                and self.cur_nid in self.saved_patches[old_filepath.name]
            ):
                saved = self.saved_patches[old_filepath.name][self.cur_nid]
                if not self.saved_patch_matches(saved):
                    return old_filepath.name, self.cur_nid
        return None, None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Differ",
        description="Diffs translated C++ files to previous version.",
    )
    parser.add_argument(
        "-e",
        dest="no_auto_apply",
        help="Do not apply saved diff resolutions. Ask for every diff again.",
        action="store_true",
    )
    parser.add_argument(
        "-a",
        dest="arch",
        help="Name of target architecture (ignored with -t option)",
        choices=["ARM", "PPC", "AArch64", "Alpha"],
        required=True,
    )
    parser.add_argument(
        "-v",
        dest="verbosity",
        help="Verbosity of the log messages.",
        choices=["debug", "info", "warning", "fatal"],
        default="info",
    )
    parser.add_argument(
        "-t", dest="testing", help="Run with test configuration.", action="store_true"
    )
    parser.add_argument(
        "--check_saved",
        dest="check_saved",
        help=f"Check if patches in {get_path('{DIFFER_PERSISTENCE_FILE}')} is up-to-date.",
        action="store_true",
    )
    arguments = parser.parse_args()
    return arguments


if __name__ == "__main__":
    if not sys.hexversion >= 0x030B00F0:
        log.fatal("Python >= v3.11 required.")
        exit(1)
    args = parse_args()
    log.basicConfig(
        level=convert_loglevel(args.verbosity),
        stream=sys.stdout,
        format="%(levelname)-5s - %(message)s",
    )
    if args.testing:
        cfg = Configurator("ARCH", get_path("{DIFFER_TEST_CONFIG_FILE}"))
    else:
        cfg = Configurator(args.arch, get_path("{CPP_TRANSLATOR_CONFIG}"))

    differ = Differ(
        cfg, args.no_auto_apply, testing=args.testing, check_saved=args.check_saved
    )
    if args.check_saved:
        exit(0)

    try:
        differ.diff()
    except Exception as e:
        differ.save_to_persistence_file()
        raise e
