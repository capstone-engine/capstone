import hashlib
import logging as log
import re
import shutil
import subprocess
import sys
from pathlib import Path

import termcolor

from PathVarHandler import PathVarHandler
from tree_sitter import Node


def convert_loglevel(level: str) -> int:
    if level == "debug":
        return log.DEBUG
    elif level == "info":
        return log.INFO
    elif level == "warning":
        return log.WARNING
    elif level == "error":
        return log.ERROR
    elif level == "fatal":
        return log.FATAL
    elif level == "critical":
        return log.CRITICAL
    raise ValueError(f'Unknown loglevel "{level}"')


def find_id_by_type(node: Node, node_types: [str], type_must_match: bool) -> bytes:
    """
    Recursively searches for a node sequence with given node types.

    A valid sequence is a path from !\f$node_n\f$ to !\f$node_{(n + |node\_types|-1)}\f$ where
    !\f$\forall i \in \{0, ..., |node\_types|-1\}: type(node_{(n + i)}) = node\_types_i\f$.

    If a node sequence is found, this functions returns the text associated with the
    last node in the sequence.

    :param node: Current node.
    :param node_types: List of node types.
    :param type_must_match: If true, it is mandatory for the current node that its type matches node_types[0]
    :return: The nodes text of the last node in a valid sequence of and empty string of no such sequence exists.
    """
    if len(node_types) == 0:
        # No ids left to compare to: Nothing found
        return b""

    # Set true if:
    #     current node type matches.
    #  OR
    #     parent dictates that node type match
    type_must_match = node.type == node_types[0] or type_must_match
    if type_must_match and node.type != node_types[0]:
        # This child has no matching type. Return.
        return b""

    if len(node_types) == 1 and type_must_match:
        if node.type == node_types[0]:
            # Found it
            return node.text
        else:
            # Not found. Return to parent
            return b""

    # If this nodes type matches the first in the list
    # we remove this one from the list.
    # Otherwise, give the whole list to the child (since our type does not matter).
    children_id_types = node_types[1:] if type_must_match else node_types

    # Check if any child has a matching type.
    for child in node.named_children:
        res = find_id_by_type(child, children_id_types, type_must_match)
        if res:
            # A path from this node matches the id_types!
            return res

    # None of our children matched the type list.
    return b""


def print_prominent_warning(msg: str) -> None:
    print("\n" + separator_line_1("yellow"))
    print(termcolor.colored("WARNING", "yellow", attrs=["bold"]) + "\n")
    print(msg)
    print(separator_line_1("yellow"))
    input("Press enter to continue...\n")


def term_width() -> int:
    return shutil.get_terminal_size()[0]


def print_prominent_info(msg: str) -> None:
    print("\n" + separator_line_1("blue"))
    print(msg)
    print(separator_line_1("blue"))
    input("Press enter to continue...\n")


def bold(msg: str, color: str = None) -> str:
    if color:
        return termcolor.colored(msg, attrs=["bold"], color=color)
    return termcolor.colored(msg, attrs=["bold"])


def colored(msg: str, color: str) -> str:
    return termcolor.colored(msg, color=color)


def separator_line_1(color: str = None) -> str:
    return f"{bold(f'⎼' * int(term_width() / 2), color)}\n"


def separator_line_2(color: str = None) -> str:
    return f"{bold(f'═' * int(term_width() / 2), color)}\n"


def get_sha256(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def get_header() -> str:
    commit = get_llvm_commit()
    tag = get_llvm_tag()
    header = (
        "/* Capstone Disassembly Engine, https://www.capstone-engine.org */\n"
        "/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */\n"
        "/*    Rot127 <unisono@quyllur.org> 2022-2023 */\n"
        "/* Automatically translated source file from LLVM. */\n\n"
        f"/* LLVM-commit: {commit} */\n"
        f"/* LLVM-tag: {tag} */\n\n"
        "/* Only small edits allowed. */\n"
        "/* For multiple similar edits, please create a Patch for the translator. */\n\n"
        "/* Capstone's C++ file translator: */\n"
        "/* https://github.com/capstone-engine/capstone/tree/next/suite/auto-sync */\n\n"
    )

    return header


def get_llvm_commit() -> str:
    llvm_dir = PathVarHandler().get_path("{LLVM_ROOT}")
    r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=llvm_dir, capture_output=True)
    return r.stdout.decode("utf8").strip()


def get_llvm_tag() -> str:
    llvm_dir = PathVarHandler().get_path("{LLVM_ROOT}")
    commit = get_llvm_commit()
    r = subprocess.run(["git", "describe", "--all", "--tags", commit], cwd=llvm_dir, capture_output=True)
    return r.stdout.split(b"/")[-1].decode("utf8").strip()


def run_clang_format(out_paths: list[Path]):
    for out_file in out_paths:
        log.info(f"Format {out_file}")
        subprocess.run(["clang-format-18", f"-style=file:{get_path('{CS_CLANG_FORMAT_FILE}')}", "-i", out_file])


def get_path(config_path: str) -> Path:
    return PathVarHandler().complete_path(config_path)


def fail_exit(msg: str) -> None:
    """Logs a fatal message and exits with error code 1."""
    log.fatal(msg)
    exit(1)


def check_py_version() -> None:
    if not sys.hexversion >= 0x030B00F0:
        log.fatal("Python >= v3.11 required.")
        exit(1)


def replace_in_file(file_path: Path, pattern: str, replacement: str):
    out = []
    with open(file_path) as f:
        lines = f.readlines()
    for l in lines:
        out.append(re.sub(pattern, replacement, l))
    with open(file_path, "w") as f:
        f.writelines(out)
    return f
