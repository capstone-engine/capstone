#!/usr/bin/env python3

from pathlib import Path

import argparse
import re
import os


def cwd():
    """Return current working directory."""
    return os.path.dirname(os.path.realpath(__file__))


def fatal_error(msg: str) -> None:
    """Prints an error message and exists with error code 1."""
    print(f"[x] {msg}")
    exit(1)


def warn(msg: str) -> None:
    """Prints a warning message."""
    print(f"[!] {msg}")


def info(msg: str) -> None:
    """Prints an info message."""
    print(f"[*] {msg}")


def check_paths(llvm_dir: Path, arch: str) -> None:
    """Checks all relevant directories for errors and if they exist."""
    if not llvm_dir.exists():
        fatal_error(f"{llvm_dir} does not exist.")

    if not llvm_dir.is_dir():
        fatal_error(f"{llvm_dir} is not a directory.")

    out_dir: Path = Path(cwd()).joinpath(arch)
    if not out_dir.exists():
        fatal_error(f"Output directory {out_dir} does not exist.")

    if not out_dir.is_dir():
        fatal_error(f"Output directory {out_dir} is not a directory.")

    arch_dir = llvm_dir.joinpath(arch)
    if not arch_dir.exists():
        fatal_error(f"Test file directory {arch_dir} does not exist.")

    if not arch_dir.is_dir():
        fatal_error(f"Test file directory {arch_dir} is not a directory.")


def get_included_files(
    arch_dir: Path,
    out_path: Path,
    included_files: set[str],
    excluded_files: set[str] = None,
) -> list[tuple[Path, Path]]:
    """
    Generates the file list to update. Only the files listed
    via command line arguments are added.
    """
    files = list()
    file: Path
    for file in arch_dir.iterdir():
        stem = file.stem
        if stem not in included_files:
            continue
        if excluded_files and stem in excluded_files:
            included_files.remove(stem)
            continue

        included_files.remove(stem)
        files.append((file, out_path.joinpath(file.name + ".cs")))

    if len(included_files) != 0:
        warn(
            f"Could not find {', '.join(included_files)} in the LLVM test files."
        )

    return files


def get_all_files(
    arch_dir: Path,
    out_path: Path,
    excluded_files: set[str] = None,
) -> list[tuple[Path, Path]]:
    """
    Generates the file list to update. All files of an
    architecture are added.
    """
    files = list()
    file: Path
    for file in arch_dir.iterdir():
        stem = file.stem
        if excluded_files and stem in excluded_files:
            continue

        files.append((file, out_path.joinpath(file.name + ".cs")))
    return files


def get_file_list(
    llvm_dir: Path,
    arch: str = None,
    excluded_files: set[str] = None,
    included_files: set[str] = None,
) -> list[tuple[Path, Path]]:
    """
    Generates a list of files to update.
    The list contains tuples of the form: (llvm_file_path, cs_file_path)
    """

    out_dir: Path = Path(cwd()).joinpath(arch)
    arch_dir = llvm_dir.joinpath(arch)

    if included_files and len(included_files) != 0:
        return get_included_files(
            arch_dir, out_dir, included_files, excluded_files
        )
    return get_all_files(arch_dir, out_dir, excluded_files)


def create_new_test_file(arch: str, cs_file: Path) -> str:
    """
    Creates a new test files and asks for the tesst parameter for it.
    :return: The test parameter string.
    """
    info(f"Add new test file: {cs_file}")
    info("You need to provide the test parameters for it.")
    test_parameters = f"# CS_ARCH_{arch.upper()}, "
    test_parameters += input(
        "\nAdd architecture mode of tests"
        "(CS_MODE_THUMB, CS_MODE_BIG_ENDIAN, ...)\n"
        "> "
    )
    test_parameters += ", "
    test_parameters += input(
        "\nAdd disassembly options for this test file"
        "(CS_OPT_SYNTAX_NOREGNAME, CS_OPT_SYNTAX_ATT, None, ...)\n"
        "> "
    )
    test_parameters += "\n"
    cs_file.touch()
    return test_parameters


def get_test_parameters(cs_file: Path) -> str:
    """
    Extracts the test parameters string from
    an existing Capstone test file.
    """
    with open(cs_file) as f:
        line = f.readline()

    # Check for "# CS_ARCH_<ARCH>, CS_MODE_<MODE>, ..." lines
    regex = r"#\s*CS_ARCH_.+,\s*CS_MODE_.+,\s*.+"
    if not re.search(regex, line):
        fatal_error(
            f"The first line in {cs_file} is not "
            f"the test parameter line.\nLine: {line}"
        )
    return line


def decimal_to_hex_fix(asm: str) -> str:
    """
    Replaces every immediate number in the asm string with its hex form.
    If it is larger than the hex threshold.
    """
    # Defined in utils.h
    hex_threshold = 9
    matches = re.findall(r"([#\s]-?\d+)", asm)
    if not matches:
        return asm

    for m in matches:
        num = int(m[1:])
        neg_num = num < 0
        sign = ""
        if neg_num:
            num = num * -1
            sign = "-"
        if num < hex_threshold:
            continue
        prefix = m[0]
        asm = re.sub(m, rf"{prefix}{sign}{hex(num)}", asm)
    return asm


def extract_tests(llvm_file: Path) -> str:
    """
    Extracts all compatible test cases in the given llvm_file
    and returns them as string.
    """
    hex_encoding = r"(0x[a-fA-F0-9][a-fA-F0-9],?\s*)+"
    asm_regex = r"(.*)"

    test_case_patterns = [
        rf"#?\s*@?\s*CHECK:\s+{asm_regex}\s+@\s+encoding:\s+\[({hex_encoding})\]",
    ]

    result = ""

    if llvm_file.is_dir():
        return result

    f = open(llvm_file)
    for line in f.readlines():
        match = list()
        for regex in test_case_patterns:
            match: list = re.findall(regex, line)
            if match:
                break
        if not match:
            continue
        match = match[0]
        asm = re.sub(r"\s+", " ", match[0])
        asm = asm.strip(" ")
        asm = decimal_to_hex_fix(asm)
        hexbytes = re.sub(r"\s", "", match[1])
        result += f"{hexbytes} = {asm}\n"
    f.close()
    return result


def update(
    llvm_dir: Path,
    arch: str,
    excluded_files: set[str] = None,
    included_files: set[str] = None,
) -> None:
    """
    Updates all regression test files for Capstone.
    """

    check_paths(llvm_dir, arch)

    files: list[tuple[Path, Path]] = get_file_list(
        llvm_dir, arch, excluded_files, included_files
    )

    for file in files:
        llvm_file = file[0]
        cs_file = file[1]

        cs_tests = extract_tests(llvm_file)
        if cs_tests == "":
            continue

        if not cs_file.exists():
            test_parameters = create_new_test_file(arch, cs_file)
        else:
            test_parameters = get_test_parameters(cs_file)

        with open(cs_file, "w") as f:
            f.write(test_parameters)
            f.write(cs_tests)
    info("Update done")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Test file updater",
        description="Synchronizes test files with LLVM",
    )
    parser.add_argument(
        "-d",
        dest="llvm_dir",
        help="Path to the LLVM MC Disassembler test files.",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "-a",
        dest="arch",
        help="Name of architecture to update.",
        choices=["ARM"],
        required=True,
    )
    parser.add_argument(
        "-e",
        dest="excluded_files",
        metavar="filename",
        nargs="+",
        help="File names to exclude from update (without file extension).",
        type=list,
    )
    parser.add_argument(
        "-f",
        dest="included_files",
        metavar="filename",
        nargs="+",
        help="Specific list of file names to update (without file extension).",
    )
    arguments = parser.parse_args()
    return arguments


if __name__ == "__main__":
    args = parse_args()
    update(args.llvm_dir, args.arch, args.excluded_files, args.included_files)
