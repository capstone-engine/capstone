#!/usr/bin/env python3
# Copyright © 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3
import argparse
import re
from enum import Enum
from pathlib import Path

from autosync.Helper import get_path

# The CHECK prefix for tests.
CHECK = r"((#|//)\s*CHECK(-NEXT)?:)"
ASM = r"(?P<asm_text>[^/@]+)"
ENC = r"(\[?(?P<enc_bytes>(0x[a-fA-F0-9]{2}[, ]?)+)\]?)"
match_patterns = {
    # A commented encoding with only CHECK or something similar in front of it, skip it.
    "skip_pattern": rf"(^((#|//)\s*[-A-Z0-9]+):\s*{ENC}\s*$)|"
    f"(warning: invalid instruction encoding)",
    # The encoding bytes pattern is in every file the same.
    # But the disassembler and assembler tests pre-fix them differently.
    # This is only the pattern for the encoding bytes. Without any prefix.
    #
    # The bytes are encoded with `0x` prefix and every byte is separated with a `,` or ` `.
    # Optionally, they are enclosed in `[0x10,...]` brackets.
    # E.g.: `[0x01,0xaa,0xb1,0x81]` or `0x01,0xaa,0xb1,0x81`.
    # In the disassembler tests they don't have any prefix.
    # In assembler tests they might have different prefixes like `CHECK-ENCODING`
    # The matched bytes can be accessed from the group "enc_bytes"
    "enc_bytes": ENC,
    # Encodings in disassembly tests can have several prefixes
    "enc_prefix_disas":
    # start of line with CHECK: ... prefix
    r"((\s*)|"
    # start of line with `CHECK: ...` prefix and the encoding after the asm text.
    rf"({CHECK}.+encoding:\s+))",
    # The asm checking line for `MC/Disassembler/*` tests follows the pattern:
    # `# CHECK: <asm-text>`
    # Usually multiple 'CHECK' come before or after the encoding bytes.
    # Meaning: first comes a block of `# CHECK: ...` and afterwards for every `# CHECK: ...`
    # line the encoding bytes.
    # And wise versa, with the encoding bytes first and afterwards the asm text checks.
    # The matched asm text can be accessed from the group "asm_text"
    "asm_check": rf"{CHECK}\s+{ASM}(\s*(#|//)\s+encoding:\s+{ENC})?",
    # Single line disassembly test
    "single_line_disas": rf"^{ENC}\s+#\s+{ASM}|"
    # Match against:
    # @ CHECK: xxx @ encoding: [xx, xx]
    rf"#?\s*@?\s*CHECK:\s+{ASM}\s+@\s+encoding:\s+\[({ENC})\]|"
    # Match against:
    # # CHECK-INST: xxx
    # # CHECK-ENCODING: encoding: [xx, xx]
    rf"#\s+CHECK-INST:\s+{ASM}\n#\s+CHECK-ENCODING:\s+encoding:\s+\[({ENC})\]|"
    # Match against:
    # # CHECK-ASM-AND-OBJ: xxx
    # # CHECK-ASM: encoding: [xx, xx]
    rf"#\s+CHECK-ASM-AND-OBJ:\s+{ASM}\n#\s+CHECK-ASM:\s+encoding:\s+\[({ENC})\]|"
    # Match against:
    # # ASM-AND-OBJ: xxx
    # # ASM: encoding: [xx, xx]
    rf"#\s+ASM-AND-OBJ:\s+{ASM}\n#\s+ASM:\s+encoding:\s+\[({ENC})\]",
    # The RUN line, with the command to run the test file, contains sometimes the `mattr` flags.
    # These are relevant, because they enable or disable features we might need to
    # respect in our tests as well.
    # The matched `mattr` cmd line option (if any) can be accessed from the group `mattr`
    "run_line": r"RUN:.*(?P<mattr>mattr=[^ ]+).+",
}


class Test:
    def __init__(self, encoding: str | None, asm_text: str | None):
        self.encoding: str | None = encoding
        self.asm_text: str | None = asm_text

    def __str__(self):
        self.encoding.replace(" ", ",")
        self.encoding = self.encoding.strip("[]")
        return f"{self.encoding} == {self.asm_text}"

    def test_complete(self) -> bool:
        return self.encoding is not None and self.asm_text is not None

    def add_missing(self, encoding: str | None, asm_text: str | None):
        if encoding is None and asm_text is None:
            raise ValueError("One of the arguments must be set.")
        if not self.encoding:
            if not encoding:
                raise ValueError("Test still needs the encoding but it is None.")
            self.encoding = encoding
        if not self.asm_text:
            if not asm_text:
                raise ValueError("Test still needs the asm_text but it is None.")
            self.asm_text = asm_text


class TestManager:
    """Class to manage incomplete tests. It automatically assigns the encoding and asm text
    to the correct Test objects it holds.
    It assumes that incomplete tests (only encoding OR the asm_text is given)
    are all given in the same order.
    Meaning: The first test without any asm_text but the encoding, is the same test
    which is later given with only the asm_text but without encoding.

    E.g.:
        Order in which tests must be given to this Manager:

        Test 1 -> (<encoding>, None)
        Test 2 -> (<encoding>, None)
        Test 3 -> (<encoding>, None)
        ...

        Test 1 -> (None, <asm_text>)
        Test 2 -> (None, <asm_text>)
        Test 3 -> (None, <asm_text>)
        ...
    """

    class AddingState(Enum):
        ENCODING = 0
        ASM_TEXT = 1
        UNSET = 2

    def __init__(self):
        # If set, the already added tests are completed with the given information.
        self.switched = False
        self.state = self.AddingState.UNSET
        # List of all tests which still miss a part.
        self.incomplete_tests: list[Test] = list()
        # Tests which are complete
        self.completed: list[Test] = list()

    def add_test(self, encoding: str | None, asm_text: str | None):
        if encoding is not None and asm_text is not None:
            # No tests can be incomplete.
            if not (
                self.state == self.AddingState.UNSET and len(self.incomplete_tests) == 0
            ):
                raise ValueError(
                    "If a complete test is added, all other tests need to be done."
                )
            self.state = self.AddingState.UNSET
            self.completed.append(Test(encoding, asm_text))
            return

        if self.state == self.AddingState.UNSET:
            assert len(self.incomplete_tests) == 0
            # Add the first incomplete test
            self.state = (
                self.AddingState.ENCODING
                if encoding is not None
                else self.AddingState.ASM_TEXT
            )

        # Check if we complete the already added tests
        if (self.state == self.AddingState.ENCODING and encoding is None) or (
            self.state == self.AddingState.ASM_TEXT and asm_text is None
        ):
            self.switched = True

        if self.switched:
            test = self.incomplete_tests.pop(0)
            test.add_missing(encoding, asm_text)
            self.completed.append(test)
        else:
            self.incomplete_tests.append(Test(encoding, asm_text))

        # Lastly check if we can reset.
        if len(self.incomplete_tests) == 0:
            # All tests are completed. Reset
            self.state = self.AddingState.UNSET
            self.switched = False

    def check_all_complete(self) -> bool:
        if len(self.incomplete_tests) != 0:
            print(f"[!] We have {len(self.incomplete_tests)} incomplete tests.")
            return False
        return True

    def get_completed(self) -> list[Test]:
        return self.completed

    def get_stats(self) -> str:
        return (
            f"completed: {len(self.completed)} incomplete: {len(self.incomplete_tests)}"
        )

    def get_num_completed(self) -> int:
        return len(self.completed)

    def get_num_incomplete(self) -> int:
        return len(self.incomplete_tests)


class TestFile:
    def __init__(
        self, arch: str, filename: str, manager: TestManager, mattrs: list[str] | None
    ):
        self.arch = arch
        self.filename = filename
        self.manager = manager
        self.mattrs: list[str] = list() if not mattrs else mattrs
        self.test_files: list[TestFile] = list()

    def add_mattr(self, mattr: str):
        if not self.mattrs:
            self.mattrs = list()
        if mattr not in self.mattrs:
            self.mattrs.append(mattr)

    def add_tests(self, tests: list[Test]):
        self.tests = tests

    def get_cs_testfile_content(self) -> str:
        old_mc_test_file = get_path("{MC_DIR}").joinpath(
            f"{self.arch}/{self.filename}.cs"
        )
        if not old_mc_test_file.exists():
            header = (
                f"# CS_ARCH_{self.arch.upper()}, None, None\n"
                "# This regression test file is new. The option flags could not be determined.\n"
                f"# LLVM uses the following mattr = {self.mattrs}"
            )
        else:
            with open(old_mc_test_file) as f:
                init_line = f.readlines()[0]
            assert init_line != "" and "# CS_ARCH_" in init_line
            header = init_line

        content = header + "\n"
        for test in self.tests:
            content += f"{test}\n"
        return content


class MCUpdater:
    def __init__(
        self,
        arch: str,
        mc_dir: Path,
        excluded: list[str] | None,
        included: list[str] | None,
    ):
        self.arch = arch
        self.mc_dir = mc_dir
        self.excluded = excluded if excluded else list()
        self.included = included if included else list()
        self.test_files: dict[str:TestFile] = dict()

    def parse_file(self, filepath: Path) -> TestFile:
        """Parse a MC test file and return it as an object with all tests found.
        If it couldn't parse the file cleanly, it prints errors but returns it anyways.
        """
        with open(filepath) as f:
            lines = f.readlines()

        test_file = TestFile(self.arch, filepath.name, TestManager(), None)
        manager = test_file.manager
        for line in lines:
            if mattr := self.get_mattr(line):
                test_file.add_mattr(mattr)
                continue
            encoding, asm_text = self.get_enc_asm(line)
            if not encoding and not asm_text:
                continue
            manager.add_test(encoding, asm_text)

        manager.check_all_complete()
        test_file.add_tests(manager.get_completed())
        print(f"[*] Parsed {manager.get_num_completed()} tests:\t{filepath.name}")
        return test_file

    @staticmethod
    def get_mattr(line: str) -> str | None:
        match = re.search(match_patterns["run_line"], line)
        if not match or not match.group("mattr"):
            return None
        return match.group("mattr")

    @staticmethod
    def get_enc_asm(line: str) -> tuple[str | None, str | None]:
        enc: str | None = None
        asm_text: str | None = None
        if re.search(match_patterns["skip_pattern"], line):
            return None, None
        # Check for single line tests
        single_match = re.search(match_patterns["single_line_disas"], line)
        if single_match:
            return (
                single_match.group("enc_bytes"),
                single_match.group("asm_text").strip(),
            )

        asm_match = re.search(match_patterns["asm_check"], line)
        if asm_match:
            asm_text = asm_match.group("asm_text")
            if asm_match.group("enc_bytes"):
                # Single line test
                enc = asm_match.group("enc_bytes")
            if asm_text:
                asm_text = asm_text.strip()
            # A single line test. Return the result
            if asm_text and enc:
                return enc, asm_text

        # Check if the line contains at least encoding bytes
        pattern = rf"{match_patterns['enc_prefix_disas']}{match_patterns['enc_bytes']}"
        enc_match = re.search(pattern, line)
        if enc_match:
            enc = enc_match.group("enc_bytes")

        return enc, asm_text

    def gen_tests_in_dir(self, curr_dir: Path):
        for file in curr_dir.iterdir():
            if file.is_dir():
                self.gen_tests_in_dir(file)
                continue
            if len(self.included) != 0 and any(
                re.search(x, file.name) is not None for x in self.included
            ):
                continue
            if any(re.search(x, file.name) is not None for x in self.excluded):
                continue
            self.test_files[file.name] = self.parse_file(curr_dir.joinpath(file))

    def gen_all(self):
        assembly_tests = self.mc_dir.joinpath(f"{self.arch}")
        disas_tests = self.mc_dir.joinpath(f"Disassembler/{self.arch}")
        if not disas_tests.exists() or not disas_tests.is_dir():
            raise ValueError(
                f"'{disas_tests}' does not exits or is not a directory. Cannot generate tests from there."
            )
        if not assembly_tests.exists() or not assembly_tests.is_dir():
            raise ValueError(
                f"'{assembly_tests}' does not exits or is not a directory. Cannot generate tests from there."
            )

        self.gen_tests_in_dir(disas_tests)
        self.gen_tests_in_dir(assembly_tests)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Test file updater",
        description="Synchronizes test files with LLVM",
    )
    parser.add_argument(
        "-d",
        dest="mc_dir",
        help=f"Path to the LLVM MC test files. Default: {get_path('{LLVM_MC_TEST_DIR}')}",
        default=get_path("{LLVM_MC_TEST_DIR}"),
        type=Path,
    )
    parser.add_argument(
        "-a",
        dest="arch",
        help="Name of architecture to update.",
        choices=["ARM", "PowerPC", "AArch64", "LoongArch"],
        required=True,
    )
    parser.add_argument(
        "-e",
        dest="excluded_files",
        metavar="filename",
        nargs="+",
        help="File names to exclude from update (can be a regex pattern).",
    )
    parser.add_argument(
        "-i",
        dest="included_files",
        metavar="filename",
        nargs="+",
        help="Specific list of file names to update (can be a regex pattern).",
    )
    arguments = parser.parse_args()
    return arguments


if __name__ == "__main__":
    args = parse_args()
    MCUpdater(
        args.arch, args.mc_dir, args.excluded_files, args.included_files
    ).gen_all()
