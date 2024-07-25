#!/usr/bin/env python3
# Copyright © 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import argparse
import logging as log
import re
import sys
import subprocess as sp

from pathlib import Path

from autosync.Targets import TARGETS_LLVM_NAMING
from autosync.Helper import convert_loglevel, get_path

# mattr flags which have to be added to all llvm-mc commands
# before executing them.
ARCH_MATTR = {"AArch64": "+all"}


class LLVM_MC_Command:
    def __init__(self, cmd_line: str, mattr: str):
        self.cmd: str = ""
        self.opts: str = ""
        self.file: Path | None = None
        self.mattr: str = mattr

        self.cmd, self.opts, self.file = self.parse_llvm_mc_line(cmd_line)
        if not (self.cmd and self.opts and self.file):
            raise ValueError(f"Could not parse llvm-mc command: {cmd_line}")

    def parse_llvm_mc_line(self, line: str) -> tuple[str, str, Path]:
        test_file_base_dir = str(get_path("{LLVM_LIT_TEST_DIR}").absolute())
        file = re.findall(rf"{test_file_base_dir}\S+", line)
        if not file:
            raise ValueError(f"llvm-mc command doesn't contain a file: {line}")
        test_file = file[0]
        cmd = re.sub(rf"{test_file}", "", line).strip()
        cmd = re.sub(r"\s+", " ", cmd)
        arch = re.finditer(r"(triple|arch)[=\s](\S+)", cmd)
        mattr = re.finditer(r"(mattr|mcpu)[=\s](\S+)", cmd)
        opts = ",".join([m.group(2) for m in arch]) if arch else ""
        if mattr:
            opts += "" if not opts else ","
            opts += ",".join([m.group(2).strip("+") for m in mattr])
        return cmd, opts, Path(test_file)

    def exec(self) -> sp.CompletedProcess:
        with open(self.file, "b+r") as f:
            content = f.read()
        if self.mattr:
            # If mattr exists, patch it into the cmd
            if "mattr" in self.cmd:
                self.cmd = re.sub(
                    r"mattr[=\s]+", f"mattr={self.mattr} -mattr=", self.cmd
                )
            else:
                self.cmd = re.sub(r"llvm-mc", f"llvm-mc -mattr={self.mattr}", self.cmd)

        result = sp.run(self.cmd.split(" "), input=content, capture_output=True)
        return result

    def get_opts_list(self) -> list[str]:
        opts = self.opts.strip().strip(",")
        opts = re.sub(r"[, ]+", ",", opts)
        return opts.split(",")

    def __str__(self) -> str:
        return f"{self.cmd} < {str(self.file.absolute())}"


class MCTest:
    """
    A single test. It can contain multiple decoded instruction for a given byte sequence.
    In general a MCTest always tests a sequence of instructions in a single .text segment.
    """

    def __init__(self, arch: str, opts: list[str], encoding: str, asm_text: str):
        self.arch = arch
        if arch.lower() in ["arm", "powerpc", "ppc"]:
            # Arch and PPC require this option for MC tests.
            self.opts = ["CS_OPT_NO_BRANCH_OFFSET"] + opts
        else:
            self.opts = opts
        self.encoding: list[str] = [encoding]
        self.asm_text: list[str] = [asm_text]

    def extend(self, encoding: str, asm_text: str):
        self.encoding.append(encoding)
        self.asm_text.append(asm_text)

    def __str__(self):
        encoding = ",".join(self.encoding)
        encoding = re.sub(r"[\[\]]", "", encoding)
        encoding = encoding.strip()
        encoding = re.sub(r"[\s,]+", ", ", encoding)
        yaml_tc = (
            "  -\n"
            "    input:\n"
            "      bytes: [ <ENCODING> ]\n"
            '      arch: "<ARCH>"\n'
            "      options: [ <OPTIONS> ]\n"
            "    expected:\n"
            "      insns:\n"
        )
        template = "        -\n          asm_text: <ASM_TEXT>\n"
        insn_cases = ""
        for text in self.asm_text:
            insn_cases += template.replace("<ASM_TEXT>", f'"{text}"')

        yaml_tc = yaml_tc.replace("<ENCODING>", encoding)
        yaml_tc = yaml_tc.replace("<ARCH>", f"CS_ARCH_{self.arch.upper()}")
        yaml_tc = yaml_tc.replace("<OPTIONS>", ", ".join([f'"{o}"' for o in self.opts]))
        yaml_tc += insn_cases
        return yaml_tc


class TestFile:
    def __init__(
        self,
        arch: str,
        filename: Path,
        opts: list[str] | None,
        mc_cmd: LLVM_MC_Command,
        unified_test_cases: bool,
    ):
        self.arch: str = arch
        self.filename: Path = filename
        self.opts: list[str] = list() if not opts else opts
        self.mc_cmd: LLVM_MC_Command = mc_cmd
        # Indexed by .text section count
        self.tests: dict[int : list[MCTest]] = dict()
        self.init_tests(unified_test_cases)

    def init_tests(self, unified_test_cases: bool):
        mc_output = self.mc_cmd.exec()
        if mc_output.stderr and not mc_output.stdout:
            # We can still continue. We just ignore the failed cases.
            log.debug(f"llvm-mc cmd stderr: {mc_output.stderr}")
        text_section = 0  # Counts the .text sections
        asm_pat = f"(?P<asm_text>.+)"
        enc_pat = r"(\[?(?P<enc_bytes>((0x[a-fA-F0-9]{1,2}[, ]{0,2}))+)[^, ]?\]?)"
        for line in mc_output.stdout.splitlines():
            line = line.decode("utf8")
            if ".text" in line:
                text_section += 1
                continue
            match = re.search(
                rf"^\s*{asm_pat}\s*(#|//|@)\s*encoding:\s*{enc_pat}", line
            )
            if not match:
                continue
            enc_bytes = match.group("enc_bytes").strip()
            asm_text = match.group("asm_text").strip()
            asm_text = re.sub(r"\t+", " ", asm_text)
            asm_text = asm_text.strip()
            if not self.valid_byte_seq(enc_bytes):
                continue

            if text_section in self.tests:
                if unified_test_cases:
                    self.tests[text_section][0].extend(enc_bytes, asm_text)
                else:
                    self.tests[text_section].append(
                        MCTest(self.arch, self.opts, enc_bytes, asm_text)
                    )
            else:
                self.tests[text_section] = [
                    MCTest(self.arch, self.opts, enc_bytes, asm_text)
                ]

    def has_tests(self) -> bool:
        return len(self.tests) != 0

    def get_cs_testfile_content(self, only_test: bool) -> str:
        content = "\n" if only_test else "test_cases:\n"
        for tl in self.tests.values():
            content += "\n".join([str(t) for t in tl])
        return content

    def num_test_cases(self) -> int:
        return len(self.tests)

    def valid_byte_seq(self, enc_bytes):
        match self.arch:
            case "AArch64":
                # It always needs 4 bytes.
                # Otherwise it is likely a reloc or symbol test
                return enc_bytes.count("0x") == 4
            case _:
                return True


class MCUpdater:
    def __init__(
        self,
        arch: str,
        mc_dir: Path,
        excluded: list[str] | None,
        included: list[str] | None,
        unified_test_cases: bool,
    ):
        self.symbolic_links = list()
        self.arch = arch
        self.test_dir_link_prefix = f"test_dir_{arch}_"
        self.mc_dir = mc_dir
        self.excluded = excluded if excluded else list()
        self.included = included if included else list()
        self.test_files: list[TestFile] = list()
        self.unified_test_cases = unified_test_cases
        self.mattr: str = ARCH_MATTR[self.arch] if self.arch in ARCH_MATTR else ""

    def check_prerequisites(self, paths):
        for path in paths:
            if not path.exists() or not path.is_dir():
                raise ValueError(
                    f"'{path}' does not exits or is not a directory. Cannot generate tests from there."
                )
        llvm_lit_cfg = get_path("{LLVM_LIT_TEST_DIR}")
        if not llvm_lit_cfg.exists():
            raise ValueError(
                f"Could not find '{llvm_lit_cfg}'. Check {{LLVM_LIT_TEST_DIR}} in path_vars.json."
            )

    def write_to_build_dir(self):
        file_cnt = 0
        test_cnt = 0
        files_written = set()
        for test in self.test_files:
            if not test.has_tests():
                continue
            file_cnt += 1
            test_cnt += test.num_test_cases()

            rel_path = str(test.filename.relative_to(get_path("{LLVM_LIT_TEST_DIR}")))
            filename = re.sub(rf"{self.test_dir_link_prefix}\d+", ".", rel_path)
            filename = get_path("{MCUPDATER_OUT_DIR}").joinpath(f"{filename}.yaml")
            if filename in files_written:
                write_mode = "a"
            else:
                write_mode = "w+"
            filename.parent.mkdir(parents=True, exist_ok=True)
            with open(filename, write_mode) as f:
                f.write(test.get_cs_testfile_content(only_test=(write_mode == "a")))
                log.debug(f"Write {filename}")
            files_written.add(filename)
        log.info(
            f"Processed {file_cnt} files with {test_cnt} test cases. Generated {len(files_written)} files"
        )

    def build_test_files(self, mc_cmds: list[LLVM_MC_Command]) -> list[TestFile]:
        log.info("Build TestFile objects")
        test_files = list()
        n_all = len(mc_cmds)
        for i, mcc in enumerate(mc_cmds):
            print(f"{i}/{n_all} {mcc.file.name}", flush=True, end="\r")
            test_files.append(
                TestFile(
                    self.arch,
                    mcc.file,
                    mcc.get_opts_list(),
                    mcc,
                    self.unified_test_cases,
                )
            )
        return test_files

    def run_llvm_lit(self, paths: list[Path]) -> list[LLVM_MC_Command]:
        """
        Calls llvm-lit with the given paths to the tests.
        It parses the llvm-lit commands to LLVM_MC_Commands.
        """
        lit_cfg_dir = get_path("{LLVM_LIT_TEST_DIR}")
        llvm_lit_cfg = str(lit_cfg_dir.absolute())
        args = ["lit", "-v", "-a", llvm_lit_cfg]
        for i, p in enumerate(paths):
            slink = lit_cfg_dir.joinpath(f"{self.test_dir_link_prefix}{i}")
            self.symbolic_links.append(slink)
            log.debug(f"Create link: {slink} -> {p}")
            try:
                slink.symlink_to(p, target_is_directory=True)
            except FileExistsError as e:
                print("Failed: Link existed. Please delete it")
                raise e

        log.info(f"Run lit: {' '.join(args)}")
        cmds = sp.run(args, capture_output=True)
        if cmds.stderr:
            raise ValueError(f"llvm-lit failed with {cmds.stderr}")
        return self.extract_llvm_mc_cmds(cmds.stdout.decode("utf8"))

    def extract_llvm_mc_cmds(self, cmds: str) -> list[LLVM_MC_Command]:
        log.debug("Parsing llvm-mc commands")
        # Get only the RUN lines which have a show-encoding set.
        matches = filter(
            lambda l: l if re.search(r"^RUN.+show-encoding[^|]+", l) else None,
            cmds.splitlines(),
        )
        # Don't add tests which are allowed to fail
        matches = filter(
            lambda m: None if re.search(r"not\s+llvm-mc", m) else m, matches
        )
        # Skip object file tests
        matches = filter(
            lambda m: None if re.search(r"filetype=obj", m) else m, matches
        )
        # Skip any relocation related tests.
        matches = filter(lambda m: None if re.search(r"reloc", m) else m, matches)
        # Remove 'RUN: at ...' prefix
        matches = map(lambda m: re.sub(r"^RUN: at line \d+: ", "", m), matches)
        # Remove redirections
        matches = map(lambda m: re.sub(r"\d>&\d", "", m), matches)
        # Remove unused arguments
        matches = map(lambda m: re.sub(r"-o\s?-", "", m), matches)
        # Remove redirection of stderr to a file
        matches = map(lambda m: re.sub(r"2>\s?\S+", "", m), matches)
        # Remove piping to FileCheck
        matches = map(lambda m: re.sub(r"\|\s*FileCheck\s+.+", "", m), matches)
        # Remove input stream
        matches = map(lambda m: re.sub(r"\s+<", "", m), matches)

        all_cmds = list()
        for match in matches:
            if self.included and not any(
                re.search(x, match) is not None for x in self.included
            ):
                continue
            if any(re.search(x, match) is not None for x in self.excluded):
                continue

            all_cmds.append(LLVM_MC_Command(match, self.mattr))
        return all_cmds

    def gen_all(self):
        log.info("Check prerequisites")
        disas_tests = self.mc_dir.joinpath(f"Disassembler/{self.arch}")
        assembly_tests = self.mc_dir.joinpath(f"{self.arch}")
        test_paths = [disas_tests, assembly_tests]
        self.check_prerequisites(test_paths)
        log.info("Generate MC regression tests")
        llvm_mc_cmds = self.run_llvm_lit(test_paths)
        self.test_files = self.build_test_files(llvm_mc_cmds)
        for slink in self.symbolic_links:
            log.debug(f"Unlink {slink}")
            slink.unlink()
        self.write_to_build_dir()


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
        choices=TARGETS_LLVM_NAMING,
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
    parser.add_argument(
        "-u",
        dest="unified_tests",
        action="store_true",
        default=False,
        help="If set, all instructions of a text segment will decoded and tested at once. Should be set, if instructions depend on each other.",
    )
    parser.add_argument(
        "-v",
        dest="verbosity",
        help="Verbosity of the log messages.",
        choices=["debug", "info", "warning", "fatal"],
        default="info",
    )
    arguments = parser.parse_args()
    return arguments


if __name__ == "__main__":
    args = parse_args()
    log.basicConfig(
        level=convert_loglevel(args.verbosity),
        stream=sys.stdout,
        format="%(levelname)-5s - %(message)s",
        force=True,
    )

    MCUpdater(
        args.arch,
        args.mc_dir,
        args.excluded_files,
        args.included_files,
        args.unified_tests,
    ).gen_all()
