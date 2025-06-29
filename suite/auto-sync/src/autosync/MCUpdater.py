#!/usr/bin/env python3
# Copyright © 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import argparse
import logging as log
import json
import re
import sys
import subprocess as sp

from pathlib import Path

from autosync.Targets import TARGETS_LLVM_NAMING, TARGET_TO_DIR_NAME
from autosync.Helper import convert_loglevel, get_path


class LLVM_MC_Command:
    def __init__(self, cmd_line: str, mattr: str):
        self.cmd: str = ""
        self.opts: str = ""
        self.file: Path | None = None
        self.additional_mattr: str = mattr

        self.cmd, self.opts, self.file = self.parse_llvm_mc_line(cmd_line)
        if not (self.cmd and self.opts and self.file):
            log.warning(f"Could not parse llvm-mc command: {cmd_line}")
        elif not "--show-encoding" in self.cmd:
            self.cmd = re.sub("llvm-mc", "llvm-mc --show-encoding", self.cmd)
        elif not "--disassemble" in self.cmd:
            self.cmd = re.sub("llvm-mc", "llvm-mc --disassemble", self.cmd)

    def parse_llvm_mc_line(self, line: str) -> tuple[str, str, Path]:
        test_file_base_dir = str(get_path("{LLVM_LIT_TEST_DIR}").absolute())
        file = re.findall(rf"{test_file_base_dir}\S+", line)
        if not file:
            log.warning(f"llvm-mc command doesn't contain a file: {line}")
            return None, None, None
        test_file = file[0]
        cmd = re.sub(rf"{test_file}", "", line).strip()
        cmd = re.sub(r"\s+", " ", cmd)
        arch = re.finditer(r"(triple|arch)[=\s](\S+)", cmd)
        mattr = re.finditer(r"(mattr|mcpu)[=\s](\S+)", cmd)
        opts = ",".join([m.group(2) for m in arch]) if arch else ""
        if mattr:
            opts += "" if not opts else ","
            processed_attr = list()
            for m in mattr:
                attribute = m.group(2).strip("+")
                processed_attr.append(attribute)
            opts += ",".join(processed_attr)
        return cmd, opts, Path(test_file)

    def exec(self) -> sp.CompletedProcess:
        with open(self.file, "b+r") as f:
            content = f.read()
        if self.additional_mattr:
            # If mattr exists, patch it into the cmd
            if "mattr" in self.cmd:
                self.cmd = re.sub(
                    r"mattr[=\s]+", f"mattr={self.additional_mattr} -mattr=", self.cmd
                )
            else:
                self.cmd = re.sub(
                    r"llvm-mc", f"llvm-mc -mattr={self.additional_mattr}", self.cmd
                )

        log.debug(f"Run: {self.cmd}")
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
        self.opts = opts
        self.encoding: list[str] = [encoding]
        self.asm_text: list[str] = [asm_text]

    def extend(self, encoding: str, asm_text: str):
        self.encoding.append(encoding)
        self.asm_text.append(asm_text)

    def get_legacy_mc_test_triple(self):
        """
        Returns the legacy triple for the old MC test files:
        <ARCH>, <MODE>, None
        Should only be used to generate fuzzing tests.
        """
        triple = "# "
        if self.arch.startswith("CS_ARCH"):
            triple += self.arch
        else:
            triple += f"CS_ARCH_{self.arch.upper()}"
        opts = "|".join([f'"{o}"' for o in self.opts if o.startswith("CS_MODE_")])
        if not opts:
            opts = "0"
        triple += f", {opts}, None"
        return triple

    def fuzz_test_str(self):
        old_mc_tcase = ""
        for enc, asm_text in zip(self.encoding, self.asm_text):
            if old_mc_tcase:
                old_mc_tcase += "\n"
            encoding = re.sub(r"[\[\]]", "", enc)
            encoding = encoding.strip()
            encoding = re.sub(r"[\s,]+", ",", encoding)
            old_mc_tcase += f"{encoding} == {asm_text}"
        return old_mc_tcase

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
        file_path: Path,
        opts: list[str] | None,
        mc_cmd: LLVM_MC_Command,
        unified_test_cases: bool,
    ):
        self.arch: str = arch
        self.file_path: Path = file_path
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
        log.debug(f"llvm-mc result: {mc_output}")
        text_section = 0  # Counts the .text sections
        asm_pat = f"(?P<asm_text>.+)"
        enc_pat = r"(\[?(?P<full_enc_string>(?P<enc_bytes>((0x[a-fA-F0-9]{1,2}[, ]{0,2}))+)[^, ]?)\]?)"

        dups = []
        for line in mc_output.stdout.splitlines():
            line = line.decode("utf8")
            if ".text" in line:
                text_section += 1
                continue
            match = re.search(
                rf"^\s*{asm_pat}\s*(#|//|@|!|;)\s*encoding:\s*{enc_pat}", line
            )
            if not match:
                continue
            full_enc_string = match.group("full_enc_string")
            if not re.search(r"0x[a-fA-F0-9]{1,2}$", full_enc_string[:-1]):
                log.debug(f"Ignore because symbol injection is needed: {line}")
                # The encoding string contains symbol information of the form:
                # [0xc0,0xe0,A,A,A... or similar. We ignore these for now.
                continue
            enc_bytes = match.group("enc_bytes").strip()
            asm_text = match.group("asm_text").strip()
            asm_text = re.sub(r"\t+", " ", asm_text)
            asm_text = asm_text.strip()
            if not self.valid_byte_seq(enc_bytes):
                continue

            if (enc_bytes + asm_text) in dups:
                continue

            dups.append(enc_bytes + asm_text)
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

    def get_cs_testfile_content(self, only_tests: bool) -> str:
        content = "\n" if only_tests else "test_cases:\n"
        for tl in self.tests.values():
            content += "\n".join([str(t) for t in tl])
        return content

    def get_fuzz_test_file_content(self, only_tests: bool) -> str:
        content = ""
        for tl in self.tests.values():
            if not content:
                content = (
                    "\n" if only_tests else tl[0].get_legacy_mc_test_triple() + "\n"
                )
            content += "\n".join([t.fuzz_test_str() for t in tl])
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

    def get_multi_mode_filename(self) -> Path:
        filename = self.file_path.stem
        parent = self.file_path.parent
        prefix_less_opts = [re.sub(r"CS_(OPT|MODE)_", "", o).lower() for o in self.opts]
        detailed_name = f"{filename}_{'_'.join(prefix_less_opts)}.txt"
        detailed_name = re.sub(r"[+-]", "_", detailed_name)
        out_path = parent.joinpath(detailed_name)
        return Path(out_path)

    def get_simple_filename(self) -> Path:
        return self.file_path

    def __lt__(self, other) -> bool:
        return str(self.file_path) < str(other.file_path)


def exists_and_is_dir(x):
    return x.exists() and x.is_dir()


class MCUpdater:
    """
    The MCUpdater parses all test files of the LLVM MC regression tests.
    Each of those LLVM files can contain several llvm-mc commands to run on the same file.
    Mostly this is done to test the same file with different CPU features enabled.
    So it can test different flavors of assembly etc.

    In Capstone all modules enable always all CPU features (even if this is not
    possible in reality).
    Due to this we always parse all llvm-mc commands run on a test file, generate a TestFile
    object for each of it, but only write the last one of them to disk.
    Once https://github.com/capstone-engine/capstone/issues/1992 is resolved, we can
    write all variants of a test file to disk.

    This is already implemented and tested with multi_mode = True.
    """

    def __init__(
        self,
        arch: str,
        mc_dir: Path,
        excluded: list[str] | None,
        included: list[str] | None,
        unified_test_cases: bool,
        multi_mode: bool = False,
    ):
        self.symbolic_links = list()
        self.arch = arch
        self.arch_dir_name = TARGET_TO_DIR_NAME[self.arch]
        self.test_dir_link_prefix = f"test_dir_{arch}_"
        self.mc_dir = mc_dir
        self.excluded = excluded if excluded else list()
        self.included = included if included else list()
        self.test_files: list[TestFile] = list()
        self.unified_test_cases = unified_test_cases
        with open(get_path("{MCUPDATER_CONFIG_FILE}")) as f:
            self.conf = json.loads(f.read())
        # Additional mattr passed to llvm-mc
        self.mattr: str = (
            ",".join(self.conf["additional_mattr"][self.arch])
            if self.arch in self.conf["additional_mattr"]
            else ""
        )
        # A list of options which are always added.
        self.mandatory_options: list[str] = (
            self.conf["mandatory_options"][self.arch]
            if self.arch in self.conf["mandatory_options"]
            else list()
        )
        self.default_endianess: str = (
            self.conf["default_endianess"][self.arch]
            if self.arch in self.conf["default_endianess"]
            else ""
        )
        self.remove_options: str = (
            self.conf["remove_options"][self.arch]
            if self.arch in self.conf["remove_options"]
            else list()
        )
        self.remove_options = [x.lower() for x in self.remove_options]
        self.replace_option_map: dict = (
            self.conf["replace_option_map"][self.arch]
            if self.arch in self.conf["replace_option_map"]
            else {}
        )
        self.replace_option_map = {
            k.lower(): v
            for k, v in self.replace_option_map.items()
            if k.lower not in self.remove_options
        }
        self.multi_mode = multi_mode

    def check_prerequisites(self, paths):
        if all(not exists_and_is_dir(path) for path in paths):
            raise ValueError(
                f"'{paths}' does not exits or is not a directory. Cannot generate tests from there."
            )
        llvm_lit_cfg = get_path("{LLVM_LIT_TEST_DIR}")
        if not llvm_lit_cfg.exists():
            raise ValueError(
                f"Could not find '{llvm_lit_cfg}'. Check {{LLVM_LIT_TEST_DIR}} in path_vars.json."
            )

    def write_to_build_dir(self, fuzzer_tests: bool = False):
        no_tests_file = 0
        file_cnt = 0
        test_cnt = 0
        overwritten = 0
        files_written = set()
        for test in sorted(self.test_files):
            if not test.has_tests():
                no_tests_file += 1
                continue
            file_cnt += 1
            test_cnt += test.num_test_cases()

            if self.multi_mode:
                rel_path = str(
                    test.get_multi_mode_filename().relative_to(
                        get_path("{LLVM_LIT_TEST_DIR}")
                    )
                )
            else:
                rel_path = str(
                    test.get_simple_filename().relative_to(
                        get_path("{LLVM_LIT_TEST_DIR}")
                    )
                )

            filename = re.sub(rf"{self.test_dir_link_prefix}\d+", ".", rel_path)
            if fuzzer_tests:
                filename = get_path("{MCUPDATER_OUT_FUZZ_DIR}").joinpath(
                    f"{filename}.cs"
                )
            else:
                filename = get_path("{MCUPDATER_OUT_DIR}").joinpath(f"{filename}.yaml")

            if filename in files_written:
                write_mode = "a"
            else:
                write_mode = "w+"
            filename.parent.mkdir(parents=True, exist_ok=True)
            if self.multi_mode and filename.exists():
                log.warning(
                    f"The following file exists already: {filename}. This indicates a blind spot in testing."
                )
                overwritten += 1
            elif not self.multi_mode and filename.exists():
                log.debug(f"Overwrite: {filename}")
                overwritten += 1
            with open(filename, write_mode) as f:
                if fuzzer_tests:
                    content = test.get_fuzz_test_file_content(
                        only_tests=(write_mode == "a")
                    )
                else:
                    content = test.get_cs_testfile_content(
                        only_tests=(write_mode == "a")
                    )
                f.write(content)
                log.debug(f"Write {filename}")
            files_written.add(filename)
        print()
        log.info(
            f"Got {len(self.test_files)} {'fuzzing ' if fuzzer_tests else ''}test files.\n"
            f"\t\tProcessed {file_cnt} files with {test_cnt} test cases.\n"
            f"\t\tIgnored {no_tests_file} without tests.\n"
            f"\t\tGenerated {len(files_written)} files"
        )
        if overwritten > 0:
            log.warning(
                f"Overwrote {overwritten} test files with the same name.\n"
                f"These files contain instructions of several different cpu features.\n"
                f"You have to use multi-mode to write them into distinct files.\n"
                f"The current setting will only keep the last one written.\n"
                f"See also: https://github.com/capstone-engine/capstone/issues/1992\n"
                "If you already used multi-mode (default = yes), there might be a blind spot in testing."
            )

    def build_test_options(self, options):
        new_options = [] + self.mandatory_options
        for opt in options:
            opt = opt.lower()
            if opt in self.remove_options:
                continue
            elif opt in self.replace_option_map:
                new_options.extend(self.replace_option_map[opt])
            else:
                new_options.append(opt)
        if (
            not any(
                [
                    True
                    for x in new_options
                    if x in ["CS_MODE_BIG_ENDIAN", "CS_MODE_LITTLE_ENDIAN"]
                ]
            )
            and self.default_endianess
        ):
            new_options.append(self.default_endianess)
        return new_options

    def build_test_files(self, mc_cmds: list[LLVM_MC_Command]) -> list[TestFile]:
        log.info("Build TestFile objects")
        test_files = list()
        n_all = len(mc_cmds)
        for i, mcc in enumerate(mc_cmds):
            print(f"{i + 1}/{n_all} {mcc.file.name}", flush=True, end="\r")
            opts = self.build_test_options(mcc.get_opts_list())
            test_files.append(
                TestFile(
                    self.arch,
                    mcc.file,
                    opts,
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
        cmd_lines = cmds.splitlines()
        log.debug(f"NO FILTER: {cmd_lines}")
        matches = list(
            filter(
                lambda l: (
                    l
                    if re.search(r"^RUN.+(show-encoding|disassemble)[^|]+", l)
                    else None
                ),
                cmd_lines,
            )
        )
        log.debug(f"FILTER RUN: {' '.join(matches)}")
        # Don't add tests which are allowed to fail
        matches = list(
            filter(lambda m: None if re.search(r"not\s+llvm-mc", m) else m, matches)
        )
        log.debug(f"FILTER not llvm-mc: {' '.join(matches)}")
        # Skip object file tests
        matches = list(
            filter(lambda m: None if re.search(r"filetype=obj", m) else m, matches)
        )
        log.debug(f"FILTER filetype=obj-mc: {' '.join(matches)}")
        # Skip any relocation related tests.
        matches = filter(lambda m: None if re.search(r"reloc", m) else m, matches)
        # Remove 'RUN: at ...' prefix
        matches = map(lambda m: re.sub(r"^RUN: at line \d+: ", "", m), matches)
        # Remove redirection
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
            llvm_mc_cmd = LLVM_MC_Command(match, self.mattr)
            if not llvm_mc_cmd.cmd:
                # Invalid
                continue
            all_cmds.append(llvm_mc_cmd)
            log.debug(f"Added: {llvm_mc_cmd}")
        log.debug(f"Extracted {len(all_cmds)} llvm-mc commands")
        return all_cmds

    def gen_all(self):
        log.info("Check prerequisites")
        test_paths = list()
        if self.arch in self.conf["use_assembly_tests"]:
            log.info(f"Add assembly tests for {self.arch}")
            test_paths.append(self.mc_dir.joinpath(self.arch))
        if self.arch not in self.conf["exclude_disassembly_tests"]:
            log.info(f"Add disassembly tests for {self.arch}")
            disas_tests = self.mc_dir.joinpath(f"Disassembler/{self.arch_dir_name}")
            test_paths.append(disas_tests)
        self.check_prerequisites(test_paths)
        log.info("Generate MC regression tests")
        llvm_mc_cmds = self.run_llvm_lit(
            [path for path in test_paths if exists_and_is_dir(path)]
        )
        log.info(f"Got {len(llvm_mc_cmds)} llvm-mc commands to run")
        self.test_files = self.build_test_files(llvm_mc_cmds)
        for slink in self.symbolic_links:
            log.debug(f"Unlink {slink}")
            slink.unlink()


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
        True,
    ).gen_all()
