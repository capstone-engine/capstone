#!/usr/bin/env python3

# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import logging as log
import os
import re
import shutil
import subprocess
from pathlib import Path

from autosync.Helper import fail_exit, get_path

inc_tables = [
    {
        "name": "Disassembler",
        "tblgen_arg": "--gen-disassembler",
        "inc_name": "DisassemblerTables",
        "only_arch": [],
        "lang": ["CCS", "C++"],
    },
    {
        "name": "AsmWriter",
        "tblgen_arg": "--gen-asm-writer",
        "inc_name": "AsmWriter",
        "only_arch": [],
        "lang": ["CCS", "C++"],
    },
    {
        "name": "RegisterInfo",
        "tblgen_arg": "--gen-register-info",
        "inc_name": "RegisterInfo",
        "only_arch": [],
        "lang": ["CCS"],
    },
    {
        "name": "InstrInfo",
        "tblgen_arg": "--gen-instr-info",
        "inc_name": "InstrInfo",
        "only_arch": [],
        "lang": ["CCS"],
    },
    {
        "name": "SubtargetInfo",
        "tblgen_arg": "--gen-subtarget",
        "inc_name": "SubtargetInfo",
        "only_arch": [],
        "lang": ["CCS"],
    },
    {
        "name": "Mapping",
        "tblgen_arg": "--gen-asm-matcher",
        "inc_name": None,
        "only_arch": [],
        "lang": ["CCS"],
    },
    {
        "name": "SystemOperand",
        "tblgen_arg": "--gen-searchable-tables",
        "inc_name": None,
        "only_arch": ["AArch64", "ARM"],
        "lang": ["CCS"],
    },
]


class IncGenerator:
    def __init__(self, arch: str, inc_list: list) -> None:
        self.arch: str = arch
        self.inc_list = inc_list  # Names of inc files to generate.
        self.arch_dir_name: str = "PowerPC" if self.arch == "PPC" else self.arch
        self.patches_dir_path: Path = get_path("{INC_PATCH_DIR}")
        self.llvm_include_dir: Path = get_path("{LLVM_INCLUDE_DIR}")
        self.output_dir: Path = get_path("{BUILD_DIR}")
        self.llvm_target_dir: Path = get_path("{LLVM_TARGET_DIR}").joinpath(
            f"{self.arch_dir_name}"
        )
        self.llvm_tblgen: Path = get_path("{LLVM_TBLGEN_BIN}")
        self.output_dir_c_inc = get_path("{C_INC_OUT_DIR}")
        self.output_dir_cpp_inc = get_path("{CPP_INC_OUT_DIR}")
        self.check_paths()

    def check_paths(self) -> None:
        if not self.llvm_include_dir.exists():
            fail_exit(f"{self.llvm_include_dir} does not exist.")
        if not self.llvm_target_dir.exists():
            fail_exit(f"{self.llvm_target_dir} does not exist.")
        if not self.llvm_tblgen.exists():
            fail_exit(f"{self.llvm_tblgen} does not exist. Have you build llvm-tblgen?")
        if not self.output_dir.exists():
            fail_exit(f"{self.output_dir} does not exist.")
        if not self.output_dir_c_inc.exists():
            log.debug(f"{self.output_dir_c_inc} does not exist. Creating it...")
            os.makedirs(self.output_dir_c_inc)
        if not self.output_dir_cpp_inc.exists():
            log.debug(f"{self.output_dir_cpp_inc} does not exist. Creating it...")
            os.makedirs(self.output_dir_cpp_inc)

    def generate(self) -> None:
        self.gen_incs()
        self.move_mapping_files()

    def move_mapping_files(self) -> None:
        """
        Moves the <ARCH>GenCS files. They are written to CWD (I know, not nice).
        We move them manually to the build dir, as long as llvm-capstone doesn't
        allow to specify an output dir.
        """
        for file in Path.cwd().iterdir():
            if re.search(rf"{self.arch}Gen.*\.inc", file.name):
                log.debug(f"Move {file} to {self.output_dir_c_inc}")
                if self.output_dir_c_inc.joinpath(file.name).exists():
                    os.remove(self.output_dir_c_inc.joinpath(file.name))
                shutil.move(file, self.output_dir_c_inc)

        if self.arch == "AArch64":
            # We have to rename the file SystemRegister -> SystemOperands
            sys_ops_table_file = self.output_dir_c_inc.joinpath(
                "AArch64GenSystemRegister.inc"
            )
            new_sys_ops_file = self.output_dir_c_inc.joinpath(
                "AArch64GenSystemOperands.inc"
            )
            if "SystemOperand" not in self.inc_list:
                return
            elif not sys_ops_table_file.exists():
                fail_exit(
                    f"{sys_ops_table_file} does not exist. But it should have been generated."
                )
            if new_sys_ops_file.exists():
                os.remove(new_sys_ops_file)
            shutil.move(sys_ops_table_file, new_sys_ops_file)

    def gen_incs(self) -> None:
        for table in inc_tables:
            if "All" not in self.inc_list and table["name"] not in self.inc_list:
                log.debug(f"Skip {table['name']} generation")
                continue

            if table["only_arch"] and self.arch not in table["only_arch"]:
                continue

            log.info(f"Generating {table['name']} tables...")
            for lang in table["lang"]:
                log.debug(f"Generating {lang} tables...")
                td_file = self.llvm_target_dir.joinpath(f"{self.arch}.td")
                out_file = f"{self.arch}Gen{table['inc_name']}.inc"
                if lang == "CCS":
                    out_path = self.output_dir_c_inc.joinpath(out_file)
                elif lang == "C++":
                    out_path = self.output_dir_cpp_inc.joinpath(out_file)
                else:
                    raise NotImplementedError(f"{lang} not supported by llvm-tblgen.")

                args = []
                args.append(str(self.llvm_tblgen))
                args.append(f"--printerLang={lang}")
                args.append(table["tblgen_arg"])
                args.append("-I")
                args.append(f"{str(self.llvm_include_dir)}")
                args.append("-I")
                args.append(f"{str(self.llvm_target_dir)}")
                if table["inc_name"]:
                    args.append("-o")
                    args.append(f"{str(out_path)}")
                args.append(str(td_file))

                log.debug(" ".join(args))
                try:
                    subprocess.run(
                        args,
                        check=True,
                    )
                except subprocess.CalledProcessError as e:
                    log.fatal("Generation failed")
                    raise e

    def apply_patches(self) -> None:
        """
        Applies a all patches of inc files.
        Files must be moved to their arch/<ARCH> directory before.
        """
        patch_dir = self.patches_dir_path.joinpath(self.arch)
        if not patch_dir.exists():
            return

        for patch in patch_dir.iterdir():
            try:
                subprocess.run(
                    ["git", "apply", str(patch)],
                    check=True,
                )
            except subprocess.CalledProcessError as e:
                log.warning(f"Patch {patch.name} did not apply correctly!")
                log.warning(f"git apply returned: {e}")
                return
