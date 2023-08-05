#!/usr/bin/env python3

import os
import subprocess

import logging as log

from Helper import fail_exit
from pathlib import Path


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
    def __init__(self, arch: str, inc_list: list, llvm_path: Path, output_dir: Path) -> None:
        self.arch: str = arch
        self.inc_list = inc_list  # Names of inc files to generate. Or all if all should be generated.
        self.arch_dir_name: str = "PowerPC" if self.arch == "PPC" else self.arch
        self.llvm_root_path: Path = llvm_path
        self.llvm_include_dir: Path = self.llvm_root_path.joinpath(Path(f"llvm/include/"))
        self.output_dir: Path = output_dir
        self.llvm_target_dir: Path = self.llvm_root_path.joinpath(Path(f"llvm/lib/Target/{self.arch_dir_name}/"))
        self.llvm_tblgen: Path = self.llvm_root_path.joinpath("build/bin/llvm-tblgen")
        self.check_paths()

    def check_paths(self) -> None:
        if not self.llvm_root_path.exists():
            fail_exit(f"{self.llvm_root_path} does not exist.")
        if not self.llvm_include_dir.exists():
            fail_exit(f"{self.llvm_include_dir} does not exist.")
        if not self.llvm_target_dir.exists():
            fail_exit(f"{self.llvm_target_dir} does not exist.")
        if not self.llvm_tblgen.exists():
            fail_exit(f"{self.llvm_tblgen} does not exist. Have you build llvm-tblgen?")
        if not self.output_dir.exists():
            fail_exit(f"{self.output_dir} does not exist.")

        self.output_dir_c_inc = self.output_dir.joinpath("llvm_c_inc")
        self.output_dir_cpp_inc = self.output_dir.joinpath("llvm_cpp_inc")
        if not self.output_dir_c_inc.is_dir():
            log.info(f"{self.output_dir_c_inc} does not exist. Creating it...")
            os.makedirs(self.output_dir_c_inc)
        if not self.output_dir_cpp_inc.is_dir():
            log.info(f"{self.output_dir_cpp_inc} does not exist. Creating it...")
            os.makedirs(self.output_dir_cpp_inc)

    def generate(self) -> None:
        self.gen_incs()
        self.patch_incs()

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
                    raise e

    def patch_incs(self) -> None:
        # Patch LLVM commit
        # Apply patches
        pass
