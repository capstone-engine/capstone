#!/usr/bin/env python3

# Copyright © 2025 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import argparse
import pathlib
import re

archs = [
    "MCInst",
    "aarch64",
    "m68k",
    "ppc",
    "systemz",
    "wasm",
    "alpha",
    "bpf",
    "hppa",
    "mips",
    "riscv",
    "x86",
    "arc",
    "loongarch",
    "mos65xx",
    "sh",
    "tms320c64x",
    "xcore",
    "arm",
    "m680x",
    "sparc",
    "evm",
    "tricore",
    "xtensa",
]

archs_op_getter = {
    "arm": "ARM_get_detail_op",
    "ppc": "PPC_get_detail_op",
    "tricore": "TriCore_get_detail_op",
    "aarch64": "AArch64_get_detail_op",
    "alpha": "Alpha_get_detail_op",
    "hppa": "HPPA_get_detail_op",
    "loongarch": "LoongArch_get_detail_op",
    "mips": "Mips_get_detail_op",
    "riscv": "RISCV_get_detail_op",
    "systemz": "SystemZ_get_detail_op",
    "xtensa": "Xtensa_get_detail_op",
    "bpf": "BPF_get_detail_op",
    "arc": "ARC_get_detail_op",
}

union_members = {
    "MCInst": r"(?P<union_member>(RegVal|ImmVal|FPImmVal))",
    "aarch64": r"(?P<union_member>(reg|imm|imm_range|fp|mem|sme|pred))",
    "alpha": r"(?P<union_member>(reg|imm))",
    "arc": r"(?P<union_member>(reg|imm))",
    "arm": r"(?P<union_member>(reg|sysop|imm|pred|fp|mem|setend))",
    "bpf": r"(?P<union_member>(reg|imm|off|mem|mmem|msh|ext))",
    "hppa": r"(?P<union_member>(reg|imm|mem))",
    "loongarch": r"(?P<union_member>(reg|imm|mem))",
    "m680x": r"(?P<union_member>(imm|reg|idx|rel|ext|direct_addr|const_val))",
    "m68k": r"(?P<union_member>(imm|dimm|simm|reg|reg_pair))",
    "mips": r"(?P<union_member>(reg|imm|uimm|mem))",
    "mos65xx": r"(?P<union_member>(reg|imm|mem))",
    "ppc": r"(?P<union_member>(reg|imm|mem))",
    "riscv": r"(?P<union_member>(reg|imm|mem))",
    "systemz": r"(?P<union_member>(reg|imm|mem))",
    "sh": r"(?P<union_member>(imm|reg|mem|dsp))",
    "sparc": r"(?P<union_member>(reg|imm|mem))",
    "tms320c64x": r"(?P<union_member>(reg|imm|mem))",
    "tricore": r"(?P<union_member>(reg|imm|mem))",
    "wasm": r"(?P<union_member>(int7|varuint32|varuint64|uint32|uint64|immediate|brtable))",
    "x86": r"(?P<union_member>(reg|imm|mem))",
    "xcore": r"(?P<union_member>(reg|imm|mem))",
    "xtensa": r"(?P<union_member>(reg|imm|mem))",
}

operand_var_names = {
    "MCInst": "(?P<operand_name>(op|MI|Inst|MC))",
    "aarch64": "(?P<operand_name>(aarch64|op))",
    "alpha": "(?P<operand_name>(alpha|op))",
    "arc": "(?P<operand_name>(arc|op))",
    "arm": "(?P<operand_name>(arm|op))",
    "bpf": "(?P<operand_name>(bpf|op))",
    "hppa": "(?P<operand_name>(hppa|op))",
    "loongarch": "(?P<operand_name>(loongarch|op))",
    "m680x": "(?P<operand_name>(m680x|op))",
    "m68k": "(?P<operand_name>(m68k|op))",
    "mips": "(?P<operand_name>(mips|op))",
    "mos65xx": "(?P<operand_name>(mos65xx|op))",
    "ppc": "(?P<operand_name>(ppc|op))",
    "riscv": "(?P<operand_name>(riscv|op))",
    "systemz": "(?P<operand_name>(systemz|op))",
    "sh": "(?P<operand_name>(sh|op))",
    "sparc": "(?P<operand_name>(sparc|op))",
    "tms320c64x": "(?P<operand_name>(tms320c64x|op))",
    "tricore": "(?P<operand_name>(tricore|op))",
    "wasm": "(?P<operand_name>(wasm|op))",
    "x86": "(?P<operand_name>(x86|op))",
    "xcore": "(?P<operand_name>(xcore|op))",
    "xtensa": "(?P<operand_name>(xtensa|op))",
}

# Acces via:
# .
# ->
# .operands[<some index>].
# ->operands[<some index>].
val_access = {
    "MCInst": rf"(?P<val_access>(\.|->)(Operands\[.+\]\.)?)",
    "aarch64": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "alpha": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "arc": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "arm": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "bpf": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "hppa": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "loongarch": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "m680x": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "m68k": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "mips": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "mos65xx": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "ppc": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "riscv": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "systemz": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "sh": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "sparc": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "tms320c64x": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "tricore": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "wasm": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "x86": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "xcore": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
    "xtensa": rf"(?P<val_access>(\.|->)(operands\[.+\]\.)?)",
}

unions = [
    "cs_detail",
    "value_unions",
    "x86_flags",
    "hppa_mod",
    "m68k_size",
]


def fix_cs_detail(line: str, arch: str) -> str:
    re_access = rf"detail(\.|->)({arch})"
    return re.sub(re_access, r"detail\1d.\2", line)


def fix_value_unions(line: str, arch: str, op_variable: str) -> str:
    if arch not in union_members:
        return line
    line = re.sub(
        rf"\b{operand_var_names[arch]}{val_access[arch]}{union_members[arch]}\b", rf"\g<operand_name>\g<val_access>v.\g<union_member>", line
    )
    if arch in archs_op_getter:
        line = re.sub(
            rf"({archs_op_getter[arch]}\(.+\)->){union_members[arch]}\b",
            rf"\1v.\g<union_member>",
            line,
        )
    if op_variable:
        line = re.sub(
            rf"\b(?P<op_variable>{op_variable})(?P<access>\.|->){union_members[arch]}\b", rf"\g<op_variable>\g<access>v.\g<union_member>", line
        )

    return line


def fix_x86_flags(line: str) -> str:
    re_access = rf"x86(.|->)(eflags|fpu_flags)"
    return re.sub(re_access, r"x86\1flags.\2", line)


def fix_hppa_mod(line: str) -> str:
    re_access = rf"modifiers\[(.+)]\.(str_mod|int_mod)"
    return re.sub(re_access, r"modifiers[\1].mod.\2", line)


def fix_m68k_size(line: str) -> str:
    re_access = rf"op_size.(fpu_size|cpu_size)"
    return re.sub(re_access, r"op_size.size.\1", line)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="C99 Refactor Helper",
        description="Searches and fixes up the union access in code.",
    )
    parser.add_argument(
        "-a",
        dest="archs",
        help="Architecture to fix up.",
        choices=archs,
        default=archs,
        nargs="+",
    )
    parser.add_argument(
        "-s",
        dest="unions",
        help="List of unions to fix.",
        choices=unions,
        default=unions,
        nargs="+",
    )
    parser.add_argument(
        "-f",
        dest="file",
        help="File to fix.",
        type=pathlib.Path,
        required=True,
    )
    parser.add_argument(
        "-o",
        dest="op_variable",
        help="The cs_<arch>_op variable name in the file. E.g. for: 'cs_arm_op Op = detail->arm.operands[0]' the variable name is 'Op'. Can be a regex.",
        required=False,
    )
    arguments = parser.parse_args()
    return arguments


def main():
    args = parse_args()
    with open(args.file) as f:
        content = f.readlines()
    result = []
    archs_to_handle = args.archs
    if len(args.archs) == len(archs):
        # All archs requested. Check file name if we can get the name from there
        # to prevent false positives.
        for a in archs:
            if a in args.file.name:
                # Found, assume this is the arch
                archs_to_handle = [a]
                break
    for line in content:
        if "cs_detail" in args.unions:
            for arch in archs_to_handle:
                line = fix_cs_detail(line, arch)
        if "value_unions" in args.unions:
            for arch in archs_to_handle:
                line = fix_value_unions(line, arch, args.op_variable)
        if "x86_flags" in args.unions and "x86" in args.archs:
            line = fix_x86_flags(line)
        if "hppa_mod" in args.unions and "hppa" in args.archs:
            line = fix_hppa_mod(line)
        if "m68k_size" in args.unions and "m68k" in args.archs:
            line = fix_m68k_size(line)
        result.append(line)

    with open(args.file, "w") as f:
        f.writelines(result)


if __name__ == "__main__":
    main()
