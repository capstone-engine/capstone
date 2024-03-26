# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import logging as log

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class Includes(Patch):
    """
    Patch   LLVM includes
    to      Capstone includes
    """

    include_count = dict()

    def __init__(self, priority: int, arch: str):
        self.arch = arch
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return "(preproc_include) @preproc_include"

    def get_main_capture_name(self) -> str:
        return "preproc_include"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        filename = kwargs["filename"]
        if filename not in self.include_count:
            self.include_count[filename] = 1
        else:
            self.include_count[filename] += 1

        include_text = get_text(src, captures[0][0].start_byte, captures[0][0].end_byte)
        # Special cases, which appear somewhere in the code.
        if b"GenDisassemblerTables.inc" in include_text:
            return (
                b'#include "'
                + bytes(self.arch, "utf8")
                + b'GenDisassemblerTables.inc"\n\n'
            )
        elif b"GenAsmWriter.inc" in include_text:
            return b'#include "' + bytes(self.arch, "utf8") + b'GenAsmWriter.inc"\n\n'
        elif b"GenSystemOperands.inc" in include_text:
            return (
                b'#include "' + bytes(self.arch, "utf8") + b'GenSystemOperands.inc"\n\n'
            )

        if self.include_count[filename] > 1:
            # Only the first include is replaced with all CS includes.
            return b""

        # All includes which belong to the source files top.
        res = get_general_inc()
        match self.arch:
            case "ARM":
                return res + get_ARM_includes(filename) + get_general_macros()
            case "PPC":
                return res + get_PPC_includes(filename) + get_general_macros()
            case "AArch64":
                return res + get_AArch64_includes(filename) + get_general_macros()
            case "TEST_ARCH":
                return res + b"test_output"
            case _:
                log.fatal(f"Includes of {self.arch} not handled.")
                exit(1)


def get_general_inc() -> bytes:
    return (
        b"#include <stdio.h>\n"
        + b"#include <string.h>\n"
        + b"#include <stdlib.h>\n"
        + b"#include <capstone/platform.h>\n\n"
    )


def get_PPC_includes(filename: str) -> bytes:
    match filename:
        case "PPCDisassembler.cpp":
            return (
                b'#include "../../LEB128.h"\n'
                + b'#include "../../MCDisassembler.h"\n'
                + b'#include "../../MCFixedLenDisassembler.h"\n'
                + b'#include "../../MCInst.h"\n'
                + b'#include "../../MCInstrDesc.h"\n'
                + b'#include "../../MCInstPrinter.h"\n'
                + b'#include "../../MCRegisterInfo.h"\n'
                + b'#include "../../SStream.h"\n'
                + b'#include "../../utils.h"\n'
                + b'#include "PPCLinkage.h"\n'
                + b'#include "PPCMapping.h"\n'
                + b'#include "PPCMCTargetDesc.h"\n'
                + b'#include "PPCPredicates.h"\n\n'
            )
        case "PPCInstPrinter.cpp":
            return (
                b'#include "../../LEB128.h"\n'
                + b'#include "../../MCInst.h"\n'
                + b'#include "../../MCInstrDesc.h"\n'
                + b'#include "../../MCInstPrinter.h"\n'
                + b'#include "../../MCRegisterInfo.h"\n'
                + b'#include "PPCInstrInfo.h"\n'
                + b'#include "PPCInstPrinter.h"\n'
                + b'#include "PPCLinkage.h"\n'
                + b'#include "PPCMCTargetDesc.h"\n'
                + b'#include "PPCMapping.h"\n'
                + b'#include "PPCPredicates.h"\n\n'
                + b'#include "PPCRegisterInfo.h"\n\n'
            )
        case "PPCInstPrinter.h":
            return (
                b'#include "../../LEB128.h"\n'
                + b'#include "../../MCDisassembler.h"\n'
                + b'#include "../../MCInst.h"\n'
                + b'#include "../../MCInstrDesc.h"\n'
                + b'#include "../../MCRegisterInfo.h"\n'
                + b'#include "../../SStream.h"\n'
                + b'#include "PPCMCTargetDesc.h"\n\n'
            )
        case "PPCMCTargetDesc.h":
            return (
                b'#include "../../LEB128.h"\n'
                + b'#include "../../MathExtras.h"\n'
                + b'#include "../../MCInst.h"\n'
                + b'#include "../../MCInstrDesc.h"\n'
                + b'#include "../../MCRegisterInfo.h"\n'
            )
    log.fatal(f"No includes given for PPC source file: {filename}")
    exit(1)


def get_ARM_includes(filename: str) -> bytes:
    match filename:
        case "ARMDisassembler.cpp":
            return (
                b'#include "../../LEB128.h"\n'
                + b'#include "../../MCDisassembler.h"\n'
                + b'#include "../../MCFixedLenDisassembler.h"\n'
                + b'#include "../../MCInst.h"\n'
                + b'#include "../../MCInstrDesc.h"\n'
                + b'#include "../../MCRegisterInfo.h"\n'
                + b'#include "../../MathExtras.h"\n'
                + b'#include "../../cs_priv.h"\n'
                + b'#include "../../utils.h"\n'
                + b'#include "ARMAddressingModes.h"\n'
                + b'#include "ARMBaseInfo.h"\n'
                + b'#include "ARMDisassemblerExtension.h"\n'
                + b'#include "ARMInstPrinter.h"\n'
                + b'#include "ARMLinkage.h"\n'
                + b'#include "ARMMapping.h"\n\n'
                + b"#define GET_INSTRINFO_MC_DESC\n"
                + b'#include "ARMGenInstrInfo.inc"\n\n'
            )
        case "ARMInstPrinter.cpp":
            return (
                b'#include "../../Mapping.h"\n'
                + b'#include "../../MCInst.h"\n'
                + b'#include "../../MCInstPrinter.h"\n'
                + b'#include "../../MCRegisterInfo.h"\n'
                + b'#include "../../SStream.h"\n'
                + b'#include "../../utils.h"\n'
                + b'#include "ARMAddressingModes.h"\n'
                + b'#include "ARMBaseInfo.h"\n'
                + b'#include "ARMDisassemblerExtension.h"\n'
                + b'#include "ARMInstPrinter.h"\n'
                + b'#include "ARMLinkage.h"\n'
                + b'#include "ARMMapping.h"\n\n'
                + b"#define GET_BANKEDREG_IMPL\n"
                + b'#include "ARMGenSystemRegister.inc"\n'
            )
        case "ARMInstPrinter.h":
            return (
                b'#include "ARMMapping.h"\n\n'
                + b'#include "../../MCInst.h"\n'
                + b'#include "../../SStream.h"\n'
                + b'#include "../../MCRegisterInfo.h"\n'
                + b'#include "../../MCInstPrinter.h"\n'
                + b'#include "../../utils.h"\n\n'
            )
        case "ARMBaseInfo.cpp":
            return b'#include "ARMBaseInfo.h"\n\n'
        case "ARMAddressingModes.h":
            return b"#include <assert.h>\n" + b'#include "../../MathExtras.h"\n\n'
    log.fatal(f"No includes given for ARM source file: {filename}")
    exit(1)


def get_AArch64_includes(filename: str) -> bytes:
    match filename:
        case "AArch64Disassembler.cpp":
            return (
                b'#include "../../MCFixedLenDisassembler.h"\n'
                + b'#include "../../MCInst.h"\n'
                + b'#include "../../MCInstrDesc.h"\n'
                + b'#include "../../MCRegisterInfo.h"\n'
                + b'#include "../../LEB128.h"\n'
                + b'#include "../../MCDisassembler.h"\n'
                + b'#include "../../cs_priv.h"\n'
                + b'#include "../../utils.h"\n'
                + b'#include "AArch64AddressingModes.h"\n'
                + b'#include "AArch64BaseInfo.h"\n'
                + b'#include "AArch64DisassemblerExtension.h"\n'
                + b'#include "AArch64Linkage.h"\n'
                + b'#include "AArch64Mapping.h"\n\n'
                + b"#define GET_INSTRINFO_MC_DESC\n"
                + b'#include "AArch64GenInstrInfo.inc"\n\n'
                + b"#define GET_INSTRINFO_ENUM\n"
                + b'#include "AArch64GenInstrInfo.inc"\n\n'
            )
        case "AArch64InstPrinter.cpp":
            return (
                b'#include "../../MCInst.h"\n'
                + b'#include "../../MCInstPrinter.h"\n'
                + b'#include "../../MCRegisterInfo.h"\n'
                + b'#include "../../SStream.h"\n'
                + b'#include "../../utils.h"\n'
                + b'#include "AArch64AddressingModes.h"\n'
                + b'#include "AArch64BaseInfo.h"\n'
                + b'#include "AArch64DisassemblerExtension.h"\n'
                + b'#include "AArch64InstPrinter.h"\n'
                + b'#include "AArch64Linkage.h"\n'
                + b'#include "AArch64Mapping.h"\n\n'
                + b"#define GET_BANKEDREG_IMPL\n"
                + b'#include "AArch64GenSystemOperands.inc"\n\n'
                + b"#define CONCATs(a, b) CONCATS(a, b)\n"
                + b"#define CONCATS(a, b) a##b\n\n"
            )
        case "AArch64InstPrinter.h":
            return (
                b'#include "AArch64Mapping.h"\n\n'
                + b'#include "../../MCInst.h"\n'
                + b'#include "../../MCRegisterInfo.h"\n'
                + b'#include "../../MCInstPrinter.h"\n'
                + b'#include "../../SStream.h"\n'
                + b'#include "../../utils.h"\n\n'
            )
        case "AArch64BaseInfo.cpp":
            return b'#include "AArch64BaseInfo.h"\n\n'
        case "AArch64BaseInfo.h":
            return (
                b'#include "../../utils.h"\n'
                + b'#include "capstone/arm.h"\n\n'
                + b"#define GET_REGINFO_ENUM\n"
                + b'#include "AArch64GenRegisterInfo.inc"\n\n'
                + b"#define GET_INSTRINFO_ENUM\n"
                + b'#include "AArch64GenInstrInfo.inc"\n\n'
            )
        case "AArch64AddressingModes.h":
            return b"#include <assert.h>\n" + b'#include "../../MathExtras.h"\n\n'
    log.fatal(f"No includes given for AArch64 source file: {filename}")
    exit(1)


def get_general_macros():
    return (
        b"#define CONCAT(a, b) CONCAT_(a, b)\n" b"#define CONCAT_(a, b) a ## _ ## b\n"
    )
