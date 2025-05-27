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
            case "LoongArch":
                return res + get_LoongArch_includes(filename) + get_general_macros()
            case "Mips":
                return res + get_Mips_includes(filename) + get_general_macros()
            case "SystemZ":
                return res + get_SystemZ_includes(filename) + get_general_macros()
            case "Xtensa":
                return res + get_Xtensa_includes(filename) + get_general_macros()
            case "ARC":
                return res + get_ARC_includes(filename) + get_general_macros()
            case "Sparc":
                return res + get_sparc_includes(filename) + get_general_macros()
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
                + b"#define GET_REGINFO_ENUM\n"
                + b'#include "AArch64GenRegisterInfo.inc"\n\n'
                + b"#define GET_INSTRINFO_ENUM\n"
                + b'#include "AArch64GenInstrInfo.inc"\n\n'
            )
        case "AArch64AddressingModes.h":
            return b"#include <assert.h>\n" + b'#include "../../MathExtras.h"\n\n'
    log.fatal(f"No includes given for AArch64 source file: {filename}")
    exit(1)


def get_LoongArch_includes(filename: str) -> bytes:
    match filename:
        case "LoongArchDisassembler.cpp":
            return (
                b'#include "../../MCInst.h"\n'
                + b'#include "../../MathExtras.h"\n'
                + b'#include "../../MCInstPrinter.h"\n'
                + b'#include "../../MCDisassembler.h"\n'
                + b'#include "../../MCFixedLenDisassembler.h"\n'
                + b'#include "../../cs_priv.h"\n'
                + b'#include "../../utils.h"\n'
                + b'#include "LoongArchDisassemblerExtension.h"\n'
                + b"#define GET_SUBTARGETINFO_ENUM\n"
                + b'#include "LoongArchGenSubtargetInfo.inc"\n\n'
                + b"#define GET_INSTRINFO_ENUM\n"
                + b'#include "LoongArchGenInstrInfo.inc"\n\n'
                + b"#define GET_REGINFO_ENUM\n"
                + b'#include "LoongArchGenRegisterInfo.inc"\n\n'
            )
        case "LoongArchInstPrinter.cpp":
            return (
                b'#include "LoongArchMapping.h"\n'
                + b'#include "LoongArchInstPrinter.h"\n\n'
                + b"#define GET_SUBTARGETINFO_ENUM\n"
                + b'#include "LoongArchGenSubtargetInfo.inc"\n\n'
                + b"#define GET_INSTRINFO_ENUM\n"
                + b'#include "LoongArchGenInstrInfo.inc"\n\n'
                + b"#define GET_REGINFO_ENUM\n"
                + b'#include "LoongArchGenRegisterInfo.inc"\n\n'
            )
        case "LoongArchInstPrinter.h":
            return (
                b'#include "../../MCInstPrinter.h"\n' + b'#include "../../cs_priv.h"\n'
            )
    log.fatal(f"No includes given for LoongArch source file: {filename}")
    exit(1)


def get_Mips_includes(filename: str) -> bytes:
    match filename:
        case "MipsDisassembler.cpp":
            return (
                b'#include "../../MCInst.h"\n'
                + b'#include "../../MathExtras.h"\n'
                + b'#include "../../MCInstPrinter.h"\n'
                + b'#include "../../MCDisassembler.h"\n'
                + b'#include "../../MCFixedLenDisassembler.h"\n'
                + b'#include "../../cs_priv.h"\n'
                + b'#include "../../utils.h"\n'
                + b"#define GET_SUBTARGETINFO_ENUM\n"
                + b'#include "MipsGenSubtargetInfo.inc"\n\n'
                + b"#define GET_INSTRINFO_ENUM\n"
                + b'#include "MipsGenInstrInfo.inc"\n\n'
                + b"#define GET_REGINFO_ENUM\n"
                + b'#include "MipsGenRegisterInfo.inc"\n\n'
            )
        case "MipsInstPrinter.cpp":
            return (
                b'#include "MipsMapping.h"\n'
                + b'#include "MipsInstPrinter.h"\n\n'
                + b"#define GET_SUBTARGETINFO_ENUM\n"
                + b'#include "MipsGenSubtargetInfo.inc"\n\n'
                + b"#define GET_INSTRINFO_ENUM\n"
                + b'#include "MipsGenInstrInfo.inc"\n\n'
                + b"#define GET_REGINFO_ENUM\n"
                + b'#include "MipsGenRegisterInfo.inc"\n\n'
            )
        case "MipsInstPrinter.h":
            return (
                b'#include "../../MCInstPrinter.h"\n' + b'#include "../../cs_priv.h"\n'
            )
    log.fatal(f"No includes given for Mips source file: {filename}")
    exit(1)


def get_SystemZ_includes(filename: str) -> bytes:
    match filename:
        case "SystemZDisassembler.cpp":
            return (
                b'#include "../../MCInst.h"\n'
                + b'#include "../../MathExtras.h"\n'
                + b'#include "../../cs_priv.h"\n'
                + b'#include "../../utils.h"\n\n'
                + b'#include "SystemZMCTargetDesc.h"\n'
                + b'#include "SystemZDisassemblerExtension.h"\n\n'
                + b"#define GET_SUBTARGETINFO_ENUM\n"
                + b'#include "SystemZGenSubtargetInfo.inc"\n\n'
                + b"#define GET_INSTRINFO_ENUM\n"
                + b'#include "SystemZGenInstrInfo.inc"\n\n'
                + b"#define GET_REGINFO_ENUM\n"
                + b'#include "SystemZGenRegisterInfo.inc"\n\n'
            )
        case "SystemZInstPrinter.cpp":
            return (
                b'#include "../../MCAsmInfo.h"\n'
                + b'#include "SystemZMapping.h"\n'
                + b'#include "SystemZInstPrinter.h"\n\n'
                + b"#define GET_SUBTARGETINFO_ENUM\n"
                + b'#include "SystemZGenSubtargetInfo.inc"\n\n'
                + b"#define GET_INSTRINFO_ENUM\n"
                + b'#include "SystemZGenInstrInfo.inc"\n\n'
                + b"#define GET_REGINFO_ENUM\n"
                + b'#include "SystemZGenRegisterInfo.inc"\n\n'
            )
        case "SystemZInstPrinter.h":
            return b"\n"
        case "SystemZMCTargetDesc.h":
            return (
                b'#include "../../MCInstPrinter.h"\n' + b'#include "../../cs_priv.h"\n'
            )
        case "SystemZMCTargetDesc.cpp":
            return (
                b'#include "../../MCInst.h"\n'
                + b'#include "../../MCRegisterInfo.h"\n\n'
                + b'#include "SystemZMCTargetDesc.h"\n'
                + b'#include "SystemZInstPrinter.h"\n\n'
                + b"#define GET_INSTRINFO_MC_DESC\n"
                + b"#define ENABLE_INSTR_PREDICATE_VERIFIER\n"
                + b'#include "SystemZGenInstrInfo.inc"\n\n'
                + b"#define GET_SUBTARGETINFO_MC_DESC\n"
                + b'#include "SystemZGenSubtargetInfo.inc"\n\n'
                + b"#define GET_REGINFO_MC_DESC\n"
                + b'#include "SystemZGenRegisterInfo.inc"\n\n'
            )
    log.fatal(f"No includes given for SystemZ source file: {filename}")
    exit(1)


def get_Xtensa_includes(filename: str) -> bytes:
    match filename:
        case "XtensaDisassembler.cpp":
            return b"""
#include "../../MathExtras.h"
#include "../../MCDisassembler.h"
#include "../../MCFixedLenDisassembler.h"
#include "../../SStream.h"
#include "../../cs_priv.h"
#include "priv.h"

#define GET_INSTRINFO_MC_DESC
#include "XtensaGenInstrInfo.inc"

"""
        case "XtensaInstPrinter.cpp":
            return b"""
#include "../../MCInstPrinter.h"
#include "../../SStream.h"
#include "XtensaMapping.h"
#include "priv.h"
        """
        case _:
            return b""


def get_ARC_includes(filename: str) -> bytes:
    match filename:
        case "ARCDisassembler.cpp":
            return (
                b'#include "../../MCInst.h"\n'
                + b'#include "../../SStream.h"\n'
                + b'#include "../../MCDisassembler.h"\n'
                + b'#include "../../MCFixedLenDisassembler.h"\n'
                + b'#include "../../MathExtras.h"\n'
                + b'#include "../../utils.h"\n'
            )
        case "ARCInstPrinter.cpp":
            return (
                b'#include "../../SStream.h"\n'
                + b'#include "../../MCInst.h"\n'
                + b'#include "../../MCInstPrinter.h"\n'
                + b'#include "ARCInfo.h"\n'
                + b'#include "ARCInstPrinter.h"\n'
                + b'#include "ARCLinkage.h"\n'
                + b'#include "ARCMapping.h"\n'
            )
        case "ARCInstPrinter.h":
            return b'#include "../../SStream.h"\n' + b'#include "../../MCInst.h"\n'
    log.fatal(f"No includes given for ARC source file: {filename}")
    exit(1)


def get_sparc_includes(filename: str) -> bytes:
    match filename:
        case "SparcDisassembler.cpp":
            return (
                b'#include "../../MCDisassembler.h"\n'
                + b'#include "../../MCFixedLenDisassembler.h"\n'
                + b'#include "SparcDisassemblerExtension.h"\n'
                + b'#include "SparcLinkage.h"\n'
                + b'#include "SparcMapping.h"\n'
                + b'#include "SparcMCTargetDesc.h"\n'
            )
        case "SparcInstPrinter.cpp":
            return (
                b'#include "SparcInstrInfo.h"\n'
                + b'#include "SparcInstPrinter.h"\n'
                + b'#include "SparcLinkage.h"\n'
                + b'#include "SparcMCTargetDesc.h"\n'
                + b'#include "SparcMapping.h"\n'
                + b'#include "SparcRegisterInfo.h"\n\n'
            )
        case "SparcInstPrinter.h":
            return b'#include "SparcMCTargetDesc.h"\n\n'
        case "SparcMCTargetDesc.h":
            return (
                b'#include "../../LEB128.h"\n'
                + b'#include "../../MathExtras.h"\n'
                + b'#include "../../MCInst.h"\n'
                + b'#include "../../MCInstrDesc.h"\n'
                + b'#include "../../MCRegisterInfo.h"\n'
            )
    log.fatal(f"No includes given for Sparc source file: {filename}")
    exit(1)


def get_general_macros():
    return (
        b"#define CONCAT(a, b) CONCAT_(a, b)\n" b"#define CONCAT_(a, b) a ## _ ## b\n"
    )
