import logging as log
import re

from tree_sitter import Node

from Patches.HelperMethods import get_text
from Patches.Patch import Patch


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
            return b'#include "' + bytes(self.arch, "utf8") + b'GenDisassemblerTables.inc"\n\n'
        elif b"GenAsmWriter.inc" in include_text:
            return b'#include "' + bytes(self.arch, "utf8") + b'GenAsmWriter.inc"\n\n'

        if self.include_count[filename] > 1:
            # Only the first include is replaced with all CS includes.
            return b""

        # All includes which belong to the source files top.
        res = get_general_inc()
        if self.arch == "ARM":
            return res + get_ARM_includes(filename) + get_general_macros()
        else:
            log.fatal(f"Includes of {self.arch} not handled.")
            exit(1)


def get_general_inc() -> bytes:
    return (
        b"#include <stdio.h>\n"
        + b"#include <string.h>\n"
        + b"#include <stdlib.h>\n"
        + b"#include <capstone/platform.h>\n\n"
    )


def get_ARM_includes(filename: str) -> bytes:
    if filename == "ARMDisassembler.cpp":
        return (
            b'#include "ARMAddressingModes.h"\n'
            + b'#include "ARMBaseInfo.h"\n'
            + b'#include "../../MCFixedLenDisassembler.h"\n'
            + b'#include "../../MCInst.h"\n'
            + b'#include "../../MCInstrDesc.h"\n'
            + b'#include "../../MCRegisterInfo.h"\n'
            + b'#include "../../LEB128.h"\n'
            + b'#include "../../MCDisassembler.h"\n'
            + b'#include "../../cs_priv.h"\n'
            + b'#include "../../utils.h"\n'
            + b'#include "ARMDisassembler.h"\n'
            + b'#include "ARMMapping.h"\n\n'
            + b"#define GET_INSTRINFO_MC_DESC\n"
            + b'#include "ARMGenInstrInfo.inc"\n\n'
            + b"#define GET_INSTRINFO_ENUM\n"
            + b'#include "ARMGenInstrInfo.inc"\n\n'
        )
    elif filename == "ARMInstPrinter.cpp":
        return (
            b'#include "../../MCInst.h"\n'
            + b'#include "../../MCInstPrinter.h"\n'
            + b'#include "../../MCRegisterInfo.h"\n'
            + b'#include "../../SStream.h"\n'
            + b'#include "../../utils.h"\n'
            + b'#include "ARMInstPrinter.h"\n'
            + b'#include "ARMAddressingModes.h"\n'
            + b'#include "ARMBaseInfo.h"\n'
            + b'#include "ARMDisassemblerExtension.h"\n'
            + b'#include "ARMMapping.h"\n\n'
            + b"#define GET_BANKEDREG_IMPL\n"
            + b'#include "ARMGenSystemRegister.inc"\n\n'
        )
    elif filename == "ARMInstPrinter.h":
        return (
            b'#include "ARMMapping.h"\n\n'
            + b'#include "../../MCInst.h"\n'
            + b'#include "../../SStream.h"\n'
            + b'#include "../../MCRegisterInfo.h"\n'
            + b'#include "../../MCInstPrinter.h"\n'
            + b'#include "../../utils.h"\n\n'
        )
    elif filename == "ARMBaseInfo.cpp":
        return b'#include "ARMBaseInfo.h"\n\n'
    elif filename == "ARMAddressingModes.h":
        return b"#include <assert.h>\n" + b'#include "../../MathExtras.h"\n\n'
    log.fatal(f"No includes given for ARM source file: {filename}")
    exit(1)


def get_general_macros():
    return b"#define CONCAT(a, b) CONCAT_(a, b)\n" b"#define CONCAT_(a, b) a ## _ ## b\n"
