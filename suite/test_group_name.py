#!/usr/bin/python

from capstone import *
from capstone.arm import *
from capstone.arm64 import *
from capstone.mips import *
from capstone.ppc import *
from capstone.sparc import *
from capstone.systemz import *
from capstone.x86 import *
from capstone.xcore import *
import sys

# yes this is bad, importing ctypes like this,
# but the Cs object did not have the group_name function
from capstone import _cs

class GroupTest:
    def __init__(self, name, arch, mode, data):
        self.name = name
        self.arch = arch
        self.mode = mode
        self.data = data

    def run(self):
        print('Testing %s' %self.name)
        cap = Cs(self.arch, self.mode)
        for group_id in xrange(0,255):
            name = self.data.get(group_id)
            res = _cs.cs_group_name(cap.csh, group_id)
            if res != name:
                print("ERROR: expected '%s', but got '%s'" %(name, res))
        print("")

arm_dict = {
    ARM_GRP_JUMP: "jump",

    ARM_GRP_CRYPTO: "crypto",
    ARM_GRP_DATABARRIER: "databarrier",
    ARM_GRP_DIVIDE: "divide",
    ARM_GRP_FPARMV8: "fparmv8",
    ARM_GRP_MULTPRO: "multpro",
    ARM_GRP_NEON: "neon",
    ARM_GRP_T2EXTRACTPACK: "T2EXTRACTPACK",
    ARM_GRP_THUMB2DSP: "THUMB2DSP",
    ARM_GRP_TRUSTZONE: "TRUSTZONE",
    ARM_GRP_V4T: "v4t",
    ARM_GRP_V5T: "v5t",
    ARM_GRP_V5TE: "v5te",
    ARM_GRP_V6: "v6",
    ARM_GRP_V6T2: "v6t2",
    ARM_GRP_V7: "v7",
    ARM_GRP_V8: "v8",
    ARM_GRP_VFP2: "vfp2",
    ARM_GRP_VFP3: "vfp3",
    ARM_GRP_VFP4: "vfp4",
    ARM_GRP_ARM: "arm",
    ARM_GRP_MCLASS: "mclass",
    ARM_GRP_NOTMCLASS: "notmclass",
    ARM_GRP_THUMB: "thumb",
    ARM_GRP_THUMB1ONLY: "thumb1only",
    ARM_GRP_THUMB2: "thumb2",
    ARM_GRP_PREV8: "prev8",
    ARM_GRP_FPVMLX: "fpvmlx",
    ARM_GRP_MULOPS: "mulops",
    ARM_GRP_CRC: "crc",
    ARM_GRP_DPVFP: "dpvfp",
    ARM_GRP_V6M: "v6m",
}

arm64_dict = {
    ARM64_GRP_JUMP: "jump",

    ARM64_GRP_CRYPTO: "crypto",
    ARM64_GRP_FPARMV8: "fparmv8",
    ARM64_GRP_NEON: "neon",
    ARM64_GRP_CRC: "crc"
}

mips_dict = {
    MIPS_GRP_JUMP: "jump",
    MIPS_GRP_BITCOUNT: "bitcount",
    MIPS_GRP_DSP: "dsp",
    MIPS_GRP_DSPR2: "dspr2",
    MIPS_GRP_FPIDX: "fpidx",
    MIPS_GRP_MSA: "msa",
    MIPS_GRP_MIPS32R2: "mips32r2",
    MIPS_GRP_MIPS64: "mips64",
    MIPS_GRP_MIPS64R2: "mips64r2",
    MIPS_GRP_SEINREG: "seinreg",
    MIPS_GRP_STDENC: "stdenc",
    MIPS_GRP_SWAP: "swap",
    MIPS_GRP_MICROMIPS: "micromips",
    MIPS_GRP_MIPS16MODE: "mips16mode",
    MIPS_GRP_FP64BIT: "fp64bit",
    MIPS_GRP_NONANSFPMATH: "nonansfpmath",
    MIPS_GRP_NOTFP64BIT: "notfp64bit",
    MIPS_GRP_NOTINMICROMIPS: "notinmicromips",
    MIPS_GRP_NOTNACL: "notnacl",

    MIPS_GRP_NOTMIPS32R6: "notmips32r6",
    MIPS_GRP_NOTMIPS64R6: "notmips64r6",
    MIPS_GRP_CNMIPS: "cnmips",

    MIPS_GRP_MIPS32: "mips32",
    MIPS_GRP_MIPS32R6: "mips32r6",
    MIPS_GRP_MIPS64R6: "mips64r6",

    MIPS_GRP_MIPS2: "mips2",
    MIPS_GRP_MIPS3: "mips3",
    MIPS_GRP_MIPS3_32: "mips3_32",
    MIPS_GRP_MIPS3_32R2: "mips3_32r2",

    MIPS_GRP_MIPS4_32: "mips4_32",
    MIPS_GRP_MIPS4_32R2: "mips4_32r2",
    MIPS_GRP_MIPS5_32R2: "mips5_32r2",

    MIPS_GRP_GP32BIT: "gp32bit",
    MIPS_GRP_GP64BIT: "gp64bit",
}

ppc_dict = {
    PPC_GRP_JUMP: "jump",

    PPC_GRP_ALTIVEC: "altivec",
    PPC_GRP_MODE32: "mode32",
    PPC_GRP_MODE64: "mode64",
    PPC_GRP_BOOKE: "booke",
    PPC_GRP_NOTBOOKE: "notbooke",
    PPC_GRP_SPE: "spe",
    PPC_GRP_VSX: "vsx",
    PPC_GRP_E500: "e500",
    PPC_GRP_PPC4XX: "ppc4xx",
    PPC_GRP_PPC6XX: "ppc6xx",
}

sparc_dict = {
    SPARC_GRP_JUMP: "jump",

    SPARC_GRP_HARDQUAD: "hardquad",
    SPARC_GRP_V9: "v9",
    SPARC_GRP_VIS: "vis",
    SPARC_GRP_VIS2: "vis2",
    SPARC_GRP_VIS3: "vis3",
    SPARC_GRP_32BIT: "32bit",
    SPARC_GRP_64BIT: "64bit",
}

sysz_dict = {
    SYSZ_GRP_JUMP: "jump",

    SYSZ_GRP_DISTINCTOPS: "distinctops",
    SYSZ_GRP_FPEXTENSION: "fpextension",
    SYSZ_GRP_HIGHWORD: "highword",
    SYSZ_GRP_INTERLOCKEDACCESS1: "interlockedaccess1",
    SYSZ_GRP_LOADSTOREONCOND: "loadstoreoncond",
}

x86_dict = {
    X86_GRP_JUMP: "jump",
    X86_GRP_CALL: "call",
    X86_GRP_RET: "ret",
    X86_GRP_INT: "int",
    X86_GRP_IRET: "iret",

    X86_GRP_VM: "vm",
    X86_GRP_3DNOW: "3dnow",
    X86_GRP_AES: "aes",
    X86_GRP_ADX: "adx",
    X86_GRP_AVX: "avx",
    X86_GRP_AVX2: "avx2",
    X86_GRP_AVX512: "avx512",
    X86_GRP_BMI: "bmi",
    X86_GRP_BMI2: "bmi2",
    X86_GRP_CMOV: "cmov",
    X86_GRP_F16C: "fc16",
    X86_GRP_FMA: "fma",
    X86_GRP_FMA4: "fma4",
    X86_GRP_FSGSBASE: "fsgsbase",
    X86_GRP_HLE: "hle",
    X86_GRP_MMX: "mmx",
    X86_GRP_MODE32: "mode32",
    X86_GRP_MODE64: "mode64",
    X86_GRP_RTM: "rtm",
    X86_GRP_SHA: "sha",
    X86_GRP_SSE1: "sse1",
    X86_GRP_SSE2: "sse2",
    X86_GRP_SSE3: "sse3",
    X86_GRP_SSE41: "sse41",
    X86_GRP_SSE42: "sse42",
    X86_GRP_SSE4A: "sse4a",
    X86_GRP_SSSE3: "ssse3",
    X86_GRP_PCLMUL: "pclmul",
    X86_GRP_XOP: "xop",
    X86_GRP_CDI: "cdi",
    X86_GRP_ERI: "eri",
    X86_GRP_TBM: "tbm",
    X86_GRP_16BITMODE: "16bitmode",
    X86_GRP_NOT64BITMODE: "not64bitmode",
    X86_GRP_SGX: "sgx",
    X86_GRP_DQI: "dqi",
    X86_GRP_BWI: "bwi",
    X86_GRP_PFI: "pfi",
    X86_GRP_VLX: "vlx",
    X86_GRP_SMAP: "smap",
    X86_GRP_NOVLX: "novlx",
}

xcore_dict = {
    XCORE_GRP_JUMP: "jump",
}

tests = [
    GroupTest('arm', CS_ARCH_ARM, CS_MODE_THUMB, arm_dict),
    GroupTest('arm64', CS_ARCH_ARM64, CS_MODE_ARM, arm64_dict),
    GroupTest('mips', CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN, mips_dict),
    GroupTest('ppc', CS_ARCH_PPC, CS_MODE_BIG_ENDIAN, ppc_dict),
    GroupTest('sparc', CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN, sparc_dict),
    GroupTest('sysz', CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN, sysz_dict),
    GroupTest('x86', CS_ARCH_X86, CS_MODE_32, x86_dict),
    GroupTest('xcore', CS_ARCH_XCORE, CS_MODE_BIG_ENDIAN, xcore_dict),
]

if __name__ == '__main__':
    args = sys.argv[1:]
    all = len(args) == 0 or 'all' in args
    for t in tests:
        if all or t.name in args:
            t.run()
        else:
            print('Skipping %s' %t.name)

