#include "platform.h"

struct platform platforms[] = {
		{
				// item 0
				CS_ARCH_X86,
				CS_MODE_32,
				"X86 32 (Intel syntax)",
				"x32"
		},
		{
				// item 1
				CS_ARCH_X86,
				CS_MODE_64,
				"X86 64 (Intel syntax)",
				"x64"
		},
		{
				// item 2
				CS_ARCH_ARM,
				CS_MODE_ARM,
				"ARM",
				"arm"
		},
		{
				// item 3
				CS_ARCH_ARM,
				CS_MODE_THUMB,
				"THUMB",
				"thumb"
		},
		{
				// item 4
				CS_ARCH_ARM,
				(cs_mode) (CS_MODE_ARM + CS_MODE_V8),
				"Arm-V8",
				"armv8"
		},
		{
				// item 5
				CS_ARCH_ARM,
				(cs_mode) (CS_MODE_THUMB + CS_MODE_V8),
				"THUMB+V8",
				"thumbv8"
		},
		{
				// item 6
				CS_ARCH_ARM,
				(cs_mode) (CS_MODE_THUMB + CS_MODE_MCLASS),
				"Thumb-MClass",
				"cortexm"
		},
		{
				// item 7
				CS_ARCH_AARCH64,
				(cs_mode) 0,
				"AARCH64",
				"aarch64"
		},
		{
				// item 8
				CS_ARCH_MIPS,
				(cs_mode) (CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN),
				"MIPS-32 (Big-endian)",
				"mipsbe"
		},
		{
				// item 9
				CS_ARCH_MIPS,
				(cs_mode) (CS_MODE_MIPS32 + CS_MODE_MICRO),
				"MIPS-32 (micro)",
				"mipsmicro"
		},
		{
				//item 10
				CS_ARCH_MIPS,
				CS_MODE_MIPS64,
				"MIPS-64-EL (Little-endian)",
				"mips64"
		},
		{
				//item 11
				CS_ARCH_MIPS,
				CS_MODE_MIPS32,
				"MIPS-32-EL (Little-endian)",
				"mips"
		},
		{
				//item 12
				CS_ARCH_MIPS,
				(cs_mode) (CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN),
				"MIPS-64 (Big-endian)",
				"mips64be"
		},
		{
				//item 13
				CS_ARCH_MIPS,
				(cs_mode) (CS_MODE_MIPS32 + CS_MODE_MICRO + CS_MODE_BIG_ENDIAN),
				"MIPS-32 | Micro (Big-endian)",
				"mipsbemicro"
		},
		{
				//item 14
				CS_ARCH_PPC,
				CS_MODE_64 | CS_MODE_BIG_ENDIAN,
				"PPC-64",
				"ppc64be"
		},
		{
				//item 15
				CS_ARCH_SPARC,
				CS_MODE_BIG_ENDIAN,
				"Sparc",
				"sparc"
		},
		{
				//item 16
				CS_ARCH_SPARC,
				(cs_mode) (CS_MODE_BIG_ENDIAN + CS_MODE_V9),
				"SparcV9",
				"sparcv9"
		},
		{
				//item 17
				CS_ARCH_SYSTEMZ,
				(cs_mode) CS_MODE_BIG_ENDIAN,
				"SystemZ",
				"systemz"
		},
		{
				//item 18
				CS_ARCH_XCORE,
				(cs_mode) 0,
				"XCore",
				"xcore"
		},
		{
				//item 19
				CS_ARCH_MIPS,
				(cs_mode) (CS_MODE_MIPS32R6 + CS_MODE_BIG_ENDIAN),
				"MIPS-32R6 (Big-endian)",
				"mipsbe32r6"
		},
		{
				//item 20
				CS_ARCH_MIPS,
				(cs_mode) (CS_MODE_MIPS32R6 + CS_MODE_MICRO + CS_MODE_BIG_ENDIAN),
				"MIPS-32R6 (Micro+Big-endian)",
				"mipsbe32r6micro"
		},
		{
				//item 21
				CS_ARCH_MIPS,
				CS_MODE_MIPS32R6,
				"MIPS-32R6 (Little-endian)",
				"mips32r6"
		},
		{
				//item 22
				CS_ARCH_MIPS,
				(cs_mode) (CS_MODE_MIPS32R6 + CS_MODE_MICRO),
				"MIPS-32R6 (Micro+Little-endian)",
				"mips32r6micro"
		},
		{
				//item 23
				CS_ARCH_M68K,
				(cs_mode) 0,
				"M68K",
				"m68k"
		},
		{
				//item 24
				CS_ARCH_M680X,
				(cs_mode) CS_MODE_M680X_6809,
				"M680X_M6809",
				"m6809"
		},
		{
				//item 25
				CS_ARCH_EVM,
				(cs_mode) 0,
				"EVM",
				"evm"
		},
		{
				//item 26
				CS_ARCH_MOS65XX,
				(cs_mode) 0,
				"MOS65XX",
				"mos65xx"
		},
		{
				//item 27
				CS_ARCH_TMS320C64X,
				CS_MODE_BIG_ENDIAN,
				"tms320c64x",
				"tms320c64x"
		},
		{
				//item 28
				CS_ARCH_WASM,
				(cs_mode) 0,
				"WASM",
				"wasm"
		},
		{
				//item 29
				CS_ARCH_BPF,
				CS_MODE_LITTLE_ENDIAN | CS_MODE_BPF_CLASSIC,
				"cBPF",
				"bpf"
		},
		{
				//item 30
				CS_ARCH_BPF,
				CS_MODE_LITTLE_ENDIAN | CS_MODE_BPF_EXTENDED,
				"eBPF",
				"ebpf"
		},
		{
				//item 31
				CS_ARCH_BPF,
				CS_MODE_BIG_ENDIAN | CS_MODE_BPF_CLASSIC,
				"cBPF",
				"bpfbe"
		},
		{
				//item 32
				CS_ARCH_BPF,
				CS_MODE_BIG_ENDIAN | CS_MODE_BPF_EXTENDED,
				"eBPF",
				"ebpfbe"
		},
		{
				// item 33
				CS_ARCH_X86,
				CS_MODE_16,
				"X86 16 (Intel syntax)",
				"x16"
		},
		{
				// item 34
				CS_ARCH_M68K,
				CS_MODE_M68K_040,
				"M68K mode 40",
				"m68k40"
		},
		{
				//item 35
				CS_ARCH_M680X,
				(cs_mode) CS_MODE_M680X_6800,
				"M680X_M6800",
				"m6800"
		},
		{
				//item 36
				CS_ARCH_M680X,
				(cs_mode) CS_MODE_M680X_6801,
				"M680X_M6801",
				"m6801"
		},
		{
				//item 37
				CS_ARCH_M680X,
				(cs_mode) CS_MODE_M680X_6805,
				"M680X_M6805",
				"m6805"
		},
		{
				//item 38
				CS_ARCH_M680X,
				(cs_mode) CS_MODE_M680X_6808,
				"M680X_M6808",
				"m6808"
		},
		{
				//item 39
				CS_ARCH_M680X,
				(cs_mode) CS_MODE_M680X_6811,
				"M680X_M6811",
				"m6811"
		},
		{
				//item 40
				CS_ARCH_M680X,
				(cs_mode) CS_MODE_M680X_CPU12,
				"M680X_cpu12",
				"cpu12"
		},
		{
				//item 41
				CS_ARCH_M680X,
				(cs_mode) CS_MODE_M680X_6301,
				"M680X_M6808",
				"hd6301"
		},
		{
				//item 42
				CS_ARCH_M680X,
				(cs_mode) CS_MODE_M680X_6309,
				"M680X_M6808",
				"hd6309"
		},
		{
				//item 43
				CS_ARCH_M680X,
				(cs_mode) CS_MODE_M680X_HCS08,
				"M680X_M6808",
				"hcs08"
		},
		{
				//item 44
				CS_ARCH_RISCV,
				CS_MODE_RISCV32,
				"RISCV",
				"riscv32"
		},
		{
				//item 45
				CS_ARCH_RISCV,
				CS_MODE_RISCV64,
				"RISCV",
				"riscv64"
		},
		{
				//item 46
				CS_ARCH_PPC,
				CS_MODE_64 | CS_MODE_BIG_ENDIAN | CS_MODE_QPX,
				"ppc+qpx",
				"ppc64beqpx"
		},
		{
				//item 46
				CS_ARCH_PPC,
				CS_MODE_32 | CS_MODE_BIG_ENDIAN | CS_MODE_PS,
				"ppc+ps",
				"ppc32beps"
		},
		{
				CS_ARCH_TRICORE,
				CS_MODE_32 | CS_MODE_BIG_ENDIAN | CS_MODE_TRICORE_110,
				"TRICORE",
				"tc110"
		},
		{
				CS_ARCH_TRICORE,
				CS_MODE_32 | CS_MODE_BIG_ENDIAN | CS_MODE_TRICORE_120,
				"TRICORE",
				"tc120"
		},
		{
				CS_ARCH_TRICORE,
				CS_MODE_32 | CS_MODE_BIG_ENDIAN | CS_MODE_TRICORE_130,
				"TRICORE",
				"tc130"
		},
		{
				CS_ARCH_TRICORE,
				CS_MODE_32 | CS_MODE_BIG_ENDIAN | CS_MODE_TRICORE_131,
				"TRICORE",
				"tc131"
		},
		{
				CS_ARCH_TRICORE,
				CS_MODE_32 | CS_MODE_BIG_ENDIAN | CS_MODE_TRICORE_160,
				"TRICORE",
				"tc160"
		},
		{
				CS_ARCH_TRICORE,
				CS_MODE_32 | CS_MODE_BIG_ENDIAN | CS_MODE_TRICORE_161,
				"TRICORE",
				"tc161"
		},
		{
				CS_ARCH_TRICORE,
				CS_MODE_32 | CS_MODE_BIG_ENDIAN | CS_MODE_TRICORE_162,
				"TRICORE",
				"tc162"
		},
		{
				CS_ARCH_TRICORE,
				CS_MODE_32 | CS_MODE_BIG_ENDIAN | CS_MODE_TRICORE_180,
				"TRICORE",
				"tc180"
		},
		{
				CS_ARCH_XTENSA,
				CS_MODE_XTENSA_ESP32,
				"XTENSA ESP32",
				"esp32"
		},
		{
				CS_ARCH_XTENSA,
				CS_MODE_XTENSA_ESP32S2,
				"XTENSA ESP32S2",
				"esp32s2"
		},
		{
				CS_ARCH_XTENSA,
				CS_MODE_XTENSA_ESP8266,
				"XTENSA ESP8266",
				"esp8266"
		},
	// dummy entry to mark the end of this array.
		// DO NOT DELETE THIS
		{
				0,
				0,
				NULL,
				NULL,
		},
};

// get length of platforms[]
unsigned int platform_len(void) {
	unsigned int c;

	for (c = 0; platforms[c].cstoolname; c++);

	return c;
}

// get platform entry encoded n (first byte for input data of OSS fuzz)
unsigned int get_platform_entry(uint8_t n) {
	unsigned len = platform_len();
	if (len == 0) {
		return 0;
	}
	return n % len;
}

// get cstoolname from encoded n (first byte for input data of OSS fuzz)
const char *get_platform_cstoolname(uint8_t n) {
	return platforms[get_platform_entry(n)].cstoolname;
}

