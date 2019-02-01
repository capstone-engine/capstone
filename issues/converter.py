from subprocess import Popen, PIPE
import sys
import re

options = {
	"CS_ARCH_ARM, CS_MODE_ARM" : "arm",
	"CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_BIG_ENDIAN" : "armb",
	"CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_BIG_ENDIAN" : "armbe",
	"CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN" : "arml",
	"CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN" : "armle",
	"CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_MCLASS" : "cortexm",
	"CS_ARCH_ARM, CS_MODE_THUMB" : "thumb",
	"CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_BIG_ENDIAN" : "thumbbe",
	"CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN" : "thumble",
	"CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN" : "arm64",
	"CS_ARCH_ARM64, CS_MODE_BIG_ENDIAN" : "arm64be",
	"CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN" : "mips",
	"CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN" : "mipsbe",
	"CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN" : "mips64",
	"CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN" : "mips64be",
	"CS_ARCH_X86, CS_MODE_16" : "x16",
	"CS_ARCH_X86, CS_MODE_16, CS_OPT_SYNTAX_ATT" : "x16att",
	"CS_ARCH_X86, CS_MODE_32" : "x32",
	"CS_ARCH_X86, CS_MODE_32, CS_OPT_SYNTAX_ATT" : "x32att",
	"CS_ARCH_X86, CS_MODE_64" : "x64",
	"CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT" : "x64att",
	"CS_ARCH_PPC, CS_MODE_64 | CS_MODE_LITTLE_ENDIAN" : "ppc64",
	"CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN" : "ppc64be",
	"CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN" : "sparc",
	"CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN" : "systemz",
	"CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN" : "sysz",
	"CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN" : "s390x",
	"CS_ARCH_XCORE, CS_MODE_BIG_ENDIAN" : "xcore",
	"CS_ARCH_M68K, CS_MODE_BIG_ENDIAN" : "m68k",
	"CS_ARCH_M68K, CS_MODE_M68K_040" : "m68k40",
	"CS_ARCH_TMS320C64X, CS_MODE_BIG_ENDIAN" : "tms320c64x",
	"CS_ARCH_TMS320C64X, CS_MODE_BIG_ENDIAN" : "tms320c64x",
	"CS_ARCH_M680X, CS_MODE_M680X_6800" : "m6800",
	"CS_ARCH_M680X, CS_MODE_M680X_6801" : "m6801",
	"CS_ARCH_M680X, CS_MODE_M680X_6805" : "m6805",
	"CS_ARCH_M680X, CS_MODE_M680X_6808" : "m6808",
	"CS_ARCH_M680X, CS_MODE_M680X_6809" : "m6809",
	"CS_ARCH_M680X, CS_MODE_M680X_6811" : "m6811",
	"CS_ARCH_M680X, CS_MODE_M680X_CPU12" : "cpu12",
	"CS_ARCH_M680X, CS_MODE_M680X_6301" : "hd6301",
	"CS_ARCH_M680X, CS_MODE_M680X_6309" : "hd6309",
	"CS_ARCH_M680X, CS_MODE_M680X_HCS08" : "hcs08",
	"CS_ARCH_EVM, 0" : "evm",
	"CS_ARCH_MOS65XX, 0" : "mos65xx"
}


file_content = open(sys.argv[1], 'r').read()
new_file_content = ''

matches = re.finditer(r"\!\#(\d+)\n\!\#(.*)\n(.*) = (.*)", file_content, re.MULTILINE)

for match in matches:
	issue_num = match.group(1)
	setting = match.group(2).split(', ')
	opcode = match.group(3)
	detail = match.group(4).split(' | ')

	cmd = ['cstool']
	if setting[-1] == 'CS_OPT_DETAIL':
		cmd.append('-d')

		cmd.append(options[', '.join(x for x in setting[:-1])])
		cmd.append('"' + opcode	+ '"')

		process = Popen(cmd, stdout=PIPE, stderr=PIPE)
		stdout, stderr = process.communicate()
		result = stdout.strip('\n').split('\n')

		tmp = ''
		tmp += '!#' + issue_num + '\n'
		tmp += '!#' + ', '.join(x for x in setting) + '\n'
		tmp += opcode + ' = ' + detail[0] + ' | ' + ' | '.join(x.strip('\t') for x in result[1:])
		new_file_content += tmp + '\n'
	else:
		new_file_content += '!#' + issue_num + '\n' + '!#' + ', '.join(x for x in setting) + '\n' + opcode + ' = ' + detail[0] + '\n' 

open(sys.argv[2], 'w').write(new_file_content)
