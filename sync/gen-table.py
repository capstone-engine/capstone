#!/usr/bin/python

import optparse
import os
import platform
import sys

parse = optparse.OptionParser(usage='"usage:%prog [options] <ARCH>"', version="%prog 1.0")
parse.add_option('-i', '--include', dest='include_dir', action='store', type=str
                 , help='path to LLVM source location, which should generally be path to a dir named `llvm-project` ('
                        'or `llvm-capstone`)')

# It's the best that you configure llvm-tblgen into PATH variable, however we support manual approach
parse.add_option('-b', '--bin', type=str, help='specify location of llvm-tblgen.exe/llvm-tblgen binary')

parse.add_option('-o', '--output', type=str, help='specify output file location, this is NOT mandatory')

parse.add_option('--mapper', dest='mapper', action='store_true'
                 , default=False, help='generate mapper instead of disassembler')

parse.add_option('-d', '--build-dir', type=str, help='custom cmake build dir (for seeking tablegen includes) relative '
                                                     'to include dir')

(options, args) = parse.parse_args()

if options.include_dir is None:
    print("Error: Please specify the LLVM source location with `-i`")
    exit()

if len(args) == 0:
    parse.print_usage()
    print("Error: Please specify the architecture")
    exit()

supported_arch = ["Mips", "ARM", "AArch64", "RISCV", "PowerPC", "Sparc", "SystemZ", "XCore"]


# In case of architecture names' ambiguity
def fix_arch_mapping(name):
    for arch in supported_arch:
        if name.lower() == arch.lower():
            return arch
    if name.lower() == "arm64":
        return "AArch64"
    if name.lower() == "ppc":
        return "PowerPC"
    return name


arch = fix_arch_mapping(args[0])

if arch not in supported_arch:
    parse.print_usage()
    print("Unrecognized architecture: " + arch)
    print("Those supported are:")
    print(supported_arch)

print(options)

is_win = platform.system().lower() == "windows"

bin_to_use = ("llvm-tblgen.exe" if is_win else "llvm-tblgen") if options.bin is None else options.bin

use_mapper = "-mapper" if options.mapper else ""

build_dir = "build" if options.build_dir is None else options.build_dir

command = "{0} --gen-capstone{1} -I{2}/llvm/lib/Target/{3} " \
          "-I{2}/{4}/include " \
          "-I{2}/llvm/include " \
          "-I{2}/llvm/lib/Target " \
          "{2}/llvm/lib/Target/{3}/{5}.td".format(bin_to_use, use_mapper, options.include_dir, arch,
                                                  build_dir, arch if arch != "PowerPC" else "PPC")

result = os.popen(command, "r")
lines = result.readlines()

if not lines:
    print("TableGen execution exited with error, command executed is:")
    print(command)
    exit()

if options.output is None:
    sys.stdout.writelines(lines)
else:
    file_out = file(options.output, "wb")
    file_out.writelines(lines)

# "/home/phosphorus/Documents/Capstone/arch/SystemZ/SystemZGenDisassemblerTables.inc "
