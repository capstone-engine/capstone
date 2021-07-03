#!/usr/bin/python
import functools
import sys
import re

# NOTE : unfortunately not all of the disassembler details are recorded in llvm *.td file
# this script is for dumping those codes into our project

arch = "ARM"  # TODO

f = open(sys.argv[1])
lines = f.readlines()
f.close()

buffer = []
read_depth = 0

thumb_mode = False


def is_arm():
    return arch == "ARM" or arch == "AArch64"


def join(x, y):
    return x + y


def create_reg_decode_def(func):
    output = functools.reduce(join, func)

    # parameters type replacement
    output = output.replace("MCInst &", "MCInst *", 1)
    output = output.replace("InsnType", "unsigned")  # replace all for InsnType is fine
    output = output.replace("const void", "MCRegisterInfo", 1)

    print(output)


def create_reg_const(func):
    output = functools.reduce(join, func)
    output = output.replace("::", "_")
    print(output)


def create_reg_decode(func):
    output = functools.reduce(join, func)

    # parameters type replacement
    output = output.replace("MCInst &", "MCInst *", 1)
    output = output.replace("InsnType", "unsigned")  # replace all for InsnType is fine
    output = output.replace("const void", "MCRegisterInfo", 1)

    # standard c-fy
    output = output.replace("nullptr", "0x0")
    output = output.replace("LLVM_FALLTHROUGH", "0x0")

    # FIXME bunch of patches incoming
    # quick patch to the MIPS function pointers
    output = output.replace(
        "using DecodeFN = DecodeStatus (*)(MCInst &, unsigned, uint64_t, const void *);",
        "DecodeStatus (* RegDecoder)(MCInst *, unsigned, uint64_t, MCRegisterInfo *);",
    )
    output = output.replace("DecodeFN RegDecoder = 0x0;", "RegDecoder = 0x0;")

    # a unfortunate patch to MIPS

    output = output.replace(
        "Inst.getOperand(2).getImm()", "MCOperand_getImm(MCInst_getOperand(Inst, 2))"
    )

    # unfortunate patch to ARM & AArch64

    if is_arm():
        output = output.replace(
            "fieldFromInstruction",
            "fieldFromInstruction_" + ("2" if thumb_mode else "4"),
        )
    output = output.replace("Check(S", "Check(&S")
    output = output.replace("Check(DS", "Check(&DS")
    output = re.sub(
        r"const FeatureBitset &[fF]eatureBits =.+?;",
        "/* Ignored bit flags */",
        output,
        flags=re.S,
    )
    output = re.sub(r"[fF]eatureBits\[.+?]", "true", output)

    # here goes the common procedure (not patch)
    # namespace replacement
    output = output.replace("MCDisassembler::", "MCDisassembler_")
    output = output.replace(arch + "::", arch + "_")

    # method call replacement
    def re_opcode(x):
        return "MCInst_setOpcode(" + x.group(1) + ", " + x.group(2) + ");"

    def re_with(op_name):
        def re_with_inner(x):
            return (
                "MCOperand_Create"
                + op_name
                + "("
                + x.group(1)
                + ", "
                + x.group(2)
                + ");"
            )

        return re_with_inner

    def re_operand(x):
        newline = x.group(0)
        if "createReg" in newline:
            return re.sub(
                r"([A-Za-z]+)\.addOperand\(\s*MCOperand::createReg\((.+?)\)\);",
                re_with("Reg0"),
                newline,
                flags=re.DOTALL,
            )
        else:
            return re.sub(
                r"([A-Za-z]+)\.addOperand\(\s*MCOperand::createImm\((.+?)\)\);",
                re_with("Imm0"),
                newline,
                flags=re.DOTALL,
            )

    output = re.sub(
        r"([A-Za-z]+)\.setOpcode\(\s*(.+?)\);", re_opcode, output, flags=re.DOTALL
    )
    output = re.sub(
        r"([A-Za-z]+)\.addOperand\(\s*(.+?)\);", re_operand, output, flags=re.DOTALL
    )
    output = re.sub(
        r"([A-Za-z]+)\.getOpcode\(\)",
        lambda x: "MCInst_getOpcode(" + x.group(1) + ")",
        output,
    )

    # for template functions constraint by value, we integrate those template param
    # template<int x> void func(); ----> void func(int x);
    # note that this change is on call site, so we've got to change the decls. manually
    while re.findall(r"<.+>\(", output, flags=re.DOTALL):
        location = re.findall(r"<.+?>\(", output)
        for line_str in location:
            pos = output.find(line_str)
            end = pos + len(line_str)  # scan parameters within brackets
            depth = 0
            while depth >= 0:
                end += 1
                if output[end] == ")":
                    depth -= 1
                if output[end] == "(":
                    depth += 1
            params = output[pos + len(line_str) : end]
            template = re.findall(r"<(.+?)>", output)
            output = output[0:pos] + "(" + params + ", " + template[0] + output[end:]

    # `::` are never valid in C, we'd remove it whenever possible
    output = output.replace("::", "_")

    print(output)


# dump the constants
print("static void llvm_unreachable(const char * info) {}")
print("static void assert(int val) {}")

const_table = False


for line in lines:
    if re.match(r"static DecodeStatus", line):
        if "readInstruction" in line or "checkDecodedInstruction" in line:
            continue
        if "Thumb" in line and is_arm():
            thumb_mode = True
        buffer.append(line)
        if ";" in line:  # let go of the function declaration
            create_reg_decode_def(buffer)
            buffer.clear()
            continue
        if "{" in line:
            read_depth = 2
        else:
            read_depth = 1
        continue
    if "static const uint16_t" in line or "static const unsigned" in line:
        if read_depth < 1:
            buffer.append(line)
            const_table = 0
            if "{" in line:
                read_depth = 2
            else:
                read_depth = 1
            continue
    if (
        ";" in line and read_depth <= 1 and len(buffer) > 0
    ):  # lazy detection of function definitions
        buffer.append(line)
        create_reg_decode_def(buffer)
        buffer.clear()
        read_depth = 0
        continue
    if is_arm() and read_depth == 1:
        if "Thumb" in line:
            thumb_mode = True
    if "{" in line and read_depth >= 1:
        buffer.append(line)
        if "}" not in line:
            read_depth += 1
        continue
    if read_depth >= 1:
        buffer.append(line)
        if "}" in line:
            read_depth -= 1
            if read_depth <= 1:
                if const_table:
                    create_reg_const(buffer)
                else:
                    create_reg_decode(buffer)
                read_depth = 0
                thumb_mode = False
                buffer.clear()
