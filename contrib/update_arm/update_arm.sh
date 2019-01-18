#!/bin/bash

LLVM=${HOME}/Projects/github/llvm

cp arch/AArch64/AArch64MappingInsn.inc \
        arch/AArch64/AArch64MappingInsn.inc.old
for inc in $(cd arch/AArch64 && ls *.inc); do
    cp $LLVM/build/lib/Target/AArch64/$inc arch/AArch64/
done

comm -1 -3 \
        <(grep ARM64_INS_ <arch/AArch64/AArch64MappingInsn.inc.old \
        | sort -u) \
        <(grep ARM64_INS_ <arch/AArch64/AArch64MappingInsn.inc \
        | sort -u) \
        >arch/AArch64/AArch64MappingInsn.inc.new
cat arch/AArch64/AArch64MappingInsn.inc.old \
        arch/AArch64/AArch64MappingInsn.inc.new \
        >arch/AArch64/AArch64MappingInsn.inc

comm -1 -3 \
        <(perl -ne 'if (/(ARM64_INS_.+),/) { print "\t$1,\n" }' <include/capstone/arm64.h | sort -u) \
        <(perl -ne 'if (/(ARM64_INS_.+),/) { print "\t$1,\n" }' <arch/AArch64/AArch64MappingInsn.inc | sort -u) >include/capstone/arm64_insn

perl -ne 'if (/(ARM64_GRP_.*?),/) { print "\t$1,\n"; }' < \
        arch/AArch64/AArch64MappingInsn.inc | sort -u >include/capstone/arm64_insn_group

perl -ne 'if (/(ARM64_GRP_(.*?)),/) { print "\t{ $1, \"" . lc($2) . "\" },\n"; }' \
        arch/AArch64/AArch64MappingInsn.inc | sort -u > arch/AArch64/AArch64Mapping.group_name_maps