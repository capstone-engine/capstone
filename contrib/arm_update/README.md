# How to update AArch64 tables.

- Checkout LLVM. Patches are tested on commit `c13d5969^`, because
  `c13d5969` changed the decode table format.
- Apply patches from the current directory.
- Run tablegen.
  ```
      cd $LLVM
      mkdir build
      cd build
      cmake -DCMAKE_CXX_FLAGS=-DCAPSTONE ..
      make AArch64CommonTableGen -j$(getconf _NPROCESSORS_ONLN)
  ```
- Copy `.inc` files.
  ```
      cp arch/AArch64/AArch64GenInsnNameMaps.inc \
         arch/AArch64/AArch64GenInsnNameMaps.inc.old
      for inc in $(cd arch/AArch64 && ls *.inc); do
        cp $LLVM/build/lib/Target/AArch64/$inc arch/AArch64/
      done
  ```
- Fixup `AArch64GenInsnNameMaps.inc`.
  ```
      comm -1 -3 \
          <(grep ARM64_INS_ <arch/AArch64/AArch64GenInsnNameMaps.inc.old \
            | sort -u) \
          <(grep ARM64_INS_ <arch/AArch64/AArch64GenInsnNameMaps.inc \
            | sort -u) \
          >arch/AArch64/AArch64GenInsnNameMaps.inc.new
      cat arch/AArch64/AArch64GenInsnNameMaps.inc.old \
          arch/AArch64/AArch64GenInsnNameMaps.inc.new \
          >arch/AArch64/AArch64GenInsnNameMaps.inc
  ```
- Add new groups, insns, registers and formats.
  - `include/capstone/arm64.h`
    - `enum ARM64_insn`:
      ```
          comm -1 -3 \
              <(perl -ne 'if (/(ARM64_INS_.+),/) { print "\t$1,\n" }' \
                <include/capstone/arm64.h | sort -u) \
              <(perl -ne 'if (/(ARM64_INS_.+),/) { print "\t$1,\n" }' \
                <arch/AArch64/AArch64MappingInsn.inc | sort -u)
      ```
    - `enum ARM64_insn_group`:
      ```
          perl -ne 'if (/(ARM64_GRP_.*?),/) { print "\t$1,\n"; }' < \
              arch/AArch64/AArch64MappingInsn.inc | sort -u
      ```
  - `arch/AArch64/AArch64Disassembler.c`
  - `arch/AArch64/AArch64InstPrinter.c`
  - `arch/AArch64/AArch64MCTargetDesc.c`
  - `arch/AArch64/AArch64MCTargetDesc.h`
  - `arch/AArch64/AArch64Mapping.c`
    - `enum group_name_maps`:
      ```
          perl -ne 'if (/(ARM64_GRP_(.*?)),/) { print "\t{ $1, \"" . lc($2) . "\" },\n"; }' \
              arch/AArch64/AArch64MappingInsn.inc | sort -u
      ```
