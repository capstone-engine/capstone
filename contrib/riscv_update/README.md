# How to update RISCV tables.

* Checkout LLVM. Patches are tested on commit `b81d715c`.
  ```
      git clone https://github.com/llvm/llvm-project.git
      git checkout b81d715c
  ```
* Apply patches from the current directory.
* Run tablegen.
  ```
      cd $LLVM
      mkdir build
      cd build
      cmake -DCMAKE_CXX_FLAGS=-DCAPSTONE -DLLVM_EXPERIMENTAL_TARGETS_TO_BUILD="RISCV" ..
      make RISCVCommonTableGen 
   ```
* Copy `.inc` files.
  ```
      cp arch/RISCV/RISCVGenInsnNameMaps.inc \
         arch/RISCV/RISCVGenInsnNameMaps.inc.old
      for inc in $(cd arch/RISCV && ls *.inc); do
        cp $LLVM/build/lib/Target/RISCV/$inc arch/RISCV/
      done
  ```
* Fixup `RISCVGenInsnNameMaps.inc`.
  ```
      comm -1 -3 \
          <(grep RISCV_INS_ <arch/RISCV/RISCVGenInsnNameMaps.inc.old \
            | sort -u) \
          <(grep RISCV_INS_ <arch/RISCV/RISCVGenInsnNameMaps.inc \
            | sort -u) \
          >arch/RISCV/RISCVGenInsnNameMaps.inc.new
      cat arch/RISCV/RISCVGenInsnNameMaps.inc.old \
          arch/RISCV/RISCVGenInsnNameMaps.inc.new \
          >arch/RISCV/RISCVGenInsnNameMaps.inc
  ```
* Add new groups, insns, registers and formats.
  * `include/capstone/RISCV.h`
    * `enum RISCV_insn`:
      ```
          comm -1 -3 \
              <(perl -ne 'if (/(RISCV_INS_.+),/) { print "\t$1,\n" }' \
                <include/capstone/RISCV.h | sort -u) \
              <(perl -ne 'if (/(RISCV_INS_.+),/) { print "\t$1,\n" }' \
                <arch/RISCV/RISCVMappingInsn.inc | sort -u)
      ```
    * `enum RISCV_insn_group`:
      ```
       perl -ne 'if (/(\{.RISCV_GRP_.*?\}),/) { print "\t$1,\n"; }' < \
            arch/RISCV/RISCVMappingInsn.inc | sort -u          
      ```
  * `arch/RISCV/RISCVDisassembler.c`
  * `arch/RISCV/RISCVInstPrinter.c`
  * `arch/RISCV/RISCVMCTargetDesc.c`
  * `arch/RISCV/RISCVMCTargetDesc.h`
  * `arch/RISCV/RISCVMapping.c`
    * `enum group_name_maps`:
      ```
          perl -ne 'if (/(RISCV_GRP_(.*?)),/) { print "\t{ $1, \"" . lc($2) . "\" },\n"; }' \
              arch/RISCV/RISCVMappingInsn.inc | sort -u
      ```
