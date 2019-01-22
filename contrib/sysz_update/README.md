# How to update SystemZ tables.

* Checkout LLVM. Patches are tested on commit `c13d5969^`, because
  `c13d5969` changed the decode table format.
* Apply patches from the current directory.
* Run tablegen.
  ```
      cd $LLVM
      mkdir build
      cd build
      cmake -DCMAKE_CXX_FLAGS=-DCAPSTONE ..
      make SystemZCommonTableGen -j$(getconf _NPROCESSORS_ONLN)
   ```
* Copy `.inc` files.
  ```
      cp arch/SystemZ/SystemZGenInsnNameMaps.inc \
         arch/SystemZ/SystemZGenInsnNameMaps.inc.old
      for inc in $(cd arch/SystemZ && ls *.inc); do
        cp $LLVM/build/lib/Target/SystemZ/$inc arch/SystemZ/
      done
  ```
* Fixup `SystemZGenInsnNameMaps.inc`.
  ```
      comm -1 -3 \
          <(grep SYSZ_INS_ <arch/SystemZ/SystemZGenInsnNameMaps.inc.old \
            | sort -u) \
          <(grep SYSZ_INS_ <arch/SystemZ/SystemZGenInsnNameMaps.inc \
            | sort -u) \
          >arch/SystemZ/SystemZGenInsnNameMaps.inc.new
      cat arch/SystemZ/SystemZGenInsnNameMaps.inc.old \
          arch/SystemZ/SystemZGenInsnNameMaps.inc.new \
          >arch/SystemZ/SystemZGenInsnNameMaps.inc
  ```
* Add new groups, insns, registers and formats.
  * `include/capstone/systemz.h`
    * `enum sysz_insn`:
      ```
          comm -1 -3 \
              <(perl -ne 'if (/(SYSZ_INS_.+),/) { print "\t$1,\n" }' \
                <include/capstone/systemz.h | sort -u) \
              <(perl -ne 'if (/(SYSZ_INS_.+),/) { print "\t$1,\n" }' \
                <arch/SystemZ/SystemZMappingInsn.inc | sort -u)
      ```
    * `enum sysz_insn_group`:
      ```
          perl -ne 'if (/(SYSZ_GRP_.*?),/) { print "\t$1,\n"; }' < \
              arch/SystemZ/SystemZMappingInsn.inc | sort -u
      ```
  * `arch/SystemZ/SystemZDisassembler.c`
  * `arch/SystemZ/SystemZInstPrinter.c`
  * `arch/SystemZ/SystemZMCTargetDesc.c`
  * `arch/SystemZ/SystemZMCTargetDesc.h`
  * `arch/SystemZ/SystemZMapping.c`
    * `enum group_name_maps`:
      ```
          perl -ne 'if (/(SYSZ_GRP_(.*?)),/) { print "\t{ $1, \"" . lc($2) . "\" },\n"; }' \
              arch/SystemZ/SystemZMappingInsn.inc | sort -u
      ```
