// Capstone definitions fix for X86 LLVM instructions.

let Defs = [EFLAGS] in
  def INT1 : I<0xf1, RawFrm, (outs), (ins), "int1", []>;

// def FNCLEX : I<0xDB, MRM_E2, (outs), (ins), "fnclex", [], IIC_FNCLEX>;
def FSETPM : I<0xDB, MRM_E4, (outs), (ins), "fsetpm", []>;
