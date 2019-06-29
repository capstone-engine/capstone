// Capstone definitions fix for X86 LLVM instructions.

let Defs = [EFLAGS] in
  def INT1 : I<0xf1, RawFrm, (outs), (ins), "int1", []>;

def FSETPM : I<0xDB, MRM_E4, (outs), (ins), "fsetpm", []>;

// Capstone: comment out below lines for X86 Reduce mode

/*
// X87 Floating Point Stack.
include "X86InstrFPStack.td"

// SIMD support (SSE, MMX and AVX)
include "X86InstrFragmentsSIMD.td"

// FMA - Fused Multiply-Add support (requires FMA)
include "X86InstrFMA.td"

// XOP
include "X86InstrXOP.td"

// SSE, MMX and 3DNow! vector support.
include "X86InstrSSE.td"
include "X86InstrAVX512.td"
include "X86InstrMMX.td"
include "X86Instr3DNow.td"

// MPX instructions
include "X86InstrMPX.td"

//include "X86InstrTSX.td"
include "X86InstrSGX.td"

// Various unary fpstack operations default to operating on ST1.
// For example, "fxch" -> "fxch %st(1)"
def : InstAlias<"faddp",        (ADD_FPrST0  ST1), 0>;
def:  InstAlias<"fadd",         (ADD_FPrST0  ST1), 0>;
def : InstAlias<"fsub{|r}p",    (SUBR_FPrST0 ST1), 0>;
def : InstAlias<"fsub{r|}p",    (SUB_FPrST0  ST1), 0>;
def : InstAlias<"fmul",         (MUL_FPrST0  ST1), 0>;
def : InstAlias<"fmulp",        (MUL_FPrST0  ST1), 0>;
def : InstAlias<"fdiv{|r}p",    (DIVR_FPrST0 ST1), 0>;
def : InstAlias<"fdiv{r|}p",    (DIV_FPrST0  ST1), 0>;
def : InstAlias<"fxch",         (XCH_F       ST1), 0>;
def : InstAlias<"fcom",         (COM_FST0r   ST1), 0>;
def : InstAlias<"fcomp",        (COMP_FST0r  ST1), 0>;
def : InstAlias<"fcomi",        (COM_FIr     ST1), 0>;
def : InstAlias<"fcompi",       (COM_FIPr    ST1), 0>;
def : InstAlias<"fucom",        (UCOM_Fr     ST1), 0>;
def : InstAlias<"fucomp",       (UCOM_FPr    ST1), 0>;
def : InstAlias<"fucomi",       (UCOM_FIr    ST1), 0>;
def : InstAlias<"fucompi",      (UCOM_FIPr   ST1), 0>;

// Handle fmul/fadd/fsub/fdiv instructions with explicitly written st(0) op.
// For example, "fadd %st(4), %st(0)" -> "fadd %st(4)".  We also disambiguate
// instructions like "fadd %st(0), %st(0)" as "fadd %st(0)" for consistency with
// gas.
multiclass FpUnaryAlias<string Mnemonic, Instruction Inst, bit EmitAlias = 1> {
 def : InstAlias<!strconcat(Mnemonic, "\t{$op, %st(0)|st(0), $op}"),
                 (Inst RST:$op), EmitAlias>;
 def : InstAlias<!strconcat(Mnemonic, "\t{%st(0), %st(0)|st(0), st(0)}"),
                 (Inst ST0), EmitAlias>;
}

defm : FpUnaryAlias<"fadd",   ADD_FST0r>;
defm : FpUnaryAlias<"faddp",  ADD_FPrST0, 0>;
defm : FpUnaryAlias<"fsub",   SUB_FST0r>;
defm : FpUnaryAlias<"fsub{|r}p",  SUBR_FPrST0>;
defm : FpUnaryAlias<"fsubr",  SUBR_FST0r>;
defm : FpUnaryAlias<"fsub{r|}p", SUB_FPrST0>;
defm : FpUnaryAlias<"fmul",   MUL_FST0r>;
defm : FpUnaryAlias<"fmulp",  MUL_FPrST0>;
defm : FpUnaryAlias<"fdiv",   DIV_FST0r>;
defm : FpUnaryAlias<"fdiv{|r}p",  DIVR_FPrST0>;
defm : FpUnaryAlias<"fdivr",  DIVR_FST0r>;
defm : FpUnaryAlias<"fdiv{r|}p", DIV_FPrST0>;
defm : FpUnaryAlias<"fcomi",   COM_FIr, 0>;
defm : FpUnaryAlias<"fucomi",  UCOM_FIr, 0>;
defm : FpUnaryAlias<"fcompi",   COM_FIPr>;
defm : FpUnaryAlias<"fucompi",  UCOM_FIPr>;


// Handle "f{mulp,addp} st(0), $op" the same as "f{mulp,addp} $op", since they
// commute.  We also allow fdiv[r]p/fsubrp even though they don't commute,
// solely because gas supports it.
def : InstAlias<"faddp\t{%st(0), $op|$op, st(0)}", (ADD_FPrST0 RST:$op), 0>;
def : InstAlias<"fmulp\t{%st(0), $op|$op, st(0)}", (MUL_FPrST0 RST:$op)>;
def : InstAlias<"fsub{|r}p\t{%st(0), $op|$op, st(0)}", (SUBR_FPrST0 RST:$op)>;
def : InstAlias<"fsub{r|}p\t{%st(0), $op|$op, st(0)}", (SUB_FPrST0 RST:$op)>;
def : InstAlias<"fdiv{|r}p\t{%st(0), $op|$op, st(0)}", (DIVR_FPrST0 RST:$op)>;
def : InstAlias<"fdiv{r|}p\t{%st(0), $op|$op, st(0)}", (DIV_FPrST0 RST:$op)>;

def : InstAlias<"fnstsw"     , (FNSTSW16r), 0>;

// Match 'movd GR64, MMX' as an alias for movq to be compatible with gas,
// which supports this due to an old AMD documentation bug when 64-bit mode was
// created.
def : InstAlias<"movd\t{$src, $dst|$dst, $src}",
                (MMX_MOVD64to64rr VR64:$dst, GR64:$src), 0>;
def : InstAlias<"movd\t{$src, $dst|$dst, $src}",
                (MMX_MOVD64from64rr GR64:$dst, VR64:$src), 0>;
*/
