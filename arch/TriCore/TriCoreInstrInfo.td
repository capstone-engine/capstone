//===-- TriCoreInstrInfo.td - Target Description for TriCore ---*- tablegen -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file describes the TriCore instructions in TableGen format.
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
// Instruction format superclass.
//===----------------------------------------------------------------------===//

include "TriCoreInstrFormats.td"

//===----------------------------------------------------------------------===//
// TriCore specific DAG Nodes.
//

// Call
def SDT_TriCoreCmp      : SDTypeProfile<1, 3, [SDTCisSameAs<0, 1>,
                           SDTCisSameAs<1, 2>,
                           SDTCisVT<3, i32>]>;
def SDT_TriCoreImask    : SDTypeProfile<1, 3, [SDTCisVT<0, i64>,
                           SDTCisVT<1, i32>,
                           SDTCisVT<2, i32>,
                           SDTCisVT<3, i32>]>;

def SDT_TriCoreExtract  : SDTypeProfile<1, 3, [SDTCisVT<0, i32>,
                           SDTCisVT<1, i32>,
                           SDTCisVT<2, i32>,
                           SDTCisVT<3, i32>]>;

def SDT_TriCoreLCmp     : SDTypeProfile<1, 4, [SDTCisSameAs<0, 1>,
                           SDTCisSameAs<1, 2>,
                           SDTCisSameAs<2, 3>,
                           SDTCisVT<4, i32>]>;
def SDT_TriCoreBrCC     : SDTypeProfile<0, 3, [SDTCisVT<0, OtherVT>,
                           SDTCisVT<1, i32>,
                           SDTCisVT<2, i32>]>;
def SDT_TriCoreCall : SDTypeProfile<0, -1, [SDTCisPtrTy<0>]>;
def SDT_TriCoreSelectCC : SDTypeProfile<1, 4, [SDTCisSameAs<0, 1>,
                           SDTCisSameAs<1, 2>,
                           SDTCisVT<3, i32>,
                           SDTCisVT<4, i32>]>;
def SDT_TriCoreWrapper  : SDTypeProfile<1, 1, [SDTCisSameAs<0, 1>,
                           SDTCisPtrTy<0>]>;

def SDT_TriCoreShift    : SDTypeProfile<1, 2, [SDTCisVT<0, i32>,
                           SDTCisVT<1, i32>,
                           SDTCisVT<2, i32>]>;

def SDT_TriCoreMovei32         : SDTypeProfile<1, 1, [SDTCisSameAs<0, 1>,
                           SDTCisVT<0, i32>]>;

def SDT_TriCoreMovei64         : SDTypeProfile<1, 1, [SDTCisSameAs<0, 1>,
                           SDTCisVT<0, i64>]>;

def TriCoreAbs     : SDNode<"TriCoreISD::ABS", SDTIntUnaryOp>;
def TriCoreBrCC    : SDNode<"TriCoreISD::BR_CC",
              SDT_TriCoreBrCC, [SDNPHasChain, SDNPInGlue]>;
def TriCoreCall    : SDNode<"TriCoreISD::CALL", SDT_TriCoreCall,
             [ SDNPHasChain, SDNPOptInGlue, SDNPOutGlue, SDNPVariadic ]>;
def TriCoreCmp     : SDNode<"TriCoreISD::CMP",
              SDT_TriCoreCmp, [SDNPOutGlue]>;
def TriCoreLogicCmp: SDNode<"TriCoreISD::LOGICCMP",
              SDT_TriCoreLCmp, [SDNPInGlue, SDNPOutGlue]>;
def TriCoreWrapper : SDNode<"TriCoreISD::Wrapper", SDT_TriCoreWrapper>;
def TriCoreImask   : SDNode<"TriCoreISD::IMASK", SDT_TriCoreImask>;
def TriCoreSh      : SDNode<"TriCoreISD::SH",  SDT_TriCoreShift>;
def TriCoreSha     : SDNode<"TriCoreISD::SHA", SDT_TriCoreShift>;
def TriCoreExtr    : SDNode<"TriCoreISD::EXTR", SDT_TriCoreExtract>;
def TriCoreSelectCC: SDNode<"TriCoreISD::SELECT_CC", SDT_TriCoreSelectCC, []>;

def load_sym : SDNode<"TriCoreISD::LOAD_SYM", SDTIntUnaryOp>;

def movei32 : SDNode<"TriCoreISD::MOVEi32", SDT_TriCoreMovei32>;


def jmptarget : Operand<OtherVT> {
  let PrintMethod = "printPCRelImmOperand";
}

// Operand for printing out a condition code.
def cc : Operand<i32> {
  let PrintMethod = "printCCOperand";
}

def isPointer : Predicate<"isPointer() == true">;
def isnotPointer : Predicate<"isPointer() == false">;

// TriCore Condition Codes
def TriCore_COND_EQ : PatLeaf<(i32 0)>;
def TriCore_COND_NE : PatLeaf<(i32 1)>;
def TriCore_COND_GE : PatLeaf<(i32 2)>;
def TriCore_COND_LT : PatLeaf<(i32 3)>;
// TriCore Logic Codes
def TriCore_LOGIC_AND_EQ : PatLeaf<(i32 0)>;
def TriCore_LOGIC_AND_NE : PatLeaf<(i32 1)>;
def TriCore_LOGIC_AND_GE : PatLeaf<(i32 2)>;
def TriCore_LOGIC_AND_LT : PatLeaf<(i32 3)>;
def TriCore_LOGIC_OR_EQ :  PatLeaf<(i32 0)>;
def TriCore_LOGIC_OR_NE :  PatLeaf<(i32 1)>;
def TriCore_LOGIC_OR_GE :  PatLeaf<(i32 12)>;
def TriCore_LOGIC_OR_LT :  PatLeaf<(i32 13)>;

// These are target-independent nodes, but have target-specific formats.
def SDT_TriCoreCallSeqStart : SDCallSeqStart<[ SDTCisVT<0, i32> ]>;
def SDT_TriCoreCallSeqEnd   : SDCallSeqEnd<[ SDTCisVT<0, i32>,
                                        SDTCisVT<1, i32> ]>;

def TriCoreRetFlag    : SDNode<"TriCoreISD::RET_FLAG", SDTNone,
                           [SDNPHasChain, SDNPOptInGlue, SDNPVariadic]>;
def callseq_start : SDNode<"ISD::CALLSEQ_START", SDT_TriCoreCallSeqStart,
                           [SDNPHasChain, SDNPOutGlue, SDNPSideEffect]>;
def callseq_end   : SDNode<"ISD::CALLSEQ_END",   SDT_TriCoreCallSeqEnd,
                           [SDNPHasChain, SDNPOptInGlue, SDNPOutGlue,
                           SDNPSideEffect]>;

//===----------------------------------------------------------------------===//
// Instruction Pattern Stuff
//===----------------------------------------------------------------------===//

// Lower 32 bits of a 64-bit word
def LO32 : SDNodeXForm<imm, [{
 return CurDAG->getTargetConstant((uint32_t) N->getZExtValue(), SDLoc(N),
   MVT::i32);
}]>;

// Higher 32 bits of a 64-bit word
def HI32 : SDNodeXForm<imm, [{
 return CurDAG->getTargetConstant((uint32_t) (N->getZExtValue()>>32), SDLoc(N),
   MVT::i32);
}]>;

def INVERT_VAL : SDNodeXForm<imm, [{
 outs() << "vall: "<< N->getZExtValue() <<"\n";
 return CurDAG->getTargetConstant(-N->getZExtValue(), SDLoc(N), MVT::i32);
}]>;

def SHIFTAMT : SDNodeXForm<imm, [{
 outs() << "vall: "<< N->getZExtValue() <<"\n";
 return CurDAG->getTargetConstant(N->getZExtValue() - 32, SDLoc(N), MVT::i32);
}]>;

def SHIFTAMT_POS : SDNodeXForm<imm, [{
 outs() << "vall: "<< N->getZExtValue() <<"\n";
 return CurDAG->getTargetConstant((32 - N->getZExtValue()), SDLoc(N), MVT::i32);
}]>;

def SHIFTAMT_NEG : SDNodeXForm<imm, [{
 return CurDAG->getTargetConstant(-(N->getZExtValue() - 32), SDLoc(N),
   MVT::i32);
}]>;

def imm32_64 : PatLeaf<(imm),
[{
  uint64_t val = N->getZExtValue();
  return val >= 32 && val < 64;
}]>;

def imm0_31 : PatLeaf<(imm),
[{
  uint64_t val = N->getZExtValue();
 outs() <<"imm0_31: " << val << "\n";
  return val > 0 && val < 32;
}]>;

//Operands
def s4imm      : Operand<i32> { let PrintMethod = "printSExtImm<4>";  }
def s6imm      : Operand<i32> { let PrintMethod = "printSExtImm<6>";  }
def s9imm      : Operand<i32> { let PrintMethod = "printSExtImm<9>";  }
def s16imm     : Operand<i32> { let PrintMethod = "printSExtImm<16>"; }
def s24imm     : Operand<i32> { let PrintMethod = "printSExtImm<24>"; }
def u8imm      : Operand<i32> { let PrintMethod = "printZExtImm<8>";  }
def u4imm      : Operand<i32> { let PrintMethod = "printZExtImm<4>";  }
def u9imm      : Operand<i32> { let PrintMethod = "printZExtImm<9>";  }
def u16imm     : Operand<i32> { let PrintMethod = "printZExtImm<16>";  }
def bl_target  : Operand<i32>;
def b_target   : Operand<OtherVT>;
def cc_val     : Operand<i32> { let PrintMethod = "printCondCode";  }

def PairAddrRegsOp : RegisterOperand<PairAddrRegs, "printPairAddrRegsOperand">;


def bo : Operand<i32> {
  let MIOperandInfo = (ops AddrRegs, i32imm);
  let PrintMethod = "printAddrBO";
  let EncoderMethod = "getBaseOffsetValue";
}

def preincbo : Operand<i32> {
  let MIOperandInfo = (ops AddrRegs, i32imm);
  let PrintMethod = "printAddrPreIncBO";
  let EncoderMethod = "getBaseOffsetValue";
}

def postincbo : Operand<i32> {
  let MIOperandInfo = (ops AddrRegs, i32imm);
  let PrintMethod = "printAddrPostIncBO";
  let EncoderMethod = "getBaseOffsetValue";
}

def circbo : Operand<i32> {
  let MIOperandInfo = (ops PairAddrRegsOp, i32imm);
  let PrintMethod = "printAddrCircBO";
  let EncoderMethod = "getBaseOffsetValue";
}

// FIXME: Bit-reverse addressing mode has no offset
// Immediate operand is ignored in PrintMethod and EncoderMethod
def bitrevbo : Operand<i32> {
  let MIOperandInfo = (ops PairAddrRegsOp, i32imm);
  let PrintMethod = "printAddrBitRevBO";  
  let EncoderMethod = "getBaseValue";
}

//Nodes
def immSExt4  : PatLeaf<(imm), [{ return isInt<4>(N->getSExtValue()); }]>;
def immSExt6  : PatLeaf<(imm), [{ return isInt<6>(N->getSExtValue()); }]>;
def immSExt9  : PatLeaf<(imm), [{ return isInt<9>(N->getSExtValue()); }]>;
def immSExt16  : PatLeaf<(imm), [{ return isInt<16>(N->getSExtValue()); }]>;
def immSExt24  : PatLeaf<(imm), [{ return isInt<24>(N->getSExtValue()); }]>;

def immZExt4 : ImmLeaf<i32, [{return Imm == (Imm & 0xf);}]>;
def immZExt8 : ImmLeaf<i32, [{return Imm == (Imm & 0xff);}]>;
def immZExt9 : ImmLeaf<i32, [{return Imm == (Imm & 0x1ff);}]>;
def immZExt16 : ImmLeaf<i32, [{return Imm == (Imm & 0xffff);}]>;

// Addressing modes
def addr : ComplexPattern<iPTR, 2, "SelectAddr", [], []>;

//===----------------------------------------------------------------------===//
// Pseudo Instructions
//===----------------------------------------------------------------------===//

let Defs = [A10], Uses = [A10] in {
def ADJCALLSTACKDOWN : Pseudo<(outs), (ins i32imm:$amt),
                                    "# ADJCALLSTACKDOWN $amt",
                                    [(callseq_start timm:$amt)]>;
def ADJCALLSTACKUP   : Pseudo<(outs), (ins i32imm:$amt1, i32imm:$amt2),
                                    "# ADJCALLSTACKUP $amt1",
                                    [(callseq_end timm:$amt1, timm:$amt2)]>;
}

//===----------------------------------------------------------------------===//
// Instructions
//===----------------------------------------------------------------------===//

// Absolute Value Instructions
let Defs = [PSW] in {
   def ABS : RR<0x0B, 0x1C, (outs DataRegs:$d),
                  (ins DataRegs:$s2), "abs $d, $s2",
                  [(set DataRegs:$d, (TriCoreAbs DataRegs:$s2))]>;
   //def ABSb : RR<0x0B, 0x5C, (outs DataRegs:$d),
   //               (ins DataRegs:$s2), "abs.b $d, $s2",
   //               [(set DataRegs:$d, (TriCoreAbs DataRegs:$s2))]>;
}

// Arithmetic Instructions
let Constraints = "$s1 = $d" in
  def ADDsrc : SRC<0xC2, (outs DataRegs:$d), (ins DataRegs:$s1, s4imm:$const4),
  "add $d, $const4",
  [(set DataRegs:$d, (add DataRegs:$s1, immSExt4:$const4) )]>;

let isCommutable = 1 in {

 let AddedComplexity = 6 in
 def ADDrr : RR<0x0B, 0x00, (outs DataRegs:$d),
   (ins DataRegs:$s1, DataRegs:$s2),
   "add $d, $s1, $s2",
   [(set i32:$d, (add i32:$s1, i32:$s2))]>;

 def ADD_Arr : RR<0x01, 0x01, (outs AddrRegs:$d),
   (ins AddrRegs:$s1, AddrRegs:$s2),
   "add.a $d, $s1, $s2",
   [(set AddrRegs:$d, (add AddrRegs:$s1, AddrRegs:$s2))]>;

} // let isCommutable = 1

let Constraints="$d = $fksrc",
  AddedComplexity = 7 in
def ADDsrr: SRR<0x42, (outs DataRegs:$d),
  (ins DataRegs:$fksrc, DataRegs:$s2 ),
  "add $d, $s2",
  [(set DataRegs:$d, (add DataRegs:$s2, DataRegs:$fksrc))]>;

def ADDrc : RC<0x8B, 0x00, (outs DataRegs:$d),
  (ins DataRegs:$s1, i32imm:$const9),
  "add $d, $s1, $const9",
  [(set DataRegs:$d, (add DataRegs:$s1, immSExt9:$const9))]>;

def ADDIrlc : RLC<0x1B, (outs DataRegs:$d),
  (ins DataRegs:$s1, i32imm:$const16), "addi $d, $s1, $const16",
  [(set DataRegs:$d, (add DataRegs:$s1, immSExt16:$const16))]>;

let Defs = [PSW], Uses = [PSW] in {
 let isCommutable = 1 in {
  def ADDCrr : RR<0x0B, 0x05, (outs DataRegs:$d),
    (ins DataRegs:$s1, DataRegs:$s2),
    "addc $d, $s1, $s2",
    [(set DataRegs:$d, (addc DataRegs:$s1, DataRegs:$s2)),
     (implicit PSW)]>;

  def ADDXrr : RR<0x0B, 0x04, (outs DataRegs:$d),
    (ins DataRegs:$s1, DataRegs:$s2),
    "addx $d, $s1, $s2",
    [(set DataRegs:$d, (adde DataRegs:$s1, DataRegs:$s2)),
     (implicit PSW)]>;
 } // let isCommutable = 1

 def ADDCrc : RC<0x8B, 0x05, (outs DataRegs:$d),
   (ins DataRegs:$s1, s9imm:$const9),
   "addc $d, $s1, $const9",
   [(set DataRegs:$d, (addc DataRegs:$s1, immSExt9:$const9)),
    (implicit PSW)]>;

 def ADDXrc : RC<0x0B, 0x04, (outs DataRegs:$d),
   (ins DataRegs:$s1, s9imm:$const9),
   "addx $d, $s1, $const9",
   [(set DataRegs:$d, (adde DataRegs:$s1, immSExt9:$const9)),
    (implicit PSW)]>;

 def SUBCrr : RR<0x0B, 0x0D, (outs DataRegs:$d),
   (ins DataRegs:$s1, DataRegs:$s2),
   "subc $d, $s1, $s2",
   [(set DataRegs:$d, (subc DataRegs:$s1, DataRegs:$s2)),
    (implicit PSW)]>;

 def SUBXrr : RR<0x0B, 0x0C, (outs DataRegs:$d),
   (ins DataRegs:$s1, DataRegs:$s2),
   "subx $d, $s1, $s2",
   [(set DataRegs:$d, (sube DataRegs:$s1, DataRegs:$s2)),
    (implicit PSW)]>;

} // let Defs = [PSW], Uses = [PSW]

def imml_32_h_32 : Operand<i64>, PatLeaf<(imm), [{

 int64_t val = N->getSExtValue();
 int32_t lByte = val & 0xffffffff;
 int32_t hByte = (val >> 32) & 0xffffffff;

 return (lByte >=-256 && lByte < 256 && hByte >=-256 && hByte < 256);

}]>;

let Defs = [PSW] in {
def ADDi64C : Pseudo<(outs ExtRegs:$d),
           (ins ExtRegs:$s1, imml_32_h_32:$const64),
           "ADDi64C Pseudo",
           [(set ExtRegs:$d, (add ExtRegs:$s1, imml_32_h_32:$const64)),
          (implicit PSW)]>;

def ADDi64 : Pseudo<(outs ExtRegs:$d),
           (ins ExtRegs:$s1, ExtRegs:$s2),
           "ADDi64 Pseudo",
           [(set ExtRegs:$d, (add ExtRegs:$s1, ExtRegs:$s2)),
          (implicit PSW)]>;

def SUBi64 : Pseudo<(outs ExtRegs:$d),
           (ins ExtRegs:$s1, ExtRegs:$s2),
           "SUBi64 Pseudo",
           [(set ExtRegs:$d, (sub ExtRegs:$s1, ExtRegs:$s2)),
          (implicit PSW)]>;

} //let Defs = [PSW]

let Defs = [A10], Uses = [A10] in
def SUB_Asc : SC<0x20, (outs), (ins u8imm:$const8), "sub.a %a10, $const8",
  [(set A10, (sub A10, immZExt8:$const8) )]>;

def SUB_Arr : RR<0x01, 0x02, (outs AddrRegs:$d),
  (ins AddrRegs:$s1, AddrRegs:$s2), "sub.a $d, $s1, $s2",
  [(set AddrRegs:$d, (sub AddrRegs:$s1, AddrRegs:$s2) )]>;

def RSUBrc : RC<0x8B, 0x08, (outs DataRegs:$d),
  (ins DataRegs:$s1, s9imm:$const9) ,"rsub $d, $s1, $const9",
  [(set DataRegs:$d, (sub immSExt9:$const9, DataRegs:$s1)) ]>;

let Constraints="$d = $s1" in
  def RSUBsr : SR<0x32, 0x05, (outs DataRegs:$d), (ins DataRegs:$s1),
  "rsub $d", [(set DataRegs:$d, (sub (i32 0), DataRegs:$s1)) ]>;

let Defs=[PSW] in {

 let Constraints="$d = $fksrc" in
 def MULsrr : SRR<0xE2, (outs DataRegs:$d),
    (ins DataRegs:$fksrc, DataRegs:$s2), "mul $d, $s2",
    [(set DataRegs:$d, (mul DataRegs:$fksrc, DataRegs:$s2) )]>;

 def MULrr2 : RR2<0x73, 0x00A, (outs DataRegs:$d),
   (ins DataRegs:$s1, DataRegs:$s2), "mul $d, $s1, $s2",
   [(set DataRegs:$d, (mul DataRegs:$s1, DataRegs:$s2) )]>;

 def MULrc : RC<0x53, 0x001, (outs DataRegs:$d),
   (ins DataRegs:$s1, s9imm:$const9),  "mul $d, $s1, $const9",
   [(set DataRegs:$d, (mul DataRegs:$s1, immSExt9:$const9) )]>;
}

// Logical Instructions
multiclass Logical32_0<bits<8> opcode1, string asmstring,
SDNode OpNode>
{
 def rc: RC<0x8f, opcode1{6-0}, (outs DataRegs:$d),
   (ins DataRegs:$s1, u9imm:$const9),
   !strconcat(asmstring, " $d, $s1, $const9"),
   [(set DataRegs:$d, (OpNode DataRegs:$s1, immZExt9:$const9))]>;

 let isCommutable = 1 in
   def rr: RR<0x0f, opcode1, (outs DataRegs:$d),
   (ins DataRegs:$s1, DataRegs:$s2),
   !strconcat(asmstring, " $d, $s1, $s2"),
   [(set DataRegs:$d, (OpNode DataRegs:$s1, DataRegs:$s2))]>;
}

multiclass Logical32_1<bits<8> opcode1, string asmstring,
SDNode OpNode1, PatFrag OpNode2>
{
 def rc: RC<0x8f, opcode1{6-0}, (outs DataRegs:$d),
   (ins DataRegs:$s1, u9imm:$const9),
   !strconcat(asmstring, " $d, $s1, $const9"),
   [(set DataRegs:$d, (OpNode2 (OpNode1 DataRegs:$s1, immZExt9:$const9)))]>;

 let isCommutable = 1 in
   def rr: RR<0x0f, opcode1, (outs DataRegs:$d),
   (ins DataRegs:$s1, DataRegs:$s2),
   !strconcat(asmstring, " $d, $s1, $s2"),
   [(set DataRegs:$d, (OpNode2 (OpNode1 DataRegs:$s1, DataRegs:$s2)))]>;
}

multiclass Logical16<bits<8> opcode1_sc, bits<8> opcode1_srr,
string asmstring, SDNode OpNode>
{

 let Uses=[D15], Defs=[D15] in
   def sc: SC<opcode1_sc, (outs),
     (ins u8imm:$const8),
     !strconcat(asmstring, " %d15, $const8"),
     [(set D15, (OpNode D15, immZExt8:$const8))]>;

 let Constraints = "$s1 = $d" in
   def srr: SRR<opcode1_srr, (outs DataRegs:$d),
   (ins DataRegs:$s1, DataRegs:$s2),
   !strconcat(asmstring, " $d, $s2"),
   [(set DataRegs:$d, (OpNode DataRegs:$s1, DataRegs:$s2))]>;
}

def imml_32_h_32_const9 : Operand<i64>, PatLeaf<(imm), [{

 int64_t val = N->getSExtValue();
 int32_t lByte = val & 0xffffffff;
 int32_t hByte = (val >> 32) & 0xffffffff;

 return (lByte >=0 && lByte < 512 && hByte >=0 && hByte < 512);

}]>;

def imml_neg_32_h_32_const64 : Operand<i64>, PatLeaf<(imm), [{

 int64_t val = N->getSExtValue();
 int32_t lByte = val & 0xffffffff;
 int32_t hByte = (val >> 32) & 0xffffffff;

 return (lByte >=-512 && lByte < 0 && hByte >=-512 && hByte < 0);

}]>;

multiclass Logical64_Pseudo<SDNode OpNode>
{
 def rc64: Pseudo<(outs ExtRegs:$d),
   (ins ExtRegs:$s1, imml_32_h_32_const9:$const64),
   "##NAME## Pseudo",
   [(set ExtRegs:$d, (OpNode ExtRegs:$s1, imml_32_h_32_const9:$const64))]>;

 let Constraints = "$s1 = $d", isCommutable = 1 in
   def srr64: Pseudo<(outs ExtRegs:$d),
   (ins ExtRegs:$s1, ExtRegs:$s2),
   "##NAME## Pseudo",
   [(set ExtRegs:$d, (OpNode ExtRegs:$s1, ExtRegs:$s2))]>;
}

defm AND : Logical64_Pseudo<and>;
defm OR  : Logical64_Pseudo<or>;
defm XOR : Logical64_Pseudo<xor>;

defm AND : Logical16<0x16, 0x26, "and", and>;
defm AND : Logical32_0<0x08, "and", and>;

defm NAND : Logical32_1<0x09, "nand", and, not>;
defm NOR  : Logical32_1<0x0B, "nor", or, not>;
//defm XNOR : Logical32_1<0x0B, "nxor", xor, not>;

defm OR : Logical32_0<0x0a, "or", or>;
defm OR : Logical16<0x96, 0xA6, "or", or>;

defm XOR : Logical32_0<0x0c, "xor", xor>;

let Constraints = "$s1 = $d", isCommutable = 1 in
  def XORsrr : SRR<0xc6, (outs DataRegs:$d),
  (ins DataRegs:$s1, DataRegs:$s2), "xor $d, $s2",
  [(set DataRegs:$d, (xor DataRegs:$s1, DataRegs:$s2))]>;

def imm_from_0_to_neg512 : Operand<i32>, PatLeaf<(imm), [{
 int64_t val = N->getSExtValue();
 return (val >=-512 && val <= 0);
}]>;

class LOGICALN_RC <bits<7> op2, string asmstring, SDNode OpNode>
 : RC<0x8f, op2, (outs DataRegs:$d),
    (ins DataRegs:$s1, imm_from_0_to_neg512:$const9),
  !strconcat(asmstring," $d, $s1, $const9"),
  [(set i32:$d, (OpNode i32:$s1, imm_from_0_to_neg512:$const9 ))]>;

def ANDNrc : LOGICALN_RC<0x0e, "andn", and>;
def ORNrc  : LOGICALN_RC<0x0f, "orn", or>;
def XNORrc : LOGICALN_RC<0x0d, "xnor", xor>;

let Constraints = "$s1 = $d" in {
def NOTsr : SR<0x46, 0x0, (outs DataRegs: $d), (ins DataRegs:$s1),
      "not $d", [(set DataRegs:$d, (not DataRegs:$s1))]>;

def NOTrr64: Pseudo<(outs ExtRegs:$d), (ins ExtRegs:$s1),
  "##NAME## Pseudo", [(set ExtRegs:$d, (not ExtRegs:$s1))]>;
} // let Constraints = "$s1 = $d" in

def ANDNrc64: Pseudo<(outs ExtRegs:$d),
  (ins ExtRegs:$s1, imml_neg_32_h_32_const64:$const64),
  "##NAME## Pseudo",
  [(set ExtRegs:$d, (and ExtRegs:$s1, imml_neg_32_h_32_const64:$const64))]>;

def ORNrc64: Pseudo<(outs ExtRegs:$d),
  (ins ExtRegs:$s1, imml_neg_32_h_32_const64:$const64),
  "##NAME## Pseudo",
  [(set ExtRegs:$d, (or ExtRegs:$s1, imml_neg_32_h_32_const64:$const64))]>;

def XORrcneg64: Pseudo<(outs ExtRegs:$d),
  (ins ExtRegs:$s1, imml_neg_32_h_32_const64:$const64),
  "##NAME## Pseudo",
  [(set ExtRegs:$d, (xor ExtRegs:$s1, imml_neg_32_h_32_const64:$const64))]>;

// Move Immediate Instructions
class MOV_RR<bits<8> op1, bits<8> op2, string opstr,
RegisterClass outregClass, RegisterClass inregClass>
: RR<op1, op2,
 (outs outregClass:$d),
 (ins inregClass:$s2),
 !strconcat(opstr, " $d, $s2"), [/* No Pattern*/]>;

class MOV_CONST<bits<8> opcode, string opstr, dag ins, list<dag> pattern>
: RLC<opcode, (outs DataRegs:$d), ins,
 !strconcat(opstr, " $d, $const16"), pattern>;

def MOVrr   : MOV_RR<0x0B, 0x1F, "mov", DataRegs, DataRegs>;
def MOV_Drr  : MOV_RR<0x01, 0x4C, "mov.d", DataRegs, AddrRegs>;
def MOV_Arr  : MOV_RR<0x01, 0x63, "mov.a", AddrRegs, DataRegs>;

def MOV_AAsrr : SRR<0x40, (outs AddrRegs:$d),
            (ins AddrRegs:$s2),
            "mov.aa $d, $s2", [] >;

def MOV_AArr : MOV_RR<0x01, 0x00, "mov.aa", AddrRegs, AddrRegs>;


def MOVsrc : SRC<0x82, (outs DataRegs:$d),
        (ins s4imm:$const4),
        "mov $d, $const4",
         [(set DataRegs:$d, immSExt4:$const4)]>;

def MOVrlc  : MOV_CONST<0x3B,"mov", (ins s16imm:$const16),
              [(set DataRegs:$d, immSExt16:$const16)]>;
def MOV_Urlc : MOV_CONST<0xBB,"mov.u", (ins u16imm:$const16),
              [(set DataRegs:$d, immZExt16:$const16)]>;

def MOVHrlc : MOV_CONST<0x7B, "movh", (ins i32imm:$const16), [/* No Pattern*/]>;

//let isReMaterializable = 1, isAsCheapAsAMove = 1 in
def MOVi32 : Pseudo<(outs DataRegs:$d), (ins i32imm:$const32), "##NAME## Pseudo",
                     [(set DataRegs:$d, (movei32 imm:$const32))]>;

def IMASKrcpw :  RCPW<0xB7, 0b01, (outs ExtRegs:$d),
  (ins u4imm:$const4, i32imm:$pos, i32imm:$width),
  "imask $d, $const4, $pos, $width",
  [(set ExtRegs:$d, (TriCoreImask immZExt4:$const4, imm:$pos, imm:$width))]>;

def DEXTRrrpw :  RRPW<0x77, 0b00, (outs DataRegs:$d),
  (ins DataRegs:$s1, DataRegs:$s2, i32imm:$pos),
  "dextr $d, $s1, $s2, $pos",
  [(set DataRegs:$d, (TriCoreExtr DataRegs:$s1, DataRegs:$s2, immZExt4:$pos))]>;

def EXTRrrpw :  RRPW<0x37, 0b10, (outs DataRegs:$d),
  (ins DataRegs:$s1, i32imm:$pos, i32imm:$width),
  "extr $d, $s1, $pos, $width",
  [(set DataRegs:$d, (TriCoreExtr DataRegs:$s1, immZExt4:$pos,
  immZExt4:$width))]>;

// Load/Store Instructions
class LoadABS<bits<8> op1, bits<2> op2, string opstr, PatFrag PF,
         RegisterClass RC = DataRegs, ValueType intType = i32>
        : ABS<op1, op2, (outs RC:$d),
         (ins i32imm:$memri),
         !strconcat(opstr, " $d, $memri"),
         [(set RC:$d, (intType (PF imm:$memri)))]>{ let mayLoad = 1; }

def LD_Babs  : LoadABS<0x05, 0x00, "ld.b"  , sextloadi8>;
def LD_BUabs : LoadABS<0x05, 0x01, "ld.bu" , zextloadi8>;
def LD_Habs  : LoadABS<0x05, 0x02, "ld.h"  , sextloadi16>;
def LD_HUabs : LoadABS<0x05, 0x03, "ld.hu" , zextloadi16>;
def LD_Wabs  : LoadABS<0x85, 0x00, "ld.w"  , load>;
def LD_Dabs  : LoadABS<0x85, 0x01, "ld.d"  , load, ExtRegs,i64>;
def LD_Aabs  : LoadABS<0x85, 0x02, "ld.a"  , load, AddrRegs>;
def LD_DAabs : ABS<0x85, 0x03, (outs PairAddrRegsOp:$d),
         (ins i32imm:$memri), "ld.da $d, $memri",
         [(set PairAddrRegsOp:$d, (i64 (load imm:$memri)))]>{ let mayLoad = 1; }
def LD_Qabs  : LoadABS<0x45, 0x00, "ld.q"  , load>;

class LoadBO<bits<6> op2, string opstr, PatFrag PF,
         RegisterClass RC = DataRegs, ValueType intType = i32>
        : BO<0x09, op2, (outs RC:$d),
         (ins bo:$memri),
         !strconcat(opstr, " $d, $memri"),
         [(set RC:$d, (intType (PF addr:$memri)))]>{ let mayLoad = 1; }

def LD_Bbo  : LoadBO<0x20, "ld.b"  , sextloadi8>;
def LD_BUbo : LoadBO<0x21, "ld.bu" , zextloadi8>;
def LD_Hbo  : LoadBO<0x22, "ld.h"  , sextloadi16>;
def LD_HUbo : LoadBO<0x23, "ld.hu" , zextloadi16>;
def LD_Wbo  : LoadBO<0x24, "ld.w"  , load>;
def LD_Dbo  : LoadBO<0x25, "ld.d"  , load, ExtRegs, i64>;
def LD_Abo  : LoadBO<0x26, "ld.a"  , load, AddrRegs>;
def LD_DAbo : BO<0x09, 0x27, (outs PairAddrRegsOp:$d),
         (ins bo:$memri), "ld.da $d, $memri",
         [(set PairAddrRegsOp:$d, (i64 (load addr:$memri)))]>{ let mayLoad = 1; }
def LD_Qbo  : LoadBO<0x28, "ld.q"  , load>;

class LoadPreIncBO<bits<6> op2, string opstr, PatFrag PF,
         RegisterClass RC = DataRegs, ValueType intType = i32>
        : BO<0x09, op2, (outs RC:$d),
         (ins preincbo:$memri),
         !strconcat(opstr, " $d, $memri"),
         [(set RC:$d, (intType (PF addr:$memri)))]>{ let mayLoad = 1; }

def LD_Bpreincbo  : LoadPreIncBO<0x10, "ld.b"  , sextloadi8>;
def LD_BUpreincbo : LoadPreIncBO<0x11, "ld.bu" , zextloadi8>;
def LD_Hpreincbo  : LoadPreIncBO<0x12, "ld.h"  , sextloadi16>;
def LD_HUpreincbo : LoadPreIncBO<0x13, "ld.hu" , zextloadi16>;
def LD_Wpreincbo  : LoadPreIncBO<0x14, "ld.w"  , load>;
def LD_Dpreincbo  : LoadPreIncBO<0x15, "ld.d"  , load, ExtRegs, i64>;
def LD_Apreincbo  : LoadPreIncBO<0x16, "ld.a"  , load, AddrRegs>;
def LD_DApreincbo : BO<0x09, 0x17, (outs PairAddrRegsOp:$d),
         (ins preincbo:$memri),
         "ld.da $d, $memri",
         [(set PairAddrRegsOp:$d, (i64 (load addr:$memri)))]>{ let mayLoad = 1; }
def LD_Qpreincbo  : LoadPreIncBO<0x18, "ld.q"  , load>;

class LoadPostIncBO<bits<6> op2, string opstr, PatFrag PF,
         RegisterClass RC = DataRegs, ValueType intType = i32>
        : BO<0x09, op2, (outs RC:$d),
         (ins postincbo:$memri),
         !strconcat(opstr, " $d, $memri"),
         [(set RC:$d, (intType (PF addr:$memri)))]>{ let mayLoad = 1; }

def LD_Bpostincbo  : LoadPostIncBO<0x00, "ld.b"  , sextloadi8>;
def LD_BUpostincbo : LoadPostIncBO<0x01, "ld.bu" , zextloadi8>;
def LD_Hpostincbo  : LoadPostIncBO<0x02, "ld.h"  , sextloadi16>;
def LD_HUpostincbo : LoadPostIncBO<0x03, "ld.hu" , zextloadi16>;
def LD_Wpostincbo  : LoadPostIncBO<0x04, "ld.w"  , load>;
def LD_Dpostincbo  : LoadPostIncBO<0x05, "ld.d"  , load, ExtRegs, i64>;
def LD_Apostincbo  : LoadPostIncBO<0x06, "ld.a"  , load, AddrRegs>;
def LD_DApostincbo : BO<0x09, 0x07, (outs PairAddrRegsOp:$d),
         (ins postincbo:$memri),
         "ld.da $d, $memri",
         [(set PairAddrRegsOp:$d, (i64 (load addr:$memri)))]>{ let mayLoad = 1; }
def LD_Qpostincbo  : LoadPostIncBO<0x08, "ld.q"  , load>;

class LoadCircBO<bits<6> op2, string opstr, PatFrag PF,
         RegisterClass RC = DataRegs, ValueType intType = i32>
        : BO<0x29, op2, (outs RC:$d),
         (ins circbo:$memri),
         !strconcat(opstr, " $d, $memri"),
         [(set RC:$d, (intType (PF addr:$memri)))]>{ let mayLoad = 1; }

def LD_Bcircbo  : LoadCircBO<0x10, "ld.b"  , sextloadi8>;
def LD_BUcircbo : LoadCircBO<0x11, "ld.bu" , zextloadi8>;
def LD_Hcircbo  : LoadCircBO<0x12, "ld.h"  , sextloadi16>;
def LD_HUcircbo : LoadCircBO<0x13, "ld.hu" , zextloadi16>;
def LD_Wcircbo  : LoadCircBO<0x14, "ld.w"  , load>;
def LD_Dcircbo  : LoadCircBO<0x15, "ld.d"  , load, ExtRegs, i64>;
def LD_Acircbo  : LoadCircBO<0x16, "ld.a"  , load, AddrRegs>;
def LD_DAcircbo : BO<0x29, 0x17, (outs PairAddrRegsOp:$d),
         (ins circbo:$memri),
         "ld.da $d, $memri",
         [(set PairAddrRegsOp:$d, (i64 (load addr:$memri)))]>{ let mayLoad = 1; }
def LD_Qcircbo  : LoadCircBO<0x18, "ld.q"  , load>;

class LoadBitRevBO<bits<6> op2, string opstr, PatFrag PF,
         RegisterClass RC = DataRegs, ValueType intType = i32>
        : BO<0x29, op2, (outs RC:$d),
         (ins bitrevbo:$memri),
         !strconcat(opstr, " $d, $memri"),
         [(set RC:$d, (intType (PF addr:$memri)))]>{ let mayLoad = 1; }

def LD_Bbitrevbo  : LoadBitRevBO<0x00, "ld.b"  , sextloadi8>;
def LD_BUbitrevbo : LoadBitRevBO<0x01, "ld.bu" , zextloadi8>;
def LD_Hbitrevbo  : LoadBitRevBO<0x02, "ld.h"  , sextloadi16>;
def LD_HUbitrevbo : LoadBitRevBO<0x03, "ld.hu" , zextloadi16>;
def LD_Wbitrevbo  : LoadBitRevBO<0x04, "ld.w"  , load>;
def LD_Dbitrevbo  : LoadBitRevBO<0x05, "ld.d"  , load, ExtRegs, i64>;
def LD_Abitrevbo  : LoadBitRevBO<0x06, "ld.a"  , load, AddrRegs>;
def LD_DAbitrevbo : BO<0x29, 0x07, (outs PairAddrRegsOp:$d),
         (ins bitrevbo:$memri),
         "ld.da $d, $memri",
         [(set PairAddrRegsOp:$d, (i64 (load addr:$memri)))]>{ let mayLoad = 1; }
def LD_Qbitrevbo  : LoadBitRevBO<0x08, "ld.q"  , load>;

def LD_Wbol : BOL<0x19, (outs DataRegs:$d),
   (ins bo:$memri),
   "ld.w $d, $memri",
   [(set DataRegs:$d, (load addr:$memri))]>{ let mayLoad = 1; }
def LD_Abol : BOL<0x99, (outs AddrRegs:$d),
   (ins bo:$memri),
   "ld.a $d, $memri",
   [(set AddrRegs:$d, (load addr:$memri))]>{ let mayLoad = 1; }

def : Pat<(extloadi8 addr:$src), (LD_Bbo addr:$src)>;
def : Pat<(extloadi16 addr:$src), (LD_Hbo addr:$src)>;

let Predicates = [isnotPointer] in {
 def ST_Babs : ABS<0x25, 0x00,(outs), (ins DataRegs:$d, i32imm:$memri),
   "st.b $memri, $d",
   [(truncstorei8 DataRegs:$d, imm:$memri)]>;
 def ST_Habs : ABS<0x25, 0x02,(outs), (ins DataRegs:$d, i32imm:$memri),
   "st.h $memri, $d",
   [(truncstorei16 DataRegs:$d, imm:$memri)]>;
 def ST_Wabs : ABS<0xA5, 0x00, (outs), (ins DataRegs:$d, i32imm:$memri),
   "st.w $memri, $d",
   [(store DataRegs:$d, imm:$memri)]>;
 def ST_Dabs : ABS<0xA5, 0x01, (outs), (ins ExtRegs:$d, i32imm:$memri),
   "st.d $memri, $d",
   [(store ExtRegs:$d, imm:$memri)]>;
 def ST_Qabs : ABS<0x65, 0x00, (outs), (ins DataRegs:$d, i32imm:$memri),
   "st.q $memri, $d",
   [(store DataRegs:$d, imm:$memri)]>;

 def ST_Bbo : BO<0x89, 0x20,(outs), (ins DataRegs:$d, bo:$memri),
   "st.b $memri, $d",
   [(truncstorei8 DataRegs:$d, addr:$memri)]>;
 def ST_Hbo : BO<0x89, 0x22,(outs), (ins DataRegs:$d, bo:$memri),
   "st.h $memri, $d",
   [(truncstorei16 DataRegs:$d, addr:$memri)]>;
 def ST_Wbo : BO<0x89, 0x24, (outs), (ins DataRegs:$d, bo:$memri),
   "st.w $memri, $d",
   [(store DataRegs:$d, addr:$memri)]>;
 def ST_Dbo : BO<0x89, 0x25, (outs), (ins ExtRegs:$d, bo:$memri),
   "st.d $memri, $d",
   [(store ExtRegs:$d, addr:$memri)]>;
 def ST_Qbo : BO<0x89, 0x28, (outs), (ins DataRegs:$d, bo:$memri),
   "st.q $memri, $d",
   [(store DataRegs:$d, addr:$memri)]>;

 def ST_Bpreincbo : BO<0x89, 0x10,(outs), (ins DataRegs:$d, preincbo:$memri),
   "st.b $memri, $d",
   [(truncstorei8 DataRegs:$d, addr:$memri)]>;
 def ST_Hpreincbo : BO<0x89, 0x12,(outs), (ins DataRegs:$d, preincbo:$memri),
   "st.h $memri, $d",
   [(truncstorei16 DataRegs:$d, addr:$memri)]>;
 def ST_Wpreincbo : BO<0x89, 0x14, (outs), (ins DataRegs:$d, preincbo:$memri),
   "st.w $memri, $d",
   [(store DataRegs:$d, addr:$memri)]>;
 def ST_Dpreincbo : BO<0x89, 0x15, (outs), (ins ExtRegs:$d, preincbo:$memri),
   "st.d $memri, $d",
   [(store ExtRegs:$d, addr:$memri)]>;
 def ST_Qpreincbo : BO<0x89, 0x18, (outs), (ins DataRegs:$d, preincbo:$memri),
   "st.q $memri, $d",
   [(store DataRegs:$d, addr:$memri)]>;

 def ST_Bpostincbo : BO<0x89, 0x00,(outs), (ins DataRegs:$d, postincbo:$memri),
   "st.b $memri, $d",
   [(truncstorei8 DataRegs:$d, addr:$memri)]>;
 def ST_Hpostincbo : BO<0x89, 0x02,(outs), (ins DataRegs:$d, postincbo:$memri),
   "st.h $memri, $d",
   [(truncstorei16 DataRegs:$d, addr:$memri)]>;
 def ST_Wpostincbo : BO<0x89, 0x04, (outs), (ins DataRegs:$d, postincbo:$memri),
   "st.w $memri, $d",
   [(store DataRegs:$d, addr:$memri)]>;
 def ST_Dpostincbo : BO<0x89, 0x05, (outs), (ins ExtRegs:$d, postincbo:$memri),
   "st.d $memri, $d",
   [(store ExtRegs:$d, addr:$memri)]>;
 def ST_Qpostincbo : BO<0x89, 0x08, (outs), (ins DataRegs:$d, postincbo:$memri),
   "st.q $memri, $d",
   [(store DataRegs:$d, addr:$memri)]>;

 def ST_Bcircbo : BO<0xA9, 0x10,(outs), (ins DataRegs:$d, circbo:$memri),
   "st.b $memri, $d",
   [(truncstorei8 DataRegs:$d, addr:$memri)]>;
 def ST_Hcircbo : BO<0xA9, 0x12,(outs), (ins DataRegs:$d, circbo:$memri),
   "st.h $memri, $d",
   [(truncstorei16 DataRegs:$d, addr:$memri)]>;
 def ST_Wcircbo : BO<0xA9, 0x14, (outs), (ins DataRegs:$d, circbo:$memri),
   "st.w $memri, $d",
   [(store DataRegs:$d, addr:$memri)]>;
 def ST_Dcircbo : BO<0xA9, 0x15, (outs), (ins ExtRegs:$d, circbo:$memri),
   "st.d $memri, $d",
   [(store ExtRegs:$d, addr:$memri)]>;
 def ST_Qcircbo : BO<0xA9, 0x18, (outs), (ins DataRegs:$d, circbo:$memri),
   "st.q $memri, $d",
   [(store DataRegs:$d, addr:$memri)]>;

 def ST_Bbitrevbo : BO<0xA9, 0x00,(outs), (ins DataRegs:$d, bitrevbo:$memri),
   "st.b $memri, $d",
   [(truncstorei8 DataRegs:$d, addr:$memri)]>;
 def ST_Hbitrevbo : BO<0xA9, 0x02,(outs), (ins DataRegs:$d, bitrevbo:$memri),
   "st.h $memri, $d",
   [(truncstorei16 DataRegs:$d, addr:$memri)]>;
 def ST_Wbitrevbo : BO<0xA9, 0x04, (outs), (ins DataRegs:$d, bitrevbo:$memri),
   "st.w $memri, $d",
   [(store DataRegs:$d, addr:$memri)]>;
 def ST_Dbitrevbo : BO<0xA9, 0x05, (outs), (ins ExtRegs:$d, bitrevbo:$memri),
   "st.d $memri, $d",
   [(store ExtRegs:$d, addr:$memri)]>;
 def ST_Qbitrevbo : BO<0xA9, 0x08, (outs), (ins DataRegs:$d, bitrevbo:$memri),
   "st.q $memri, $d",
   [(store DataRegs:$d, addr:$memri)]>;

 def : Pat<(truncstorei32 ExtRegs:$d, addr:$memri),
    (ST_Wbo (EXTRACT_SUBREG ExtRegs:$d, subreg_even), addr:$memri)>;

 def : Pat<(truncstorei8 ExtRegs:$d, addr:$memri),
     (ST_Wbo (ANDrc (EXTRACT_SUBREG ExtRegs:$d, subreg_even),
     (i32 255)), addr:$memri)>;
} // let Predicates = [isnotPointer]


let Predicates = [isPointer] in {
  def ST_Aabs : ABS<0xA5, 0x02,(outs), (ins AddrRegs:$d, i32imm:$memri),
   "st.a $memri, $d",
   [(truncstorei8 i32:$d, imm:$memri)]>;

  def ST_DAabs : ABS<0xA5, 0x03,(outs), (ins PairAddrRegsOp:$d, i32imm:$memri),
   "st.da $memri, $d",
   [(truncstorei8 i64:$d, imm:$memri)]>;

  def ST_Abo : BO<0x89, 0x26, (outs), (ins AddrRegs:$d, bo:$memri),
  "st.a $memri, $d",
  [(store i32:$d, addr:$memri)]>;

  def ST_DAbo : BO<0x89, 0x27, (outs), (ins PairAddrRegsOp:$d, bo:$memri),
  "st.da $memri, $d",
  [(store i64:$d, addr:$memri)]>;

  def ST_Apreincbo : BO<0x89, 0x16,(outs), (ins AddrRegs:$d, preincbo:$memri),
   "st.a $memri, $d",
   [(store i32:$d, addr:$memri)]>;

  def ST_DApreincbo : BO<0x89, 0x17,(outs), (ins PairAddrRegsOp:$d, preincbo:$memri),
   "st.da $memri, $d",
   [(store i64:$d, addr:$memri)]>;

   def ST_Apostincbo : BO<0x89, 0x06,(outs), (ins AddrRegs:$d, postincbo:$memri),
   "st.a $memri, $d",
   [(store i32:$d, addr:$memri)]>;

   def ST_DApostincbo : BO<0x89, 0x07,(outs), (ins PairAddrRegsOp:$d, postincbo:$memri),
   "st.da $memri, $d",
   [(store i64:$d, addr:$memri)]>;
   
   def ST_Acircbo : BO<0xA9, 0x16,(outs), (ins AddrRegs:$d, circbo:$memri),
   "st.a $memri, $d",
   [(store i32:$d, addr:$memri)]>;

   def ST_DAcircbo : BO<0xA9, 0x17,(outs), (ins PairAddrRegsOp:$d, circbo:$memri),
   "st.da $memri, $d",
   [(store i64:$d, addr:$memri)]>;

   def ST_Abitrevbo : BO<0xA9, 0x06,(outs), (ins AddrRegs:$d, bitrevbo:$memri),
   "st.a $memri, $d",
   [(store i32:$d, addr:$memri)]>;

   def ST_DAbitrevbo : BO<0xA9, 0x07,(outs), (ins PairAddrRegsOp:$d, bitrevbo:$memri),
   "st.da $memri, $d",
   [(store i64:$d, addr:$memri)]>;

} // let Predicates = [isPointer]

// Shift Instructions

// only const9[5:0] is of importance
def SHrc : RC<0x8F,0x00, (outs DataRegs:$d), (ins DataRegs:$s1, s9imm:$const9),
  "sh $d, $s1, $const9",
  [(set DataRegs:$d, (TriCoreSh DataRegs:$s1, immSExt6:$const9))]>;

def SHrr : RR<0x0F, 0x00, (outs DataRegs:$d), (ins DataRegs:$s1, DataRegs:$s2),
  "sh $d, $s1, $s2",
  [(set DataRegs:$d, (TriCoreSh DataRegs:$s1, DataRegs:$s2))]>;

def SHArc : RC<0x8F,0x01, (outs DataRegs:$d), (ins DataRegs:$s1, s9imm:$const9),
  "sha $d, $s1, $const9",
  [(set DataRegs:$d, (TriCoreSha DataRegs:$s1, immSExt6:$const9))]>;

def SHArr : RR<0x0F, 0x01, (outs DataRegs:$d), (ins DataRegs:$s1, DataRegs:$s2),
  "sha $d, $s1, $s2",
  [(set DataRegs:$d, (TriCoreSha DataRegs:$s1, DataRegs:$s2))]>;

// Return Instructions
let isTerminator = 1, isReturn = 1, isBarrier = 1 in
   def RET : T32<(outs), (ins variable_ops), "ret",  [(TriCoreRetFlag)]>;

//let isTerminator = 1, isReturn = 1,
//  isBarrier = 1, Uses =[PCXI, PSW, FCX],
//  Defs= [PSW, PCXI, PC, FCX] in
//  def RETsr : T16<0x00, (outs), (ins variable_ops), "ret",  [(TriCoreRetFlag)]> {
//   let Inst{15-12} = 0x9;
//  }

//let isTerminator = 1, isReturn = 1,
//  isBarrier = 1, Uses = [A11] in
// def RETsr : T16<0x00, (outs), (ins variable_ops), "ret",  [(TriCoreRetFlag)]>
// {
//  let Inst{15-12} = 0x9;
// }

// Call Instructions

// The target of a 24-bit call instruction.
def call_target : Operand<i32>
{
  let EncoderMethod = "encodeCallTarget";
}


let isCall = 1, Defs = [A11], Uses = [A10] in
 def CALLb : B<0x6D, (outs), (ins i32imm:$disp24),
 "call $disp24",  [(TriCoreCall imm:$disp24)]>;

def : Pat<(TriCoreCall (i32 tglobaladdr:$dst)),
     (CALLb tglobaladdr:$dst)>;
def : Pat<(i32 (TriCoreWrapper tglobaladdr:$dst)),
   (MOVi32 tglobaladdr:$dst)>;


// Tentative Call Instructions

//def SDT_LEGCall    : SDTypeProfile<0, -1, [SDTCisPtrTy<0>]>;
//
//def load_sym : SDNode<"TriCoreISD::LOAD_SYM", SDT_TriCoreWrapper>;
//
//def leg_call
//  : SDNode<"TriCoreISD::CALL", SDT_LEGCall,
//       [ SDNPHasChain, SDNPOptInGlue, SDNPOutGlue, SDNPVariadic ]>;
//
//let isCall = 1, Defs = [A11], Uses = [A10] in
// def CALLb : B<0x6D, (outs), (ins call_target:$disp24),
// "call $disp24",  [(leg_call imm:$disp24)]>;
//
//def : Pattern<(i32 (load_sym tglobaladdr:$addr)),  [(MOVi32 $addr)]>;
//
//let isCall = 1, Defs = [A11], Uses = [A10] in
// def CALLb : B<0x6D, (outs), (ins DataRegs:$addr),
// "call $addr",  [(leg_call DataRegs:$addr)]>;

//def : Pattern<(i32 (load_sym tglobaladdr:$addr)),  [(MOVi32 $addr)]>;

//def : Pat<(add DataRegs:$src, (TriCoreWrapper tglobaladdr :$src2)),
//     (ADDrc DataRegs:$src, tglobaladdr:$src2)>;

//def : Pattern<(i32 (load_sym tglobaladdr:$addr)),  [(MOVi32 $addr)]>;


// Compare Instructions
multiclass COMPARE_32<bits<8> op2, string asmstring, PatLeaf PF> {

 def rc : RC<0x8B, op2{6-0},
      (outs DataRegs:$d),
      (ins DataRegs:$s1, s9imm:$const9),
      !strconcat(asmstring, " $d, $s1, $const9"),
      [( set DataRegs:$d, (TriCoreCmp DataRegs:$s1, immSExt9:$const9, PF))]>;

 def rr : RR<0x0B, op2,
       (outs DataRegs:$d),
       (ins DataRegs:$s1, DataRegs:$s2),
       !strconcat(asmstring, " $d, $s1, $s2"),
       [( set DataRegs:$d, (TriCoreCmp DataRegs:$s1, DataRegs:$s2, PF))]>;
}

defm EQ : COMPARE_32<0x10, "eq", TriCore_COND_EQ>;
defm NE : COMPARE_32<0x11, "ne", TriCore_COND_NE>;
defm LT : COMPARE_32<0x12, "lt", TriCore_COND_LT>;
defm GE : COMPARE_32<0x14, "ge", TriCore_COND_GE>;


// 64 bit Compare Instructions
multiclass LOGIC_COMPARE_S<bits<8> op_s, string asmstring, PatLeaf PF>
{
  let Constraints="$d = $fsrc" in {
    def rc : RC<0x8B, op_s{6-0},
    (outs DataRegs:$d),
    (ins DataRegs:$fsrc, DataRegs:$s1, s9imm:$const9),
    !strconcat(asmstring, " $d, $s1, $const9"),
    [( set DataRegs:$d,
      (TriCoreLogicCmp DataRegs:$fsrc, DataRegs:$s1, immSExt9:$const9, PF))]>;

    def rr : RR<0x0B, op_s,
    (outs DataRegs:$d),
    (ins DataRegs:$fsrc, DataRegs:$s1, DataRegs:$s2),
    !strconcat(asmstring, " $d, $s1, $s2"),
    [( set DataRegs:$d,
      (TriCoreLogicCmp DataRegs:$fsrc, DataRegs:$s1, DataRegs:$s2, PF))]>;
  }
}

multiclass LOGIC_COMPARE_U<bits<8> op_u, string asmstring, PatLeaf PF>
{
  let Constraints="$d = $fsrc" in {
    def rc : RC<0x8B, op_u{6-0},
    (outs DataRegs:$d),
    (ins DataRegs:$fsrc, DataRegs:$s1, u9imm:$const9),
    !strconcat(asmstring, " $d, $s1, $const9"),
    [( set DataRegs:$d,
      (TriCoreLogicCmp DataRegs:$fsrc, DataRegs:$s1, immZExt9:$const9, PF))]>;

    def rr : RR<0x0B, op_u,
    (outs DataRegs:$d),
    (ins DataRegs:$fsrc, DataRegs:$s1, DataRegs:$s2),
    !strconcat(asmstring, " $d, $s1, $s2"),
    [( set DataRegs:$d,
      (TriCoreLogicCmp DataRegs:$fsrc, DataRegs:$s1, DataRegs:$s2, PF))]>;
  }
}

defm AND_EQ    : LOGIC_COMPARE_S<0x20, "and.eq",  TriCore_LOGIC_AND_EQ>;
defm AND_NE    : LOGIC_COMPARE_S<0x21, "and.ne",  TriCore_LOGIC_AND_NE>;
defm AND_LT    : LOGIC_COMPARE_S<0x22, "and.lt", TriCore_LOGIC_AND_LT>;
defm AND_LT_U  : LOGIC_COMPARE_U<0x23, "and.lt.u", TriCore_LOGIC_AND_LT>;
defm AND_GE    : LOGIC_COMPARE_S<0x24, "and.ge", TriCore_LOGIC_AND_GE>;
defm AND_GE_U  : LOGIC_COMPARE_U<0x25, "and.ge.u", TriCore_LOGIC_AND_GE>;

defm OR_EQ     : LOGIC_COMPARE_S<0x27, "or.eq",  TriCore_LOGIC_OR_EQ>;
defm OR_NE     : LOGIC_COMPARE_S<0x28, "or.ne",  TriCore_LOGIC_OR_NE>;
defm OR_LT     : LOGIC_COMPARE_S<0x29, "or.lt",  TriCore_LOGIC_OR_LT>;
defm OR_LT_U   : LOGIC_COMPARE_U<0x2A, "or.lt.u",  TriCore_LOGIC_OR_LT>;
defm OR_GE     : LOGIC_COMPARE_S<0x2B, "or.ge",  TriCore_LOGIC_OR_GE>;
defm OR_GE_U   : LOGIC_COMPARE_U<0x2C, "or.ge.u",  TriCore_LOGIC_OR_GE>;

defm XOR_EQ    : LOGIC_COMPARE_S<0x2F, "xor.eq",  TriCore_LOGIC_OR_EQ>;
defm XOR_NE    : LOGIC_COMPARE_S<0x30, "xor.ne",  TriCore_LOGIC_OR_NE>;
defm XOR_LT    : LOGIC_COMPARE_S<0x31, "xor.lt",  TriCore_LOGIC_OR_LT>;
defm XOR_LT_U  : LOGIC_COMPARE_U<0x32, "xor.lt.u",  TriCore_LOGIC_OR_LT>;
defm XOR_GE    : LOGIC_COMPARE_S<0x33, "xor.ge",  TriCore_LOGIC_OR_GE>;
defm XOR_GE_U  : LOGIC_COMPARE_U<0x34, "xor.ge.u",  TriCore_LOGIC_OR_GE>;

// Branch Instructions
let Uses = [PC], Defs = [PC] in
multiclass JUMP_16<bits<8> op1_sb, bits<8> op1_sbr,
         string asmstring, PatLeaf PF>
{
  let Uses = [D15] in
  def sb: SB<op1_sb, (outs),
     (ins jmptarget:$disp8),
     !strconcat(asmstring, " %d15, $disp8"),
     [(TriCoreBrCC bb:$disp8, D15, PF)]>;

  def sbr: SBR<op1_sbr, (outs),
     (ins DataRegs:$s1, jmptarget:$disp4),
     !strconcat(asmstring, " $s1, $disp4"),
     [(TriCoreBrCC bb:$disp4, DataRegs:$s1, PF)]>;
}

let isBranch = 1, isTerminator = 1 in {
// Direct branch
let isBarrier = 1 in {
  def Jb : B<0x1D, (outs), (ins jmptarget:$dst),
                "j $dst",
        [(br bb:$dst)]>;
}

// Conditional branches

 defm JNZ : JUMP_16<0xEE, 0xF6, "jnz", TriCore_COND_NE>;
 defm JZ : JUMP_16<0x6E, 0x76, "jz", TriCore_COND_EQ>;

} // isBranch, isTerminator


//multiclass BRANCH_SIGNED<bits<8> op1_brc, bits<8> op1_brr,
//            bit op2, string asmstring>
//{
//
//  def brc: BRC<op2, op1_brc, (outs),
//     (ins jmptarget:$disp15, DataRegs:$s1, s4imm:$const4),
//     !strconcat(asmstring, " $s1, $const4, $disp15"),
//     [(TriCoreBrCC  bb:$disp15, i32:$s1, immSExt4:$const4)]>;
//
//  def brr: BRR<op2, op1_brr, (outs),
//     (ins jmptarget:$disp15, DataRegs:$s1, DataRegs:$s2),
//     !strconcat(asmstring, " $s1, $s2, $disp15"),
//     [(TriCoreBrCC  bb:$disp15, i32:$s1, i32:$s2)]>;
//}
//
//let isBranch =1, isTerminator = 1 in {
//
// defm JNE : BRANCH_SIGNED<0xdf, 0x5f, 0b1, "jne">;
// defm JEQ : BRANCH_SIGNED<0xdf, 0x5f, 0b0, "jeq">;
// defm JGE : BRANCH_SIGNED<0xff, 0x7f, 0b0, "jge">;
// defm JLT : BRANCH_SIGNED<0xbf, 0x3f, 0b0, "jlt">;
//
//}// isBranch, isTerminator


let usesCustomInserter = 1 in {
  def Select8  : Pseudo<(outs DataRegs:$dst),
             (ins DataRegs:$src, DataRegs:$src2, i32imm:$cc, DataRegs:$src1 ),
             "# Select8 PSEUDO",
            [(set DataRegs:$dst,
            (TriCoreSelectCC DataRegs:$src, DataRegs:$src2, imm:$cc,
            DataRegs:$src1))]>;
}

//===----------------------------------------------------------------------===//
// Non-Instruction Patterns
//===----------------------------------------------------------------------===//

// TODO: Also write a pattern when we have a zero shift
def : Pat<(shl ExtRegs:$src, (i32 imm32_64:$amt)),
          (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
                       (SHrc (EXTRACT_SUBREG ExtRegs:$src, subreg_even),
                         (SHIFTAMT (imm32_64:$amt))), subreg_odd)),
                       (MOVrlc (i32 0)), subreg_even)>;

def : Pat<(shl ExtRegs:$src, (i32 imm0_31:$amt)),
          (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
                       (DEXTRrrpw (EXTRACT_SUBREG ExtRegs:$src, subreg_odd),
                         (EXTRACT_SUBREG ExtRegs:$src, subreg_even),
                 (i32 imm0_31:$amt)), subreg_odd)),
                   (SHrc (EXTRACT_SUBREG ExtRegs:$src, subreg_even),
                 ( i32 imm0_31:$amt)), subreg_even)>;

def : Pat<(srl ExtRegs:$src, (i32 imm0_31:$amt)),
          (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
                       (DEXTRrrpw (EXTRACT_SUBREG ExtRegs:$src, subreg_odd),
                         (EXTRACT_SUBREG ExtRegs:$src, subreg_even),
                 (SHIFTAMT_POS (imm0_31:$amt))), subreg_even)),
                   (SHrc (EXTRACT_SUBREG ExtRegs:$src, subreg_odd),
                 (INVERT_VAL imm0_31:$amt)), subreg_odd)>;

def : Pat<(srl ExtRegs:$src, (i32 imm32_64:$amt)),
          (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
                       (SHrc (EXTRACT_SUBREG ExtRegs:$src, subreg_odd),
                         (SHIFTAMT_NEG (imm32_64:$amt))), subreg_even)),
                       (MOVrlc (i32 0)), subreg_odd)>;

def : Pat<(sra ExtRegs:$src, (i32 imm32_64:$amt)),
          (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
           (SHArc ( EXTRACT_SUBREG (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
             (SHArc (EXTRACT_SUBREG ExtRegs:$src, subreg_odd),
               (SHIFTAMT_NEG (imm32_64:$amt))), subreg_even), subreg_even),
                  (i32 -31)), subreg_odd)>;

def : Pat<(sra ExtRegs:$src, (i32 imm0_31:$amt)),
          (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
                       (DEXTRrrpw (EXTRACT_SUBREG ExtRegs:$src, subreg_odd),
                         (EXTRACT_SUBREG ExtRegs:$src, subreg_even),
                 (SHIFTAMT_POS (imm0_31:$amt))), subreg_even)),
                   (SHArc (EXTRACT_SUBREG ExtRegs:$src, subreg_odd),
                 (INVERT_VAL imm0_31:$amt)), subreg_odd)>;

def : Pat<(shl DataRegs:$src, (i32 0)),
     (MOVrr DataRegs:$src)>;

// This extracts the even register from an extended register
def : Pat<(i32 (trunc ExtRegs:$src)),
     (EXTRACT_SUBREG ExtRegs:$src, subreg_even)>;

// sext
def : Pat<(sext DataRegs:$src),
     (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
        (i32 DataRegs:$src), subreg_even)),
        (SHArc (i32 DataRegs:$src), (i32 -31)), subreg_odd)>;

// sext_inreg for i16
def : Pat<(sext_inreg DataRegs:$src, i16),
          (MOVrr (i32 DataRegs:$src))>;

// sext_inreg for i8
def : Pat<(sext_inreg DataRegs:$src, i8),
          (MOVrr (i32 DataRegs:$src))>;

// sext_inreg from i8 to i64
def : Pat<(sext_inreg ExtRegs:$src, i8),
  (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
    (SHArc ( EXTRACT_SUBREG (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
      ( EXTRrrpw (EXTRACT_SUBREG ExtRegs:$src, subreg_even),
        (i32 0), (i32 8) ), subreg_even), subreg_even),
         (i32 -31)), subreg_odd)>;

// sext_inreg from i16 to i64
def : Pat<(sext_inreg ExtRegs:$src, i16),
  (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
    (SHArc ( EXTRACT_SUBREG (INSERT_SUBREG (i64 (IMPLICIT_DEF)) ,
      ( EXTRrrpw (EXTRACT_SUBREG ExtRegs:$src, subreg_even),
        (i32 0), (i32 16) ), subreg_even), subreg_even)
      , (i32 -31)), subreg_odd)>;

// anyext
def : Pat<(anyext DataRegs:$src),
  (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
    (SHArc ( EXTRACT_SUBREG (INSERT_SUBREG (i64 (IMPLICIT_DEF)) ,
      (i32 DataRegs:$src), subreg_even), subreg_even)
      , (i32 -31)), subreg_odd)>;

// zext
def : Pat<(zext DataRegs:$src),
  (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
    (SHArc ( EXTRACT_SUBREG (INSERT_SUBREG (i64 (IMPLICIT_DEF)) ,
      (i32 DataRegs:$src), subreg_even), subreg_even)
      , (i32 -31)), subreg_odd)>;

// This extracts the odd register from an extended register
// odd_reg = (Extended Register >> 32)
def : Pat<(i32 (trunc (srl ExtRegs:$src, (i32 32)))),
     (EXTRACT_SUBREG ExtRegs:$src, subreg_odd)>;

def : Pat<(i64 imm:$src),
    (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
                 (MOVi32( LO32 imm:$src)), subreg_even)),
                 (MOVi32( HI32 imm:$src)), subreg_odd)>;

def : Pat<(i64 (sextloadi32 addr:$offset)),
  (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
             (SHArc ( EXTRACT_SUBREG (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
               (LD_Wbo addr:$offset), subreg_even), subreg_even),
               (i32 -31)), subreg_odd)>;

def : Pat<(i64 (zextloadi32 addr:$offset)),
  (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
                         (LD_Wbo addr:$offset), subreg_even)),
                         (MOVrlc 0), subreg_odd)>;

def : Pat<(i64 (sextloadi16 addr:$offset)),
  (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
             (SHArc ( EXTRACT_SUBREG (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
               ( EXTRrrpw (LD_Hbo addr:$offset),
                 (i32 0), (i32 16) ), subreg_even), subreg_even)
             , (i32 -31)), subreg_odd)>;

def : Pat<(i64 (zextloadi16 addr:$offset)),
  (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
                         (LD_Wbo addr:$offset), subreg_even)),
                         (MOVrlc 0), subreg_odd)>;


def : Pat<(i64 (sextloadi8 addr:$offset)),
  (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
             (SHArc ( EXTRACT_SUBREG (INSERT_SUBREG (i64 (IMPLICIT_DEF)) ,
               ( EXTRrrpw (LD_Bbo addr:$offset),
                 (i32 0), (i32 8) ), subreg_even), subreg_even)
             , (i32 -31)), subreg_odd)>;

def : Pat<(i64 (zextloadi8 addr:$offset)),
  (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
                         (LD_BUbo addr:$offset), subreg_even)),
                         (MOVrlc 0), subreg_odd)>;

