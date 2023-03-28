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
def SDT_TriCoreCall     : SDTypeProfile<0, -1, [SDTCisPtrTy<0>]>;
def SDT_TriCoreSelectCC : SDTypeProfile<1, 4, [SDTCisSameAs<0, 1>,
                           SDTCisSameAs<1, 2>,
                           SDTCisVT<3, i32>,
                           SDTCisVT<4, i32>]>;
def SDT_TriCoreWrapper  : SDTypeProfile<1, 1, [SDTCisSameAs<0, 1>,
                           SDTCisPtrTy<0>]>;

def SDT_TriCoreShift    : SDTypeProfile<1, 2, [SDTCisVT<0, i32>,
                           SDTCisVT<1, i32>,
                           SDTCisVT<2, i32>]>;

def SDT_TriCoreMovei32  : SDTypeProfile<1, 1, [SDTCisSameAs<0, 1>,
                           SDTCisVT<0, i32>]>;

def SDT_TriCoreMovei64  : SDTypeProfile<1, 1, [SDTCisSameAs<0, 1>,
                           SDTCisVT<0, i64>]>;

def TriCoreAbs     : SDNode<"TriCoreISD::ABS", SDTIntUnaryOp>;
def TriCoreAbsDif  : SDNode<"TriCoreISD::ABSDIF", SDTIntBinOp>;
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
def TriCore_LOGIC_OR_EQ  : PatLeaf<(i32 0)>;
def TriCore_LOGIC_OR_NE  : PatLeaf<(i32 1)>;
def TriCore_LOGIC_OR_GE  : PatLeaf<(i32 12)>;
def TriCore_LOGIC_OR_LT  : PatLeaf<(i32 13)>;

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
def s8imm      : Operand<i32> { let PrintMethod = "printSExtImm<8>";  }
def s9imm      : Operand<i32> { let PrintMethod = "printSExtImm<9>";  }
def s10imm     : Operand<i32> { let PrintMethod = "printSExtImm<10>";  }
def s16imm     : Operand<i32> { let PrintMethod = "printSExtImm<16>"; }
def s24imm     : Operand<i32> { let PrintMethod = "printSExtImm<24>"; }
def u8imm      : Operand<i32> { let PrintMethod = "printZExtImm<8>";  }
def u4imm      : Operand<i32> { let PrintMethod = "printZExtImm<4>";  }
def u2imm      : Operand<i32> { let PrintMethod = "printZExtImm<2>";  }
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
def immSExt10  : PatLeaf<(imm), [{ return isInt<10>(N->getSExtValue()); }]>;
def immSExt16  : PatLeaf<(imm), [{ return isInt<16>(N->getSExtValue()); }]>;
def immSExt24  : PatLeaf<(imm), [{ return isInt<24>(N->getSExtValue()); }]>;

def immZExt2 : ImmLeaf<i32, [{return Imm == (Imm & 0x3);}]>;
def immZExt4 : ImmLeaf<i32, [{return Imm == (Imm & 0xf);}]>;
def immZExt8 : ImmLeaf<i32, [{return Imm == (Imm & 0xff);}]>;
def immZExt9 : ImmLeaf<i32, [{return Imm == (Imm & 0x1ff);}]>;
def immZExt16 : ImmLeaf<i32, [{return Imm == (Imm & 0xffff);}]>;

// Addressing modes
def addr : ComplexPattern<iPTR, 2, "SelectAddr", [], []>;

/// 16-Bit Opcode Formats

class ISC_D15<bits<8> op1, string asmstr> 
    : SC<op1, (outs), (ins u8imm:$const8),
      asmstr # " %d15, $const8", []>;

class ISC_A10<bits<8> op1, string asmstr> 
    : SC<op1, (outs), (ins u8imm:$const8),
      asmstr # " %sp, $const8", []>;

class ISC_A15A10C<bits<8> op1, string asmstr> 
    : SC<op1, (outs), (ins u8imm:$const8),
      asmstr # " %a15, %sp, $const8", []>;

class ISC_A10CA15<bits<8> op1, string asmstr> 
    : SC<op1, (outs), (ins u8imm:$const8),
      asmstr # " %sp, $const8, %a15", []>;

class ISC_0<bits<8> op1, string asmstr> 
    : SC<op1, (outs), (ins u8imm:$const8),
      asmstr # " $const8", []>;

multiclass mISC_D15<bits<8> op1, string asmstr> {
  def _src : ISC_D15<op1, asmstr>;
}

class ISRC<bits<8> op1, string asmstr> 
    : SRC<op1, (outs DataRegs:$d), (ins s4imm:$const4),
      asmstr # " $d, $const4",
      []>;

class ISRC_Aa<bits<8> op1, string asmstr> 
    : SRC<op1, (outs AddrRegs:$d), (ins s4imm:$const4),
      asmstr # " $d, $const4",
      []>;

class ISRC_AaZ<bits<8> op1, string asmstr> 
    : SRC<op1, (outs AddrRegs:$d), (ins u4imm:$const4),
      asmstr # " $d, $const4",
      []>;

class ISRC_a15<bits<8> op1, string asmstr> 
    : SRC<op1, (outs DataRegs:$d), (ins s4imm:$const4),
      asmstr # " $d, %d15, $const4",
      []>;

class ISRC_15a<bits<8> op1, string asmstr> 
    : SRC<op1, (outs DataRegs:$d), (ins s4imm:$const4),
      asmstr # " %d15, $d, $const4",
      []>;

multiclass mISRC_s<bits<8> op1, string asmstr> {
  def _src : ISRC<op1, asmstr>;
}

multiclass mISRC_a15a<bits<8> op1, bits<8> op2, bits<8> op3,
                        string asmstr> {
  def _src : ISRC<op1, asmstr>;
  def _src_a15 : ISRC_a15<op2, asmstr>;
  def _src_15a : ISRC_15a<op3, asmstr>;
}

class ISRRS<bits<6> op1, string asmstr>
    : SRRS<op1, (outs AddrRegs:$d), (ins AddrRegs:$s2, u2imm:$n),
      asmstr # " $d, $s2, %d15, $n", []>;

/// 32-Bit Opcode Formats

/// RC

class IRC<bits<8> op1, bits<7> op2, string asmstr>
    : RC<op1, op2, (outs), (ins s9imm:$const9),
      asmstr # " $const9", []>;

class IRC_R<bits<8> op1, bits<7> op2, string asmstr, RegisterClass rcd>
    : RC<op1, op2, (outs rcd:$d), (ins DataRegs:$s1, s9imm:$const9),
         asmstr # " $d, $s1, $const9", []>;

class IRC_2<bits<8> op1, bits<7> op2, string asmstr>
    : RC<op1, op2, (outs DataRegs:$d), (ins DataRegs:$s1, s9imm:$const9),
      asmstr # " $d, $s1, $const9", []>;

/// RR

class IRR_Ra<bits<8> op1, bits<8> op2, string asmstr, RegisterClass rc>
    : RR<op1, op2, (outs rc:$d), (ins rc:$s1), asmstr # " $s1", []>;

/// op A[a]
class IRR_Aa<bits<8> op1, bits<8> op2, string asmstr>
    : IRR_Ra<op1, op2, asmstr, AddrRegs>;

/// op R[c], R[a]
class IRR_a<bits<8> op1, bits<8> op2, string asmstr, RegisterClass cd, RegisterClass c1>
    : RR<op1, op2, (outs cd:$d), (ins c1:$s1),
      asmstr # " $d, $s1", []>;

/// op R[c], R[b]
class IRR_b<bits<8> op1, bits<8> op2, string asmstr, RegisterClass cd, RegisterClass c2>
    : RR<op1, op2, (outs cd:$d), (ins c2:$s1, c2:$s2),
      asmstr # " $d, $s2", []>;

/// op D[c], D[a]
class IRR_DcDa<bits<8> op1, bits<8> op2, string asmstr>
    : IRR_a<op1, op2, asmstr, DataRegs, DataRegs>;

/// op D[c], D[b]
class IRR_DcDb<bits<8> op1, bits<8> op2, string asmstr>
    : IRR_b<op1, op2, asmstr, DataRegs, DataRegs>;

/// op E[c], D[a]
class IRR_EcDa<bits<8> op1, bits<8> op2, string asmstr>
    : IRR_a<op1, op2, asmstr, ExtRegs, DataRegs>;

/// op D[c], A[a]
class IRR_DcAa<bits<8> op1, bits<8> op2, string asmstr>
    : IRR_a<op1, op2, asmstr, DataRegs, AddrRegs>;

/// R[c], R[a], R[b]
class IRR_2<bits<8> op1, bits<8> op2, string asmstr, RegisterClass cd, RegisterClass c1, RegisterClass c2>
    : RR<op1, op2, (outs cd:$d), (ins c1:$s1, c2:$s2), asmstr, []>;

/// op D[c], D[a], D[b]
class IRR_DcDaDb<bits<8> op1, bits<8> op2, string asmstr>
    : IRR_2<op1, op2, asmstr # " $d, $s1, $s2", DataRegs, DataRegs, DataRegs>;
/// op D[c], D[b], D[a]
class IRR_DcDbDa<bits<8> op1, bits<8> op2, string asmstr>
    : IRR_2<op1, op2, asmstr # " $d, $s2, $s1", DataRegs, DataRegs, DataRegs>;

/// op E[c], D[a], D[b]
class IRR_EcDaDb<bits<8> op1, bits<8> op2, string asmstr>
    : IRR_2<op1, op2, asmstr # " $d, $s1, $s2", ExtRegs, DataRegs, DataRegs>;

/// op D[c], A[a], A[b]
class IRR_DcAaAb<bits<8> op1, bits<8> op2, string asmstr>
    : IRR_2<op1, op2, asmstr # " $d, $s1, $s2", DataRegs, AddrRegs, AddrRegs>;

/// op A[c], A[b], D[a], n (RR)
class IRR_AcAbDaN<bits<8> op1, bits<8> op2, string asmstr>
    : RR<op1, op2, (outs AddrRegs:$d), (ins DataRegs:$s1, AddrRegs:$s2, i32imm:$n),
         asmstr # " $d, $s2, $s1, $n", []>;

multiclass mIRR_RC<bits<8> rr1, bits<8> rr2, bits<8> rc1, bits<7> rc2,
                        string asmstr> {
  def _rr : IRR_DcDaDb<rr1, rr2, asmstr>;
  def _rc : IRC_2<rc1, rc2, asmstr>;
}

class IRLC<bits<8> op1, string asmstr>
    : RLC<op1, (outs DataRegs:$d), (ins DataRegs:$s1, s16imm:$const16),
      asmstr # " $d, $s1, $const16",
      []>;


class ISRR_2<bits<8> op1, string asmstr, RegisterClass rc1, RegisterClass rc2>
    : SRR<op1, (outs rc1:$d), (ins rc2:$s2),
      asmstr # " $d, $s2", []>;

class ISRR<bits<8> op1, string asmstr>
    : ISRR_2<op1, asmstr, DataRegs, DataRegs>;

class ISRR_AaAb<bits<8> op1, string asmstr>
    : ISRR_2<op1, asmstr, AddrRegs, AddrRegs>;

class ISRR_AaDb<bits<8> op1, string asmstr>
    : ISRR_2<op1, asmstr, AddrRegs, DataRegs>;

class ISRR_a15<bits<8> op1, string asmstr>
    : SRR<op1, (outs DataRegs:$d), (ins DataRegs:$s2),
      asmstr # " $d, %d15, $s2",
      []>;

class ISRR_15a<bits<8> op1, string asmstr>
    : SRR<op1, (outs DataRegs:$d), (ins DataRegs:$s2),
      asmstr # " %d15, $d, $s2",
      []>;


multiclass mISRR_s<bits<8> op1, string asmstr>{
    def _srr : ISRR<op1, asmstr>;
}

multiclass mISRR_a15a<bits<8> op1, bits<8> op2, bits<8> op3,
                    string asmstr>{
  def _srr     : ISRR<op1, asmstr>;
  def _srr_a15 : ISRR_a15<op2, asmstr>;
  def _srr_15a : ISRR_15a<op3, asmstr>;
}

class IBIT<bits<8> op1, bits<2> op2, string asmstr>
    : BIT<op1, op2, (outs DataRegs:$d), (ins DataRegs:$s1, DataRegs:$s2, u4imm:$pos1, u4imm:$pos_r),
      asmstr # " $d, $s1, $pos1, $s2, $pos_r",
      []>;

//===----------------------------------------------------------------------===//
// Pseudo Instructions
//===----------------------------------------------------------------------===//

//let Defs = [A10], Uses = [A10] in {
//def ADJCALLSTACKDOWN : Pseudo<(outs), (ins i32imm:$amt),
//                                    "# ADJCALLSTACKDOWN $amt",
//                                    [(callseq_start timm:$amt)]>;
//def ADJCALLSTACKUP   : Pseudo<(outs), (ins i32imm:$amt1, i32imm:$amt2),
//                                    "# ADJCALLSTACKUP $amt1",
//                                    [(callseq_end timm:$amt1, timm:$amt2)]>;
//}

//===----------------------------------------------------------------------===//
// Instructions
//===----------------------------------------------------------------------===//

// Arithmetic Instructions

// Absolute Value Instructions
let Defs = [PSW] in {
   def ABS_rr : RR<0x0B, 0x1C, (outs DataRegs:$d),
                              (ins DataRegs:$s2),
                  "abs $d, $s2",
                  [(set DataRegs:$d, (TriCoreAbs DataRegs:$s2))]>;
   def ABS_B_rr : RR<0x0B, 0x5C, (outs DataRegs:$d),
                                (ins DataRegs:$s2),
                                 "abs.b $d, $s2",
                  [(set DataRegs:$d, (TriCoreAbs DataRegs:$s2))]>;
   def ABS_H_rr : RR<0x0B, 0x7C, (outs DataRegs:$d),
                                (ins DataRegs:$s2),
                                 "abs.h $d, $s2",
                  [(set DataRegs:$d, (TriCoreAbs DataRegs:$s2))]>;

   def ABSDIF_rc : RC<0x8B, 0x0E, (outs DataRegs:$d),
                  (ins DataRegs:$s1, s9imm:$const9), "absdif $d, $s1, $const9",
                  [(set DataRegs:$d, (TriCoreAbsDif DataRegs:$s1, immSExt9:$const9))]>;
   def ABSDIF_rr : RR<0x0B, 0x0E, (outs DataRegs:$d),
                  (ins DataRegs:$s1, DataRegs:$s2), "absdif $d, $s1, $s2",
                  [(set DataRegs:$d, (TriCoreAbsDif DataRegs:$s1, DataRegs:$s2))]>;
   def ABSDIF_B_rr : RR<0x0B, 0x4E, (outs DataRegs:$d),
                  (ins DataRegs:$s1, DataRegs:$s2), "absdif.b $d, $s1, $s2",
                  [(set DataRegs:$d, (TriCoreAbsDif DataRegs:$s1, DataRegs:$s2))]>;
   def ABSDIF_H_rr : RR<0x0B, 0x6E, (outs DataRegs:$d),
                  (ins DataRegs:$s1, DataRegs:$s2), "absdif.h $d, $s1, $s2",
                  [(set DataRegs:$d, (TriCoreAbsDif DataRegs:$s1, DataRegs:$s2))]>;

   def ABSDIFS_rc : RC<0x8B, 0x0F, (outs DataRegs:$d),
                  (ins DataRegs:$s1, DataRegs:$s2), "absdifs $d, $s1, $s2",
                  [(set DataRegs:$d, (TriCoreAbsDif DataRegs:$s1, DataRegs:$s2))]>;
   def ABSDIFS_rr : RR<0x0B, 0x0F, (outs DataRegs:$d),
                  (ins DataRegs:$s1, DataRegs:$s2), "absdifs $d, $s1, $s2",
                  [(set DataRegs:$d, (TriCoreAbsDif DataRegs:$s1, DataRegs:$s2))]>;
   def ABSDIFS_H_rr : RR<0x0B, 0x6F, (outs DataRegs:$d),
                  (ins DataRegs:$s1, DataRegs:$s2), "absdifs.h $d, $s1, $s2",
                  [(set DataRegs:$d, (TriCoreAbsDif DataRegs:$s1, DataRegs:$s2))]>;

   def ABSS_rr : RR<0x0B, 0x1D, (outs DataRegs:$d),
                  (ins DataRegs:$s1, DataRegs:$s2), "abss $d, $s1, $s2",
                  [(set DataRegs:$d, (TriCoreAbsDif DataRegs:$s1, DataRegs:$s2))]>;
   def ABSS_H_rr : RR<0x0B, 0x7D, (outs DataRegs:$d),
                  (ins DataRegs:$s1, DataRegs:$s2), "abss.h $d, $s1, $s2",
                  [(set DataRegs:$d, (TriCoreAbsDif DataRegs:$s1, DataRegs:$s2))]>;
}

multiclass mIB_H<bits<8> brr1, bits<8> brr2, bits<8> hrr1, bits<8> hrr2,
                        string asmstr> {
  def _B_rr : IRR_DcDaDb<brr1, brr2, asmstr # ".b">;
  def _H_rr : IRR_DcDaDb<hrr1, hrr2, asmstr # ".h">;
}

// - ADD Instructions

defm ADD : mIRR_RC<0x0B, 0x00, 0x8B, 0x00, "add">,
           mISRC_a15a<0xC2, 0x92, 0x9A, "add">,
           mISRR_a15a<0x42, 0x12, 0x1A, "add">,
           mIB_H<0x0B, 0x40, 0x0B, 0x60, "add">;

multiclass mIRR_SRC_SRR__A<bits<8> rr1, bits<8> rr2, bits<8> src1, bits<8> srr1,
                        string asmstr> {
  def _rr : IRR_2<rr1, rr2, asmstr, AddrRegs, AddrRegs, AddrRegs>;
  def _src : ISRC_Aa<src1, asmstr>;
  def _srr : ISRR_AaAb<srr1, asmstr>;
}

defm ADD_A : mIRR_SRC_SRR__A<0x01, 0x01, 0xB0, 0x30, "add.a">;
defm ADDC : mIRR_RC<0x0B, 0x05, 0x8B, 0x05, "addc">;

multiclass mIRLC<bits<8> op1, bits<8> op2, bits<8> op3, string asmstr>{
  def _rlc    : IRLC<op1, asmstr>;
  def H_rlc   : IRLC<op2, asmstr # "h">;
  def H_A_rlc : IRLC<op3, asmstr # "h.a">;
}

defm ADDI : mIRLC<0x1B, 0x9B, 0x11, "addi">;

multiclass mIH_HU_U<bits<8> h1, bits<8> h2,
                    bits<8> hu1, bits<8> hu2,
                    bits<8> u1, bits<8> u2,
                    string asmstr>{
  def _H  : IRR_DcDaDb<h1, h2, asmstr # ".h">;
  def _HU : IRR_DcDaDb<hu1,hu2,asmstr # ".hu">;
  def _U  : IRR_DcDaDb<u1, u2, asmstr # ".u">;
}

defm ADDS : mIRR_RC<0x0B, 0x02, 0x8B, 0x02, "adds">,
            mISRR_s<0x22, "adds">,
            mIH_HU_U<0x0B, 0x62, 0x0B, 0x63, 0x0B, 0x03, "adds">;
def ADDS_U_rc : IRC_2<0x8B, 0x03, "adds.u">;
def ADDSC_A_rr : IRR_AcAbDaN<0x01, 0x60, "addsc.a">;
def ADDSC_A_srrs : ISRRS<0x10, "addsc.a">;
def ADDSC_AT_rr : IRR_DcDaDb<0x01, 0x62, "addsc.at">;

defm ADDX : mIRR_RC<0x0B, 0x04, 0x8B, 0x04, "addx">;


/// AND Instructions

defm AND : mIRR_RC<0x0F, 0x08, 0x8F, 0x08, "and">,
           mISRR_s<0x26, "and">,
           mISC_D15<0x16, "and">;

def AND_AND_T  : IBIT<0x47, 0x00, "and.and.t">;
def AND_ANDN_T : IBIT<0x47, 0x03, "and.andn.t">;
def AND_NOR_T  : IBIT<0x47, 0x02, "and.nor.t">;
def AND_OR_T   : IBIT<0x47, 0x01, "and.or.t">;
def AND_T      : IBIT<0x87, 0x00, "and.t">;
def ANDN_T     : IBIT<0x87, 0x03, "andn.t">;

defm AND_EQ   : mIRR_RC<0x0B, 0x20, 0x8B, 0x20, "and.eq">;
defm AND_GE   : mIRR_RC<0x0B, 0x24, 0x8B, 0x24, "and.ge">;
defm AND_GE_U : mIRR_RC<0x0B, 0x25, 0x8B, 0x25, "and.ge.u">;
defm AND_LT   : mIRR_RC<0x0B, 0x22, 0x8B, 0x22, "and.lt">;
defm AND_LT_U : mIRR_RC<0x0B, 0x23, 0x8B, 0x23, "and.lt.u">;
defm AND_NE   : mIRR_RC<0x0B, 0x21, 0x8B, 0x21, "and.ne">;

defm ANDN     : mIRR_RC<0x0F, 0x0E, 0x8F, 0x0E, "andn">;

/// BISR
def BISR_rc : IRC<0xAD, 0x00, "bisr">;
def BISR_sc : ISC_0<0xE0, "bisr">;

/// Multiple Instructions (RR)
def BMAERGE_rr : IRR_DcDaDb<0x4B, 0x01, "bmerge">;
def BSPLIT_rr  : IRR_EcDa<0x4B, 0x09, "bsplit">;

/// BO Opcode Formats
// A[b], off10 (BO) (Base + Short Offset Addressing Mode)
class IBO_bso<bits<8> op1, bits<6> op2, string asmstr> 
    : BO<op1, op2, (outs), (ins AddrRegs:$s2, s10imm:$off10),
      asmstr # " [$s2]$off10", []>;
// P[b] (BO) (Bit Reverse Addressing Mode)
class IBO_r<bits<8> op1, bits<6> op2, string asmstr> 
    : BO<op1, op2, (outs), (ins AddrRegs:$s2),
      asmstr # " [${s2}+r]", []>;
// P[b], off10 (BO) (Circular Addressing Mode)
class IBO_c<bits<8> op1, bits<6> op2, string asmstr> 
    : BO<op1, op2, (outs), (ins AddrExtRegs:$s2, s10imm:$off10),
      asmstr # " [${s2}+c]$off10", []>;
// A[b], off10 (BO) (Post-increment Addressing Mode)

class IBO_pos<bits<8> op1, bits<6> op2, string asmstr> 
    : BO<op1, op2, (outs), (ins AddrRegs:$s2, s10imm:$off10),
      asmstr # " [${s2}+]$off10", []>;
// A[b], off10 (BO) (Pre-increment Addressing Mode)
class IBO_pre<bits<8> op1, bits<6> op2, string asmstr> 
    : BO<op1, op2, (outs), (ins AddrRegs:$s2, s10imm:$off10),
      asmstr # " [+${s2}]$off10", []>;


multiclass mIBO_a<bits<8> op11, bits<6> op12,
                  bits<8> op21, bits<6> op22,
                  bits<8> op31, bits<6> op32,
                  string asmstr> {
    def _bo_bso  : IBO_bso<op11, op12, asmstr>;
    def _bo_pos : IBO_pos<op21, op22, asmstr>;
    def _bo_pre  : IBO_pre<op31, op32, asmstr>;
}

multiclass mIBO_b<bits<8> op11, bits<6> op12,
                  bits<8> op21, bits<6> op22,
                  string asmstr> {
    def _bo_r    : IBO_r<op11, op12, asmstr>;
    def _bo_c    : IBO_c<op21, op22, asmstr>;
}

multiclass mIBO_ab<bits<8> op11, bits<6> op12, ///_bso
                   bits<8> op21, bits<6> op22, ///_r
                   bits<8> op31, bits<6> op32, ///_c
                   bits<8> op41, bits<6> op42, ///_post
                   bits<8> op51, bits<6> op52, ///_pre
                   string asmstr>{
  defm "" : mIBO_a<op11,op12,
                   op41,op42,
                   op51,op52,
                   asmstr>,
            mIBO_b<op21,op22,
                   op31,op32,
                   asmstr>;
}

/// CACHEA.* Instructions

defm CACHE_I : mIBO_ab<0x89, 0x2E,
                       0xA9, 0x0E,
                       0xA9, 0x1E,
                       0x89, 0x0E,
                       0x89, 0x1E,
                       "cache.i">;

defm CACHE_W : mIBO_ab<0x89, 0x2C,
                       0xA9, 0x0C,
                       0xA9, 0x1C,
                       0x89, 0x0C,
                       0x89, 0x1C,
                       "cache.w">;

defm CACHE_WI : mIBO_ab<0x89, 0x2D,
                        0xA9, 0x0D,
                        0xA9, 0x1D,
                        0x89, 0x0D,
                        0x89, 0x1D,
                        "cache.wi">;

defm CACHEI_W : mIBO_ab<0x89, 0x2B,
                        0xA9, 0x0B,
                        0xA9, 0x1B,
                        0x89, 0x0B,
                        0x89, 0x1B,
                        "cachei.w">;

defm CACHEI_I : mIBO_a<0x89, 0x2A,
                       0x89, 0x0A,
                       0x89, 0x1A,
                       "cachei.i">;

defm CACHEI_WI : mIBO_a<0x89, 0x2F,
                        0x89, 0x0F,
                        0x89, 0x1F,
                        "cachei.wi">;


/// RRR Opcodes Formats
// Dc Dd Da Db
class IRRR_DcDdDaDb<bits<8>op1, bits<4> op2, string asmstr>
    : RRR<op1, op2, (outs DataRegs:$d), (ins DataRegs:$s1, DataRegs:$s2, DataRegs:$s3),
          asmstr # " $d, $s3, $s1, $s2", []>;
// Dc Dd Da
class IRRR_DcDdDa<bits<8>op1, bits<4> op2, string asmstr>
    : RRR<op1, op2, (outs DataRegs:$d), (ins DataRegs:$s1, DataRegs:$s3),
          asmstr # " $d, $s3, $s1", []>;
// Ec Ed Db
class IRRR_EcEdEb<bits<8>op1, bits<4> op2, string asmstr>
    : RRR<op1, op2, (outs ExtRegs:$d), (ins DataRegs:$s2, ExtRegs:$s3),
          asmstr # " $d, $s3, $s2", []>;
// Dc Ed Da
class IRRR_DcEdDa<bits<8>op1, bits<4> op2, string asmstr>
    : RRR<op1, op2, (outs DataRegs:$d), (ins DataRegs:$s1, ExtRegs:$s3),
          asmstr # " $d, $s3, $s1", []>;

/// RCR Opcodes Formats
/// Dc Dd Da const9
class IRCR_DcDdDa<bits<8>op1, bits<3> op2, string asmstr>
    : RCR<op1, op2, (outs DataRegs:$d), (ins DataRegs:$s1, DataRegs:$s3, s9imm:$const9),
          asmstr # " $d, $s3, $s1, $const9", []>;
/// Ec Ed Da const9
class IRCR_EcEdDa<bits<8>op1, bits<3> op2, string asmstr>
    : RCR<op1, op2, (outs ExtRegs:$d), (ins DataRegs:$s1, ExtRegs:$s3, s9imm:$const9),
          asmstr # " $d, $s3, $s1, $const9", []>;

multiclass mIRCR<bits<8>op1, bits<3> op2, bits<8>op3, bits<3> op4, string asmstr>{
  def _rcr   : IRCR_DcDdDa<op1, op2, asmstr>;
  def _rcr_e : IRCR_EcEdDa<op3, op4, asmstr>;
}

/// CADD Instructions
def CADD_rcr : IRCR_DcDdDa<0xAB, 0x00, "cadd">;
def CADD_rrr : IRRR_DcDdDaDb<0x2B, 0x00, "cadd">;
def CADD_src : ISRC_a15<0x8A, "cadd">;

def CADDN_rcr : IRCR_DcDdDa<0xAB, 0x01, "caddn">;
def CADDN_rrr : IRRR_DcDdDaDb<0x2B, 0x01, "caddn">;
def CADDN_src : ISRC_a15<0xCA, "caddn">;

// Call Instructions

class IB<bits<8> op1, string asmstr>
    : B<op1, (outs), (ins s24imm:$disp24),
        asmstr # " $disp24", []>;

// The target of a 24-bit call instruction.
def call_target : Operand<i32> {
  let EncoderMethod = "encodeCallTarget";
}

let isCall = 1,
    Defs = [A11],
    Uses = [A10] in {
  def CALL_b    : IB<0x6D, "call">;
  def CALLA_b   : IB<0xED, "calla">;
  def CALLI_rr  : IRR_Aa<0x2D, 0x00, "calli">;
}

multiclass mI_H<bits<8> op1,bits<8> op2,bits<8> op3,bits<8> op4,
                string asmstr> {
  def _rr   : IRR_DcDa<op1, op2, asmstr>;
  def _H_rr : IRR_DcDa<op3, op4, asmstr # ".h">;
}

defm CLO : mI_H<0x0F, 0x1C, 0x0F, 0x7D, "clo">;
defm CLS : mI_H<0x0F, 0x1D, 0x0F, 0x7E, "cls">;
defm CLZ : mI_H<0x0F, 0x1B, 0x0F, 0x7C, "clz">;

def CMOV_src  : ISRC_a15<0xAA, "cmov">;
def CMOV_srr  : ISRR_a15<0x2A, "cmov">;
def CMOVN_src : ISRC_a15<0xEA, "cmovn">;
def CMOVN_srr : ISRR_a15<0x6A, "cmovn">;

// A[b], off10, E[a] (BO)(Base + Short Offset Addressing Mode)
class IBO_bsoEa<bits<8> op1, bits<6> op2, string asmstr> 
    : BO<op1, op2, (outs), (ins AddrRegs:$s2, s10imm:$off10, AddrExtRegs:$s1),
      asmstr # " $s1, [$s2]$off10", []>;
// P[b], E[a] (BO)(Bit-reverse Addressing Mode)
class IBO_rEa<bits<8> op1, bits<6> op2, string asmstr> 
    : BO<op1, op2, (outs AddrExtRegs:$b), (ins AddrRegs:$s2, AddrExtRegs:$s1),
      asmstr # " $s1, [${b}+r]", []>;
// P[b], off10, E[a] (BO)(Circular Addressing Mode)
class IBO_cEa<bits<8> op1, bits<6> op2, string asmstr> 
    : BO<op1, op2, (outs AddrExtRegs:$b), (ins s10imm:$off10, AddrExtRegs:$s1),
      asmstr # " $s1, [${b}+c]", []>;
// A[b], off10, E[a] (BO)(Post-increment Addressing Mode)
class IBO_posEa<bits<8> op1, bits<6> op2, string asmstr> 
    : BO<op1, op2, (outs), (ins AddrExtRegs:$s1, AddrRegs:$s2, s10imm:$off10),
      asmstr # " $s1, [${s2}+]$off10", []>;
// A[b], off10, E[a] (BO)(Pre-increment Addressing Mode)
class IBO_preEa<bits<8> op1, bits<6> op2, string asmstr> 
    : BO<op1, op2, (outs), (ins AddrExtRegs:$s1, AddrRegs:$s2, s10imm:$off10),
      asmstr # " $s1, [+${s2}]$off10", []>;


multiclass mIBO_Ea<bits<8> bso1, bits<6> bso2, ///_bso
                   bits<8> r1, bits<6> r2, ///_r
                   bits<8> c1, bits<6> c2, ///_c
                   bits<8> pos1, bits<6> pos_r, ///_post
                   bits<8> pre1, bits<6> pre_c, ///_pre
                   string asmstr>{
  def _bo_bso  : IBO_bsoEa<bso1, bso2, asmstr>;
  def _bo_pos  : IBO_posEa<pos1, pos_r, asmstr>;
  def _bo_pre  : IBO_preEa<pre1, pre_c, asmstr>;
  def _bo_r    : IBO_rEa<r1, r2, asmstr>;
  def _bo_c    : IBO_cEa<c1, c2, asmstr>;
}

defm CMPSWAP_W : mIBO_Ea<0x49, 0x23, 0x69, 0x03,
                         0x69, 0x13, 0x49,0x03,
                         0x49, 0x13, "CMPSWAP.W">;

def CRC32_B_rr  : IRR_DcDbDa<0x4B, 0x06, "crc32.b">;
def CRC32B_W_rr : IRR_DcDbDa<0x4B, 0x03, "crc32b.w">;
def CRC32L_W_rr : IRR_DcDbDa<0x4B, 0x07, "crc32l.w">;
def CRCN_rrr    : IRRR_DcDdDaDb<0x6B, 0x01, "crcn">;

def CSUB_rrr    : IRRR_DcDdDaDb<0x2B, 0x02, "csub">;
def CSUBN_rrr   : IRRR_DcDdDaDb<0x2B, 0x03, "csub">;

class ISR_0<bits<8> op1, bits<4> op2, string asmstr>
    : SR<op1, op2, (outs), (ins),
        asmstr, []>;

class ISR_1<bits<8> op1, bits<4> op2, string asmstr>
    : SR<op1, op2, (outs), (ins DataRegs:$s1),
        asmstr # " $s1", []>;

class ISYS_0<bits<8> op1, bits<6> op2, string asmstr>
    : SYS<op1, op2, (outs), (ins),
        asmstr, []>;
class ISYS_1<bits<8> op1, bits<6> op2, string asmstr>
    : SYS<op1, op2, (outs), (ins DataRegs:$s1),
        asmstr # " $s1", []>;

def DEBUG_sr  : ISR_0<0x00, 0x0A, "debug">;
def DEBUG_sys : ISYS_0<0x0D, 0x04, "debug">;

/// RRPW Instruction Formats
/// op D[c], D[a], pos, width
class IRRPW_DcDaPW<bits<8> op1, bits<2> op2, string asmstr>
     : RRPW<op1, op2, (outs DataRegs:$d), (ins DataRegs:$s1, i32imm:$pos, i32imm:$width),
            asmstr # " $d, $s1, $pos, $width", []>;
/// op D[c], D[b], pos, width
class IRRPW_DcDbPW<bits<8> op1, bits<2> op2, string asmstr>
     : RRPW<op1, op2, (outs DataRegs:$d), (ins DataRegs:$s2, i32imm:$pos, i32imm:$width),
            asmstr # " $d, $s2, $pos, $width", []>;
/// op E[c], D[b], pos, width
class IRRPW_EcDbPW<bits<8> op1, bits<2> op2, string asmstr>
     : RRPW<op1, op2, (outs ExtRegs:$d), (ins DataRegs:$s2, i32imm:$pos, i32imm:$width),
            asmstr # " $d, $s2, $pos, $width", []>;
/// op D[c], D[a], D[b], pos
class IRRPW_DcDaDbP<bits<8> op1, bits<2> op2, string asmstr>
     : RRPW<op1, op2, (outs DataRegs:$d), (ins DataRegs:$s1, DataRegs:$s2, i32imm:$pos),
            asmstr # " $d, $s1, $s2, $pos", []>;
/// op D[c], D[a], D[b], pos, width
class IRRPW_DcDaDbPW<bits<8> op1, bits<2> op2, string asmstr>
     : RRPW<op1, op2, (outs DataRegs:$d), (ins DataRegs:$s1, DataRegs:$s2, i32imm:$pos, i32imm:$width),
            asmstr # " $d, $s1, $s2, $pos, $width", []>;

/// RRRR Instruction Formats
/// op D[c], D[a], D[b], D[d]
class IRRRR<bits<8> op1, bits<3> op2, string asmstr> 
    : RRRR<op1, op2, (outs DataRegs:$d), (ins DataRegs:$s1, DataRegs:$s2, DataRegs:$s3),
            asmstr # " $d, $s1, $s2, $s3", []>;
/// op D[c], D[a], D[d]
class IRRRR_ad<bits<8> op1, bits<3> op2, string asmstr> 
    : RRRR<op1, op2, (outs DataRegs:$d), (ins DataRegs:$s1, DataRegs:$s3),
            asmstr # " $d, $s1, $s3", []>;
/// op D[c], D[a], E[d]
class IRRRR_aEd<bits<8> op1, bits<3> op2, string asmstr> 
    : RRRR<op1, op2, (outs DataRegs:$d), (ins DataRegs:$s1, ExtRegs:$s3),
            asmstr # " $d, $s1, $s3", []>;

/// op D[c], D[a], D[b], D[d], width
class IRRRW_abd<bits<8> op1, bits<3> op2, string asmstr>
     : RRRW<op1, op2, (outs DataRegs:$d), (ins DataRegs:$s1, DataRegs:$s2, DataRegs:$s3, i32imm:$width),
            asmstr # " $d, $s1, $s2, $s3, $width", []>;
/// op D[c], D[a], D[d], width
class IRRRW_ad<bits<8> op1, bits<3> op2, string asmstr>
     : RRRW<op1, op2, (outs DataRegs:$d), (ins DataRegs:$s1, DataRegs:$s3, i32imm:$width),
            asmstr # " $d, $s1, $s3, $width", []>;
/// op E[c], D[b], D[d], width
class IRRRW_Ebd<bits<8> op1, bits<3> op2, string asmstr>
     : RRRW<op1, op2, (outs ExtRegs:$d), (ins DataRegs:$s2, DataRegs:$s3, i32imm:$width),
            asmstr # " $d, $s2, $s3, $width", []>;

/// op E[c], const4, pos, width
class IRCPW_E<bits<8> op1, bits<2> op2, string asmstr>
     : RCPW<op1, op2, (outs ExtRegs:$d), (ins i32imm:$const4, i32imm:$pos, i32imm:$width),
            asmstr # " $d, $const4, $pos, $width", []>;
/// op D[c], D[a], const4, pos, width
class IRCPW_a<bits<8> op1, bits<2> op2, string asmstr>
     : RCPW<op1, op2, (outs DataRegs:$d), (ins DataRegs:$s1, i32imm:$const4, i32imm:$pos, i32imm:$width),
            asmstr # " $d, $s1, $const4, $pos, $width", []>;


// D[c], D[a], const4, E[d] (RCRR)
class IRCRR_DcDaCEd<bits<8> op1, bits<3> op2, string asmstr>
     : RCRR<op1, op2, (outs DataRegs:$d), (ins DataRegs:$s1, i32imm:$const4, ExtRegs:$s3),
            asmstr # " $d, $s1, $const4, $s3", []>;
// E[c], const4, D[d], width (RCRW)
class IRCRW_EcCDdW<bits<8> op1, bits<3> op2, string asmstr>
     : RCRW<op1, op2, (outs ExtRegs:$d), (ins i32imm:$const4, DataRegs:$s3, i32imm:$width),
            asmstr # " $d, $const4, $s3, $width", []>;
// D[c], D[a], const4, D[d], width (RCRW)
class IRCRW_DcDaCDdW<bits<8> op1, bits<3> op2, string asmstr>
     : RCRW<op1, op2, (outs DataRegs:$d), (ins DataRegs:$s1, i32imm:$const4, DataRegs:$s3, i32imm:$width),
            asmstr # " $d, $s1, $const4, $s3, $width", []>;

multiclass mIRRPWab_RRRR<bits<8> op1, bits<2> op2, bits<8> op3, bits<3> op4, string asmstr>{
  def _rrpw : IRRPW_DcDaDbP<op1, op2, asmstr>;
  def _rrrr : IRRRR<op3, op4, asmstr>;
}

defm DEXTR : mIRRPWab_RRRR<0x77, 0x00, 0x17, 0x04, "dextr">;

def DISABLE_sys   : ISYS_0<0x0D, 0x0D, "disable">;
def DISABLE_sys_1 : ISYS_1<0x0D, 0x0F, "disable">;

def DSYNC_sys : ISYS_0<0x0D, 0x12, "dsync">;

def DVADJ_rrr : IRRR_EcEdEb<0x6B, 0x0D, "dvadj">;

multiclass mI_U_RR_Eab<bits<8> op1, bits<8> op2, bits<8> op3, bits<8> op4,
                string asmstr> {
  def _rr   : IRR_EcDaDb<op1, op2, asmstr>;
  def _U_rr : IRR_EcDaDb<op3, op4, asmstr # ".u">;
}

defm DIV     : mI_U_RR_Eab<0x4B, 0x20, 0x4B, 0x21, "div">;
defm DVINIT  : mI_U_RR_Eab<0x4B, 0x1A, 0x4B, 0x0A, "dvinit">;

multiclass mIU_RR_Eab<bits<8> op1, bits<8> op2, bits<8> op3, bits<8> op4,
                string asmstr> {
  def _rr   : IRR_EcDaDb<op1, op2, asmstr>;
  def U_rr  : IRR_EcDaDb<op3, op4, asmstr # "u">;
}

defm DVINIT_B  : mIU_RR_Eab<0x4B, 0x5A, 0x4B, 0x4A, "dvinit.b">;
defm DVINIT_H  : mIU_RR_Eab<0x4B, 0x3A, 0x4B, 0x2A, "dvinit.h">;

multiclass mI_U_RRR_EEdb<bits<8> op1, bits<4> op2, bits<8> op3, bits<4> op4,
                string asmstr> {
  def _rrr   : IRRR_EcEdEb<op1, op2, asmstr>;
  def _U_rrr : IRRR_EcEdEb<op3, op4, asmstr # ".u">;
}

defm DVSTEP : mI_U_RRR_EEdb<0x6B, 0x0F, 0x6B, 0x0E, "dvstep">;

def ENABLE_sys   : ISYS_0<0x0D, 0x0C, "enable">;

multiclass mIB_H_W<bits<8> brr1, bits<8> brr2,
                   bits<8> hrr1, bits<8> hrr2,
                   bits<8> wrr1, bits<8> wrr2,
                   string asmstr>
        :  mIB_H<brr1, brr2, hrr1, hrr2, asmstr>{
  def _W_rr : IRR_DcDaDb<wrr1, wrr2, asmstr # ".w">;
}

defm EQ    : mIRR_RC<0x0B, 0x10, 0x8B, 0x10, "eq">
           , mIB_H_W<0x0B, 0x50, 0x0B, 0x70, 0x0B, 0x90, "eq">;
def EQ_src : ISRC_15a<0xBA, "eq">;
def EQ_srr : ISRR_15a<0x3A, "eq">;
def EQ_A_rr: IRR_DcAaAb<0x01, 0x40, "eq.a">;

defm EQANY_B : mIRR_RC<0x0B, 0x56, 0x8B, 0x56, "eqany.b">;
defm EQANY_H : mIRR_RC<0x0B, 0x76, 0x8B, 0x76, "eqany.h">;

def EQZ_A_rr : IRR_DcAa<0x01, 0x48, "eqz.a">;

def EXTR_rrpw : IRRPW_DcDaPW<0x37, 0x02, "extr">;
def EXTR_rrrr : IRRRR_aEd<0x17, 0x02, "extr">;
def EXTR_rrrw : IRRRW_ad<0x57, 0x02, "extr">;

def EXTR_U_rrpw : IRRPW_DcDaPW<0x37, 0x03, "extr.u">;
def EXTR_U_rrrr : IRRRR_aEd<0x17, 0x03, "extr.u">;
def EXTR_U_rrrw : IRRRW_ad<0x57, 0x03, "extr.u">;

def FCALL_b  : IB<0x61, "fcall">;
def FCALLA_b : IB<0xE1, "fcalla">;
def FCALLA_i : IRR_Aa<0x2D, 0x01, "fcalli">;

def FRET_sr : ISR_0<0x00, 0x07, "fret">;
def FRET_sys : ISR_0<0x0D, 0x03, "fret">;

multiclass mI_U__RR_RC<bits<8> op1, bits<8> op2, bits<8> op3, bits<7> op4,
                      bits<8> uop1, bits<8> uop2, bits<8> uop3, bits<7> uop4,
                      string asmstr> {
  defm ""  : mIRR_RC<op1, op2, op3, op4, asmstr>;
  defm _U  : mIRR_RC<uop1, uop2, uop3, uop4, asmstr # ".u">;
}

defm GE : mI_U__RR_RC<0x0B, 0x14, 0x8B, 0x14,
                     0x0B, 0x15, 0x8B, 0x15, "ge">;
def GE_A_rr : IRR_DcAaAb<0x01, 0x43, "ge.a">;

def IMASK_rcpw : IRCPW_E<0xB7, 0x01, "imask">;
def IMASK_rcrw : IRCRW_EcCDdW<0xD7, 0x01, "imask">;
def IMASK_rrpw : IRRPW_EcDbPW<0x37, 0x01, "imask">;
def IMASK_rrrw : IRRRW_Ebd<0x57, 0x01, "imask">;

def INS_T  : IBIT<0x67, 0x00, "ins.t">;
def INSN_T : IBIT<0x67, 0x01, "insn.t">;

def INSERT_rcpw : IRCPW_a  <0xB7, 0x00, "insert">;
def INSERT_rcrr : IRCRR_DcDaCEd<0x97, 0x00, "insert">;
def INSERT_rcrw : IRCRW_DcDaCDdW <0xD7, 0x00, "insert">;
def INSERT_rrpw : IRRPW_DcDaDbPW<0x37, 0x00, "insert">;
def INSERT_rrrr : IRRRW_abd<0x17, 0x00, "insert">;
def INSERT_rrrw : IRRRW_abd<0x57, 0x00, "insert">;

def ISYNC_sys : ISYS_0<0x0D, 0x13, "isync">;

defm IXMAX : mI_U_RRR_EEdb<0x6B, 0x0A, 0x6B, 0x0B, "ixmax">;
defm IXMIN : mI_U_RRR_EEdb<0x6B, 0x08, 0x6B, 0x09, "ixmin">;

class ISB<bits<8> op1, string asmstr>
    : SB<op1, (outs), (ins s8imm:$disp8), asmstr # " $disp8", []>;

def J_b  : IB<0x1D, "j">;
def J_sb : ISB<0x3C, "j">;
def JA_b : IB<0x9D, "ja">;

// disp15
class IBRR_0<bits<8> op1, bits<1> op2, string asmstr>
    : BRR<op1, op2, (outs), (ins i32imm:$disp15), asmstr # " $disp15", []>;
// A[a], disp15
class IBRR_Aa<bits<8> op1, bits<1> op2, string asmstr>
    : BRR<op1, op2, (outs), (ins AddrRegs:$s1, i32imm:$disp15), asmstr # " $s1, $disp15", []>;
// A[b], disp15
class IBRR_Ab<bits<8> op1, bits<1> op2, string asmstr>
    : BRR<op1, op2, (outs), (ins AddrRegs:$s2, i32imm:$disp15), asmstr # " $s2, $disp15", []>;
// A[a], A[b], disp15
class IBRR_AaAb<bits<8> op1, bits<1> op2, string asmstr>
    : BRR<op1, op2, (outs), (ins AddrRegs:$s1, AddrRegs:$s2, i32imm:$disp15),
          asmstr # " $s1, $s2, $disp15", []>;
// D[a], D[b], disp15
class IBRR<bits<8> op1, bits<1> op2, string asmstr>
    : BRR<op1, op2, (outs), (ins DataRegs:$s1, DataRegs:$s2, i32imm:$disp15),
          asmstr # " $s1, $s2, $disp15", []>;


class IBRC<bits<8> op1, bits<1> op2, string asmstr>
    : BRC<op1, op2, (outs), (ins jmptarget:$disp15, DataRegs:$s1, s4imm:$const4),
      !strconcat(asmstr, " $s1, $const4, $disp15"), []>;

class ISBC<bits<8> op1, string asmstr>
    : SBC<op1, (outs), (ins s4imm:$const4, jmptarget:$disp4),
      !strconcat(asmstr, " %d15, $const4, $disp4"), []>;

// D[15], D[b], disp4 (SBR)
class ISBR_15b<bits<8> op1, string asmstr>
    : SBR<op1, (outs), (ins DataRegs:$s2, jmptarget:$disp4),
      !strconcat(asmstr, " %d15, $s2, $disp4"), []>;
// D[b], disp4 (SBR)
class ISBR_b<bits<8> op1, string asmstr>
    : SBR<op1, (outs), (ins DataRegs:$s2, jmptarget:$disp4),
      !strconcat(asmstr, " $s2, $disp4"), []>;
// A[b], disp4 (SBR)
class ISBR_Ab<bits<8> op1, string asmstr>
    : SBR<op1, (outs), (ins AddrRegs:$s2, jmptarget:$disp4),
      !strconcat(asmstr, " $s2, $disp4"), []>;

multiclass mIBRC_BRR<bits<8> c1, bits<1> c2, bits<8> r1, bits<1> r2, string asmstr>{
  def _brc : IBRC<c1, c2, asmstr>;
  def _brr : IBRR<r1, r2, asmstr>;
}

multiclass mIBRC_BRR_2SBC_2SBR<bits<8> c1, bits<1> c2, bits<8> r1, bits<1> r2,
                               bits<8> x1, bits<8> x2, bits<8> x3, bits<8> x4,
                               string asmstr>
         : mIBRC_BRR<c1, c2, r1, r2, asmstr> {
  def _sbc1 : ISBC<x1, asmstr>;
  def _sbc2 : ISBC<x2, asmstr>;
  def _sbr1 : ISBR_15b<x3, asmstr>;
  def _sbr2 : ISBR_15b<x4, asmstr>;
}

defm JEQ : mIBRC_BRR_2SBC_2SBR<0xDF, 0x00, 0x5F, 0x00,
                               0x1E, 0x9E, 0x3E, 0xBE,
                               "jeq">; 
def JEQ_A_brr : IBRR_AaAb<0x7D, 0x00, "jeq.a">;

defm JGE   : mIBRC_BRR<0xFF, 0x00, 0x7F, 0x00, "jge">;
defm JGE_U : mIBRC_BRR<0xFF, 0x01, 0x7F, 0x01, "jge.u">;

def JGEZ_sbr : ISBR_b<0xCE, "jgez">;
def JGTZ_sbr : ISBR_b<0x4E, "jgtz">;

def JI_rr : IRR_Aa<0x2D, 0x03, "ji">;
def JI_sr : ISR_1<0xDC, 0x00, "ji">;

def JL_b  : IB<0x5D, "jl">;
def JLA_b : IB<0xDD, "jla">;

def JLEZ_sbr : ISBR_b<0x8E, "jlez">;

def JLI_rr : IRR_Aa<0x2D, 0x02, "jli">;

defm JLT   : mIBRC_BRR<0xBF, 0x00, 0x3F, 0x00, "jlt">;
defm JLT_U : mIBRC_BRR<0xBF, 0x01, 0x3F, 0x01, "jlt.u">;

def JLTZ_sbr : ISBR_b<0x0E, "jltz">;

defm JNE : mIBRC_BRR_2SBC_2SBR<0xDF, 0x01, 0x5F, 0x01,
                               0x5E, 0xDE, 0x7E, 0xFE,
                               "jne">;

def JNE_A_brr : IBRR_AaAb<0x7D, 0x01, "jne.a">;

defm JNED : mIBRC_BRR<0x9F, 0x01, 0x1F, 0x01, "jned">;
defm JNEI : mIBRC_BRR<0x9F, 0x00, 0x1F, 0x00, "jnei">;

multiclass mIBRR_SBR<bits<8> brr1, bits<1> brr2, bits<8> sbr, string asmstr> {
  def _brr : IBRR<brr1, brr2, asmstr>;
  def _sbr : ISBR_Ab<sbr, asmstr>;
}

multiclass mISB_SBR_T_BRN_SBRN<bits<8> sb, bits<8> sbr,
                               bits<8> a1, bits<1> a2, bits<8> a3,
                               bits<7> brn1, bits<1> brn2, bits<8> sbrn,
                               string asmstr>{
  def _sb  : ISB<sb, asmstr>;
  def _sbr : ISBR_b<sbr, asmstr>;
  defm _A  : mIBRR_SBR<a1, a2, a3, asmstr # ".a">;
  def _T_brn : BRN<brn1, brn2, (outs), (ins DataRegs:$s1, i32imm:$n, i32imm:$disp15),
                   asmstr # ".t $s1, $n, $disp15", []>;
  def _T_sbrn: SBRN<sbrn, (outs), (ins i32imm:$n, i32imm:$disp4),
                   asmstr # ".t %d15, $n, $disp4", []>;
}

defm JNZ : mISB_SBR_T_BRN_SBRN<0xEE, 0xF6, 0xBD, 0x01, 0x7C, 0x6F, 0x01, 0xA3, "jnz">;
defm JZ  : mISB_SBR_T_BRN_SBRN<0x6E, 0x76, 0xBD, 0x00, 0xBC, 0x6F, 0x00, 0x2E, "jz">;


class IABS_off18<bits<8> op1, bits<2> op2, string asmstr> 
    : ABS<op1, op2, (outs), (ins i32imm:$off18),
      asmstr # " $off18", []>;
class IABS_RO<bits<8> op1, bits<2> op2, string asmstr, RegisterClass dc> 
    : ABS<op1, op2, (outs dc:$d), (ins i32imm:$off18),
      asmstr # " $d, $off18", []>;
class IABS_OR<bits<8> op1, bits<2> op2, string asmstr, RegisterClass s1c> 
    : ABS<op1, op2, (outs), (ins s1c:$s1, i32imm:$off18),
      asmstr # " $off18, $s1", []>;

class IBOL_RAaO<bits<8> op1, string asmstr, RegisterClass dc> 
    : BOL<op1, (outs dc:$d), (ins AddrRegs:$s1, i32imm:$off16),
      asmstr # " $d, [$s1]$off16", []>;

class IBOL_AbOR<bits<8> op1, string asmstr, RegisterClass dc> 
    : BOL<op1, (outs AddrRegs:$d), (ins dc:$s1, i32imm:$off16),
      asmstr # " [$d]$off16, $s1", []>;

class ISLR<bits<8> op1, string asmstr, RegisterClass dc>
    : SLR<op1, (outs dc:$d), (ins AddrRegs:$s2),
      asmstr # " $d, [$s2]", []>;
class ISLR_pos<bits<8> op1, string asmstr, RegisterClass dc>
    : SLR<op1, (outs dc:$d), (ins AddrRegs:$s2),
      asmstr # " $d, [$s2+]", []>;

class ISLRO<bits<8> op1, string asmstr, RegisterClass dc>
    : SLRO<op1, (outs dc:$d), (ins u4imm:$off4),
      asmstr # " $d, [%a15]$off4", []>;

class ISRO_A15RO<bits<8> op1, string asmstr, RegisterClass s2c>
    : SRO<op1, (outs), (ins s2c:$s2, u4imm:$off4),
      asmstr # " %a15, [$s2]$off4", []>;

class ISRO_A15ROst<bits<8> op1, string asmstr, RegisterClass s2c>
    : SRO<op1, (outs), (ins s2c:$s2, u4imm:$off4),
      asmstr # " [$s2]$off4, %a15", []>;

class ISRO_D15RO<bits<8> op1, string asmstr, RegisterClass s2c>
    : SRO<op1, (outs), (ins s2c:$s2, u4imm:$off4),
      asmstr # " %d15, [$s2]$off4", []>;

class ISRO_D15ROst<bits<8> op1, string asmstr, RegisterClass s2c>
    : SRO<op1, (outs), (ins s2c:$s2, u4imm:$off4),
      asmstr # " [$s2]$off4, %d15", []>;

// A|D[a], A[b], off10 (BO) (Base + Short Offset Addressing Mode)
class IBO_RAbso<bits<8> op1, bits<6> op2, string asmstr, RegisterClass dc> 
    : BO<op1, op2, (outs dc:$d), (ins AddrRegs:$s2, s10imm:$off10),
      asmstr # " $d, [$s2]$off10", []>;
// A|D[a], P[b] (BO) (Bit Reverse Addressing Mode)
class IBO_RPr<bits<8> op1, bits<6> op2, string asmstr, RegisterClass dc>
    : BO<op1, op2, (outs dc:$d), (ins AddrExtRegs:$s2),
      asmstr # " $d, [${s2}+r]", []>;
// A|D[a], P[b], off10 (BO) (Circular Addressing Mode)
class IBO_RPc<bits<8> op1, bits<6> op2, string asmstr, RegisterClass dc> 
    : BO<op1, op2, (outs dc:$d), (ins AddrExtRegs:$s2, s10imm:$off10),
      asmstr # " $d, [${s2}+c]$off10", []>;
// A|D[a], A[b], off10 (BO)(Post-increment Addressing Mode)
class IBO_RApos<bits<8> op1, bits<6> op2, string asmstr, RegisterClass dc>
    : BO<op1, op2, (outs), (ins dc:$s1, AddrRegs:$s2, s10imm:$off10),
      asmstr # " $s1, [${s2}+]$off10", []>;
// A|D[a], A[b], off10 (BO) (Pre-increment Addressing Mode)
class IBO_RApre<bits<8> op1, bits<6> op2, string asmstr, RegisterClass dc>
    : BO<op1, op2, (outs), (ins dc:$s1, AddrRegs:$s2, s10imm:$off10),
      asmstr # " $s1, [+${s2}]$off10", []>;


multiclass mIABS_BO<bits<8> abs1, bits<2> abs2,   ///_abs
                    bits<8> prefix1, bits<8> prefix2,
                    bits<6> bso2, ///_bso
                    bits<6> pos_r, ///_pos|_r
                    bits<6> pre_c, ///_pre|_c
                    string asmstr, RegisterClass rc>{
  def _abs     : IABS_RO<abs1, abs2, asmstr, rc>;
  def _bo_bso  : IBO_RAbso<prefix1, bso2, asmstr, rc>;
  def _bo_pos : IBO_RApos<prefix1, pos_r, asmstr, rc>;
  def _bo_pre  : IBO_RApre<prefix1, pre_c, asmstr, rc>;
  def _bo_r    : IBO_RPr<prefix2, pos_r, asmstr, rc>;
  def _bo_c    : IBO_RPc<prefix2, pre_c, asmstr, rc>;
}

multiclass mISLR_SLRO_SRO<bits<8> slr, bits<8> slrp, bits<8> slro, bits<8> sro,
                    string asmstr, RegisterClass c>{
  def _slr : ISLR<slr, asmstr, c>;
  def _slr_post : ISLR_pos<slrp, asmstr, c>;
  def _slro : ISLRO<slro, asmstr, c>;
  def _sro  : ISRO_A15RO<sro, asmstr, c>;
}

multiclass mISLR_SLRO_SROd15<bits<8> slr, bits<8> slrp, bits<8> slro, bits<8> sro,
                    string asmstr, RegisterClass c>{
  def _slr : ISLR<slr, asmstr, c>;
  def _slr_post : ISLR_pos<slrp, asmstr, c>;
  def _slro : ISLRO<slro, asmstr, c>;
  def _sro  : ISRO_D15RO<sro, asmstr, c>;
}

defm LD_A  : mIABS_BO<0x85, 0x02, 0x09, 0x29, 0x26, 0x06, 0x16, "ld.a", AddrRegs>
           , mISLR_SLRO_SRO<0xD4, 0xC4, 0xC8, 0xCC, "ld.a", AddrRegs>;
def LD_A_bol : IBOL_RAaO<0x99, "ld.a", AddrRegs>;
def LD_A_sc  : ISC_A15A10C<0xD8, "ld.a">;

defm LD_B  : mIABS_BO<0x05, 0x00, 0x09, 0x29, 0x20, 0x00, 0x10,"ld.b", DataRegs>;
def LD_B_bol : IBOL_RAaO<0x79, "ld.b", DataRegs>;

defm LD_BU  : mIABS_BO<0x05, 0x01, 0x09, 0x29, 0x21, 0x01, 0x11, "ld.bu", DataRegs>
            , mISLR_SLRO_SROd15<0x14, 0x04, 0x08, 0x0C, "ld.bu", DataRegs>;
def LD_BU_bol : IBOL_RAaO<0x39, "ld.bu", DataRegs>;

defm LD_D  : mIABS_BO<0x85, 0x01, 0x09, 0x29, 0x25, 0x05, 0x15, "ld.d", ExtRegs>;
defm LD_DA : mIABS_BO<0x85, 0x03, 0x09, 0x29, 0x27, 0x07, 0x17, "ld.da", AddrExtRegs>;

defm LD_H  : mIABS_BO<0x05, 0x02, 0x09, 0x29, 0x22, 0x02, 0x12, "ld.h", DataRegs>
           , mISLR_SLRO_SROd15<0x94, 0x84, 0x88, 0x8C, "ld.h", DataRegs>;
def LD_H_bol : IBOL_RAaO<0xC9, "ld.h", DataRegs>;

defm LD_HU  : mIABS_BO<0x05, 0x03, 0x09, 0x29, 0x23, 0x03, 0x13, "ld.hu", DataRegs>;
def LD_HU_bol : IBOL_RAaO<0xB9, "ld.hu", DataRegs>;

defm LD_Q  : mIABS_BO<0x45, 0x00, 0x09, 0x29, 0x28, 0x08, 0x18, "ld.q", DataRegs>;

defm LD_W  : mIABS_BO<0x85, 0x00, 0x09, 0x29, 0x24, 0x04, 0x14, "ld.w", DataRegs>
           , mISLR_SLRO_SROd15<0x54, 0x44, 0x48, 0x4C, "ld.w", AddrRegs>;
def LD_W_bol : IBOL_RAaO<0x19, "ld.w", DataRegs>;
def LD_W_sc  : ISC_A15A10C<0x58, "ld.w">;


def LDLCX_abs    : IABS_off18<0x15, 0x02, "ldlcx">;
def LDLCX_bo_bso : IBO_bso<0x49, 0x24, "ldlcx">;

def LDMST_abs : IABS_OR<0xE5, 0x01, "ldmst", ExtRegs>;
defm LDMST    : mIBO_Ea<0x49, 0x21, 0x69, 0x01, 0x69, 0x11, 0x49, 0x01, 0x49, 0x11, "ldmst">;

def LDUCX_abs    : IABS_off18<0x15, 0x03, "lducx">;
def LDUCX_bo_bso : IBO_bso<0x49, 0x25, "lducx">;

def LEA_abs    : IABS_RO<0xC5, 0x00, "lea", AddrRegs>;
def LEA_bo_bso : IBO_RAbso<0x49, 0x28, "lea", AddrRegs>;
def LEA_bol    : IBOL_RAaO<0xD9, "lea", AddrRegs>;

def LHA_abs    : IABS_RO<0xC5, 0x01, "lha", AddrRegs>;

def LOOP_brr : IBRR_Ab<0xFD, 0x00, "loop">;
def LOOP_sbr : ISBR_Ab<0xFC, "loop">;
def LOOPU_brr : IBRR_0<0xFD, 0x01, "loopu">;

defm LT : mIRR_RC<0x0B, 0x12, 0x8B, 0x12, "lt">;
def LT_src : ISRC_15a<0xFA, "lt">;
def LT_srr : ISRR_15a<0x7A, "lt">;

defm LT_U : mIRR_RC<0x0B, 0x13, 0x8B, 0x13, "lt.u">;
def LT_A_rr : IRR_DcAaAb<0x01, 0x42, "lt.a">;

multiclass mIU__RR_ab<bits<8> op1, bits<8> op2,
                      bits<8> uop1, bits<8> uop2,
                      string asmstr> {
  def ""  : IRR_DcDaDb<op1, op2, asmstr>;
  def U   : IRR_DcDaDb<uop1, uop2, asmstr # "u">;
}

defm LT_B : mIU__RR_ab<0x0B, 0x52, 0x0B, 0x53, "lt.b">;
defm LT_H : mIU__RR_ab<0x0B, 0x72, 0x0B, 0x73, "lt.h">;
defm LT_W : mIU__RR_ab<0x0B, 0x92, 0x0B, 0x93, "lt.w">;

class IRRR1_label<bits<8> op1, bits<6> op2, string asmstr, RegisterClass rc, string label>
    : RRR1<op1, op2, (outs rc:$d), (ins DataRegs:$s1, DataRegs:$s2, rc:$s3, u2imm:$n),
           asmstr # " $d, $s3, $s1, $s2 " # label # ", $n", []>;
class IRRR1_label2<bits<8> op1, bits<6> op2, string asmstr, RegisterClass rc, string label1, string label2>
    : RRR1<op1, op2, (outs rc:$d), (ins DataRegs:$s1, DataRegs:$s2, rc:$s3, u2imm:$n),
           asmstr # " $d, $s3, ${s1}" # label1 # ", ${s2}" # label2 # ", $n", []>;
class IRRR1<bits<8> op1, bits<6> op2, string asmstr, RegisterClass rc>
    : RRR1<op1, op2, (outs rc:$d), (ins DataRegs:$s1, DataRegs:$s2, rc:$s3, u2imm:$n),
           asmstr # " $d, $s3, $s1, $s2, $n", []>;

class IRRR2<bits<8> op1, bits<8> op2, string asmstr, RegisterClass rc>
    : RRR2<op1, op2, (outs rc:$d), (ins DataRegs:$s1, DataRegs:$s2, rc:$s3),
           asmstr # " $d, $s3, $s1, $s2", []>;

multiclass mIRRR2<bits<8> op1, bits<8> op2, bits<8> op3, bits<8> op4, string asmstr>{
  def _rrr2   : IRRR2<op1, op2, asmstr, DataRegs>;
  def _rrr2_e : IRRR2<op3, op4, asmstr, ExtRegs>;
}

defm MADD : mIRCR<0x13, 0x01, 0x13, 0x03, "madd">
          , mIRRR2<0x03, 0x0A, 0x03, 0x6A, "madd">;

defm MADDS : mIRCR<0x13, 0x05, 0x13, 0x07, "madds">
           , mIRRR2<0x03, 0x8A, 0x03, 0xEA, "madds">;

multiclass mIRRR1_LU2<bits<8> prefix, bits<6> ll2, bits<6> lu2,
                      bits<6> ul2, bits<6> uu2,
                      string asmstr, RegisterClass rc>{
  def _rrr1_LL : IRRR1_label<prefix, ll2, asmstr, rc, "LL">;
  def _rrr1_LU : IRRR1_label<prefix, lu2, asmstr, rc, "LU">;
  def _rrr1_UL : IRRR1_label<prefix, ul2, asmstr, rc, "UL">;
  def _rrr1_UU : IRRR1_label<prefix, uu2, asmstr, rc, "UU">;
}
multiclass mIRRR1_E_LU2<bits<8> ll1, bits<6> ll2, bits<6> lu2,
                       bits<6> ul2, bits<6> uu2, string asmstr>{
  defm "" : mIRRR1_LU2<ll1, ll2, lu2, ul2, uu2, asmstr, ExtRegs>;
}

defm MADD_H  : mIRRR1_E_LU2<0x83, 0x1A, 0x19, 0x18, 0x1B, "madd.h">;
defm MADDS_H : mIRRR1_E_LU2<0x83, 0x3A, 0x39, 0x38, 0x3B, "madds.h">;

multiclass mIRRR1_maddq_msubq<bits<8> prefix, bits<6> op1, bits<6> op2, bits<6> op3, bits<6> op4,
                              bits<6> op5, bits<6> op6, bits<6> op7, bits<6> op8, bits<6> op9,
                              bits<6> op10, string asmstr>{
  def _rrr1              : IRRR1<prefix, op1, asmstr, DataRegs>;
  def _rrr1_e            : IRRR1<prefix, op2, asmstr, ExtRegs>;
  def _rrr1_L      : IRRR1_label<prefix, op3, asmstr, DataRegs, "L">;
  def _rrr1_e_L    : IRRR1_label<prefix, op4, asmstr, ExtRegs,  "L">;
  def _rrr1_U      : IRRR1_label<prefix, op5, asmstr, DataRegs, "U">;
  def _rrr1_e_U    : IRRR1_label<prefix, op6, asmstr, ExtRegs,  "U">;
  def _rrr1_L_L   : IRRR1_label2<prefix, op7, asmstr, DataRegs, "L", "L">;
  def _rrr1_e_L_L : IRRR1_label2<prefix, op8, asmstr, ExtRegs,  "L", "L">;
  def _rrr1_U_U   : IRRR1_label2<prefix, op9, asmstr, DataRegs, "U", "U">;
  def _rrr1_e_U_U : IRRR1_label2<prefix, op10, asmstr, ExtRegs,  "U", "U">;
}

defm MADD_Q  : mIRRR1_maddq_msubq<0x43, 0x02, 0x1B, 0x01, 0x19, 0x00, 0x18, 0x05, 0x1D, 0x04, 0x1C, "madd.q">;
defm MADDS_Q : mIRRR1_maddq_msubq<0x43, 0x22, 0x3B, 0x21, 0x39, 0x20, 0x38, 0x25, 0x3D, 0x24, 0x3C, "madds.q">;

def MADD_U_rcr : IRCR_EcEdDa<0x13, 0x02, "madd.u">; 
def MADD_U_rrr2 : IRRR2<0x03, 0x68, "madd.u", ExtRegs>;

defm MADDS_U : mIRCR<0x13, 0x04, 0x13, 0x06, "madds.u">
            , mIRRR2<0x03, 0x88, 0x03, 0xE8, "madds.u">;

defm MADDM_H  : mIRRR1_E_LU2<0x83, 0x1E, 0x1D, 0x1C, 0x1F, "maddm.h">;
defm MADDMS_H : mIRRR1_E_LU2<0x83, 0x3E, 0x3D, 0x3C, 0x3F, "maddms.h">;

defm MADDR_H  : mIRRR1_LU2<0x83, 0x0E, 0x0D, 0x0C, 0x0F, "maddr.h", DataRegs>;
defm MADDRS_H : mIRRR1_LU2<0x83, 0x2E, 0x2D, 0x2C, 0x2F, "maddrs.h", DataRegs>;

def MADDR_H_rrr1_DcEdDaDbUL
  : RRR1<0x43, 0x1E, (outs DataRegs:$d), (ins DataRegs:$s1, DataRegs:$s2, ExtRegs:$s3, u2imm:$n),
         "maddr.h $d, $s3, $s1, $s2, UL, $n", []>;
def MADDRS_H_rrr1_DcEdDaDbUL
  : RRR1<0x43, 0x3E, (outs DataRegs:$d), (ins DataRegs:$s1, DataRegs:$s2, ExtRegs:$s3, u2imm:$n),
         "maddrs.h $d, $s3, $s1, $s2, UL, $n", []>;

multiclass mIRRR1_label2_LL_UU<bits<8> prefix, bits<6> op1, bits<6> op2, string asmstr> {
  def _rrr1_L_L : IRRR1_label2<prefix, op1, asmstr, DataRegs, "L", "L">;
  def _rrr1_U_U : IRRR1_label2<prefix, op2, asmstr, DataRegs, "U", "U">;
}

defm MADDR_Q  : mIRRR1_label2_LL_UU<0x43, 0x07, 0x06, "maddr.q">;
defm MADDRS_Q : mIRRR1_label2_LL_UU<0x43, 0x27, 0x26, "maddrs.q">;

defm MADDSU_H   : mIRRR1_E_LU2<0xC3, 0x1A, 0x19, 0x18, 0x1B, "maddsu.h">;
defm MADDSUS_H  : mIRRR1_E_LU2<0xC3, 0x3A, 0x39, 0x38, 0x3B, "maddsus.h">;
defm MADDSUM_H  : mIRRR1_E_LU2<0xC3, 0x1E, 0x1D, 0x1C, 0x1F, "maddsum.h">;
defm MADDSUMS_H : mIRRR1_E_LU2<0xC3, 0x3E, 0x3D, 0x3C, 0x3F, "maddsums.h">;
defm MADDSUR_H    : mIRRR1_LU2<0xC3, 0x0E, 0x0D, 0x0C, 0x0F, "maddsur.h", DataRegs>;
defm MADDSURS_H   : mIRRR1_LU2<0xC3, 0x2E, 0x2D, 0x2C, 0x2F, "maddsurs.h", DataRegs>;

defm MAX   : mIRR_RC<0x0B, 0x1A, 0x8B, 0x1A, "max">;
defm MAX_U : mIRR_RC<0x0B, 0x1B, 0x8B, 0x1B, "max.u">;

defm MAX_B : mIU__RR_ab<0x0B, 0x5A, 0x0B, 0x5B, "max.b">;
defm MAX_H : mIU__RR_ab<0x0B, 0x7A, 0x0B, 0x7B, "max.h">;

defm MIN   : mIRR_RC<0x0B, 0x18, 0x8B, 0x18, "min">;
defm MIN_U : mIRR_RC<0x0B, 0x19, 0x8B, 0x19, "min.u">;

defm MIN_B : mIU__RR_ab<0x0B, 0x58, 0x0B, 0x59, "min.b">;
defm MIN_H : mIU__RR_ab<0x0B, 0x78, 0x0B, 0x79, "min.h">;

class IRLC_1<bits<8> op1, string asmstr, RegisterClass rc>
    : RLC<op1, (outs rc:$d), (ins u16imm:$const16),
      asmstr # " $d, $const16", []>;

class ISRC_1<bits<8> op1, string asmstr, RegisterClass rc> 
    : SRC<op1, (outs rc:$d), (ins s4imm:$const4),
      asmstr # " $d, $const4", []>;

def MOV_rlcDc       : IRLC_1<0x3B, "mov", DataRegs>;
def MOV_rlcEc       : IRLC_1<0xFB, "mov", ExtRegs>;
def MOV_rrDcDb     : IRR_DcDb<0x0B, 0x1F, "mov">;
def MOV_rrEcDb        : IRR_b<0x0B, 0x80, "mov", ExtRegs, DataRegs>;
def MOV_rrEcDaDb : IRR_EcDaDb<0x0B, 0x81, "mov">;
def MOV_sc              : ISC_D15<0xDA, "mov">;
def MOV_srcDa          : ISRC<0x82, "mov">;
def MOV_srcEa       : ISRC_1<0xD2, "mov", ExtRegs>;
def MOV_srr            : ISRR<0x02, "mov">;

multiclass mIRR_SRCz_SRR__A<bits<8> rr1, bits<8> rr2, bits<8> src1, bits<8> srr1,
                        string asmstr> {
  def _rr : IRR_2<rr1, rr2, asmstr, AddrRegs, AddrRegs, AddrRegs>;
  def _src : ISRC_AaZ<src1, asmstr>;
  def _srr : ISRR_AaDb<srr1, asmstr>;
}

defm MOV_A : mIRR_SRCz_SRR__A<0x01, 0x63, 0xA0, 0x60, "mov.a">;

def MOV_AA_rr : IRR_b<0x01, 0x00, "mov.aa", AddrRegs, AddrRegs>;
def MOV_AA_srr : ISRR_AaAb<0x40, "mov.aa">;

def MOV_D_rr : IRR_b<0x01, 0x4C, "mov.d", DataRegs, AddrRegs>;
def MOV_D_srr : ISRR_2<0x80, "mov.d", DataRegs, AddrRegs>;

def MOV_U_rlc  : IRLC_1<0xBB, "mov.u", DataRegs>;
def MOVH_rlc   : IRLC_1<0x7B, "movh", DataRegs>;
def MOVH_A_rlc : IRLC_1<0x91, "movh.a", AddrRegs>;

defm MSUB : mIRCR<0x33, 0x01, 0x33, 0x03, "msub">
          , mIRRR2<0x23, 0x0A, 0x23, 0x6A, "msub">;
defm MSUBS : mIRCR<0x33, 0x05, 0x33, 0x07, "msubs">
          , mIRRR2<0x23, 0x8A, 0x23, 0xEA, "msubs">;
defm MSUB_H  : mIRRR1_E_LU2<0xA3, 0x1A, 0x19, 0x18, 0x1B, "msub.h">;
defm MSUBS_H : mIRRR1_E_LU2<0xA3, 0x3A, 0x39, 0x38, 0x3B, "msubs.h">;
defm MSUB_Q  : mIRRR1_maddq_msubq<0x63, 0x02, 0x1B, 0x01, 0x19, 0x00, 0x18, 0x05, 0x1D, 0x04, 0x1C, "msub.q">;
defm MSUBS_Q : mIRRR1_maddq_msubq<0x63, 0x22, 0x3B, 0x21, 0x39, 0x20, 0x38, 0x25, 0x3D, 0x24, 0x3C, "msubs.q">;

def MSUB_U_rcr : IRCR_EcEdDa<0x33, 0x02, "madd.u">; 
def MSUB_U_rrr2 : IRRR2<0x23, 0x68, "madd.u", ExtRegs>;
defm MSUBS_U : mIRCR<0x33, 0x04, 0x33, 0x06, "madds.u">
            , mIRRR2<0x23, 0x88, 0x23, 0xE8, "madds.u">;

defm MSUBAD_H   : mIRRR1_E_LU2<0xE3, 0x1A, 0x19, 0x18, 0x1B, "msubad.h">;
defm MSUBADS_H  : mIRRR1_E_LU2<0xE3, 0x3A, 0x39, 0x38, 0x3B, "msubads.h">;
defm MSUBADM_H  : mIRRR1_E_LU2<0xE3, 0x1E, 0x1D, 0x1C, 0x1F, "msubadm.h">;
defm MSUBADMS_H : mIRRR1_E_LU2<0xE3, 0x3E, 0x3D, 0x3C, 0x3F, "msubadms.h">;
defm MSUBADR_H    : mIRRR1_LU2<0xE3, 0x0E, 0x0D, 0x0C, 0x0F, "msubadr.h", DataRegs>;
defm MSUBADRS_H   : mIRRR1_LU2<0xE3, 0x2E, 0x2D, 0x2C, 0x2F, "msubadrs.h", DataRegs>;
defm MSUBM_H    : mIRRR1_E_LU2<0xA3, 0x1E, 0x1D, 0x1C, 0x1F, "msubm.h">;
defm MSUBMS_H   : mIRRR1_E_LU2<0xA3, 0x3E, 0x3D, 0x3C, 0x3F, "msubms.h">;
defm MSUBR_H      : mIRRR1_LU2<0xA3, 0x0E, 0x0D, 0x0C, 0x0F, "msubr.h", DataRegs>;
defm MSUBRS_H     : mIRRR1_LU2<0xA3, 0x2E, 0x2D, 0x2C, 0x2F, "msubrs.h", DataRegs>;

def MSUBR_H_rrr1_DcEdDaDbUL
  : RRR1<0x63, 0x1E, (outs DataRegs:$d), (ins DataRegs:$s1, DataRegs:$s2, ExtRegs:$s3, u2imm:$n),
         "msubr.h $d, $s3, $s1, $s2, UL, $n", []>;
def MSUBRS_H_rrr1_DcEdDaDbUL
  : RRR1<0x63, 0x3E, (outs DataRegs:$d), (ins DataRegs:$s1, DataRegs:$s2, ExtRegs:$s3, u2imm:$n),
         "msubrs.h $d, $s3, $s1, $s2, UL, $n", []>;

defm MSUBR_Q  : mIRRR1_label2_LL_UU<0x63, 0x07, 0x06, "msubr.q">;
defm MSUBRS_Q : mIRRR1_label2_LL_UU<0x63, 0x27, 0x26, "msubrs.q">;

class IRLC_CR<bits<8> op1, string asmstr, RegisterClass rc>
    : RLC<op1, (outs), (ins s16imm:$const16, rc:$d),
      asmstr # " $const16, $d", []>;

def MTCR_rlc : IRLC_CR<0xCD, "mtcr", DataRegs>;
def MFCR_rlc : IRLC_1 <0x4D, "mfcr", DataRegs>;

class IRR2<bits<8> op1, bits<12> op2, string asmstr, RegisterClass rcd, RegisterClass rca, RegisterClass rcb>
    : RR2<op1, op2, (outs rcd:$d), (ins rca:$s1, rcb:$s2), asmstr # " $d, $s1, $s2", []>;

class IRR2_RcDaDb<bits<8> op1, bits<12> op2, string asmstr, RegisterClass rcd>
    : IRR2<op1, op2, asmstr, rcd, DataRegs, DataRegs>;

def MUL_rc  : RC<0x53, 0x01, (outs DataRegs:$d), (ins DataRegs:$s1, s9imm:$const9),
                "mul $d, $s1, $const9", []>;
def MUL_rc_e : RC<0x53, 0x03, (outs ExtRegs:$d), (ins DataRegs:$s1, s9imm:$const9),
                "mul $d, $s1, $const9", []>;
def MUL_rr2 : IRR2_RcDaDb<0x73, 0x0A, "mul", DataRegs>;
def MUL_rr2_e : IRR2_RcDaDb<0x73, 0x6A, "mul", ExtRegs>;
def MUL_srr : ISRR<0xE2, "mul">;

multiclass mIRC_RR2_RcDaDb<bits<8> rc1, bits<7> rc2, bits<8> op1, bits<12> op2, string asmstr, RegisterClass rcd>{
  def _rc  : IRC_R<rc1, rc2, asmstr, rcd>;
  def _rr2 : IRR2_RcDaDb<op1, op2, asmstr, rcd>;
}

defm MULS : mIRC_RR2_RcDaDb<0x53, 0x05, 0x73, 0x8A, "muls", DataRegs>;

class IRR1<bits<8> op1, bits<10> op2, string asmstr,
           RegisterClass rcd, string labela, string labelb>
    : RR1<op1, op2, (outs rcd:$d), (ins DataRegs:$s1, DataRegs:$s2, u2imm:$n),
          asmstr # " $d, ${s1}" # labela # ", ${s2}" # labelb # ", $n", []>;

multiclass mIRR1_LU2e<bits<8> op1, bits<10> op2, bits<10> op3, bits<10> op4, bits<10> op5, string asmstr>{
  def _rr1_LL2e : IRR1<op1, op2, asmstr, ExtRegs, "", "LL">;
  def _rr1_LU2e : IRR1<op1, op3, asmstr, ExtRegs, "", "LU">;
  def _rr1_UL2e : IRR1<op1, op4, asmstr, ExtRegs, "", "UL">;
  def _rr1_UU2e : IRR1<op1, op5, asmstr, ExtRegs, "", "UU">;
}

defm MUL_H : mIRR1_LU2e<0xB3, 0x1A, 0x19, 0x18, 0x1B, "mul.h">;

multiclass mIRR1_mulq<bits<8> op, bits<10> op1, bits<10> op2, bits<10> op3, bits<10> op4,
                      bits<10> op5, bits<10> op6, bits<10> op7, bits<10> op8, string asmstr>{
  def _rr1_2__  : IRR1<op, op1, asmstr, DataRegs, "", "">;
  def _rr1_2__e : IRR1<op, op2, asmstr, ExtRegs, "", "">;

  def _rr1_2_L  : IRR1<op, op3, asmstr, DataRegs, "", "L">;
  def _rr1_2_Le : IRR1<op, op4, asmstr, ExtRegs, "", "L">;
  def _rr1_2_U  : IRR1<op, op5, asmstr, DataRegs, "", "U">;
  def _rr1_2_Ue : IRR1<op, op6, asmstr, ExtRegs, "", "U">;

  def _rr1_2LL : IRR1<op, op7, asmstr, DataRegs, "L", "L">;
  def _rr1_2UU : IRR1<op, op8, asmstr, DataRegs, "U", "U">;
}

defm MUL_Q : mIRR1_mulq<0x93, 0x02, 0x1B, 0x01, 0x19, 0x00, 0x18, 0x05, 0x04, "mul.q">;

defm MUL_U : mIRC_RR2_RcDaDb<0x53, 0x02, 0x73, 0x68, "mul.u", ExtRegs>;
defm MULS_U : mIRC_RR2_RcDaDb<0x53, 0x04, 0x73, 0x88, "muls.u", ExtRegs>;

defm MULM_H : mIRR1_LU2e<0xB3, 0x1E, 0x1D, 0x1C, 0x1F, "mulm.h">;
defm MULR_H : mIRR1_LU2e<0xB3, 0x0E, 0x0D, 0x0C, 0x0F, "mulr.h">;

def MULR_Q_rr1_2LL : IRR1<0x93, 0x07, "mulr.q", DataRegs, "L", "L">;
def MULR_Q_rr1_2UU : IRR1<0x93, 0x06, "mulr.q", DataRegs, "U", "U">;

defm NAND : mIRR_RC<0x0F, 0x09, 0x8F, 0x09, "nand">;
def NAND_T : IBIT<0x07, 0x00, "nand.t">;

defm NE : mIRR_RC<0x0B, 0x11, 0x8B, 0x11, "ne">;
def NE_A : IRR_DcAaAb<0x01, 0x41, "ne.a">;
def NEZ_A : IRR_DcAa<0x01, 0x49, "nez.a">;

def NOP_sr : ISR_0<0x00, 0x00, "nop">;
def NOP_sys : ISYS_0<0x00, 0x0D, "nop">;

defm NOR : mIRR_RC<0x0F, 0x0B, 0x8F, 0x0B, "nor">;
def NOR_T : IBIT<0x87, 0x02, "nor.t">;

def NOT_sr : ISR_1<0x46, 0x00, "not">;

defm OR : mIRR_RC<0x0F, 0x0A, 0x8F, 0x0A, "or">;
def OR_sc : ISC_D15<0x96, "or">;
def OR_srr : ISRR<0xA6, "or">;

def OR_AND_T  : IBIT<0xC7, 0x00, "or.and.t">;
def OR_ANDN_T : IBIT<0xC7, 0x03, "or.andn.t">;
def OR_NOR_T  : IBIT<0xC7, 0x02, "or.nor.t">;
def OR_OR_T   : IBIT<0xC7, 0x01, "or.or.t">;

defm OR_EQ   : mIRR_RC<0x0B, 0x27, 0x8B, 0x27, "or.eq">;
defm OR_GE   : mIRR_RC<0x0B, 0x2B, 0x8B, 0x2B, "or.ge">;
defm OR_GE_U : mIRR_RC<0x0B, 0x2C, 0x8B, 0x2C, "or.ge.u">;
defm OR_LT   : mIRR_RC<0x0B, 0x29, 0x8B, 0x29, "or.lt">;
defm OR_LT_U : mIRR_RC<0x0B, 0x2A, 0x8B, 0x2A, "or.lt.u">;
defm OR_NE   : mIRR_RC<0x0B, 0x28, 0x8B, 0x28, "or.ne">;

def OR_T : IBIT<0x87, 0x01, "or.t">;

defm ORN : mIRR_RC<0x0F, 0x0F, 0x8F, 0x0F, "orn">;

def ORN_T : IBIT<0x07, 0x01, "orn.t">;

def PACK_rrr : IRRR_DcEdDa<0x6B, 0x00, "pack">;

def PARITY_rr : IRR_DcDa<0x4B, 0x02, "parity">;

def POPCNT_W_rr : IRR_DcDa<0x4B, 0x22, "popcnt.w">;

def RESTORE_sys : ISYS_0<0x0D, 0x0E, "restore">;

def RET_sr : ISR_0<0x00, 0x09, "ret">;
def RET_sys : ISYS_0<0x0D, 0x06, "ret">;

def RFE_sr : ISR_0<0x00, 0x08, "rfe">;
def RFE_sys : ISYS_0<0x0D, 0x07, "rfe">;

def RFM_sys : ISYS_0<0x0D, 0x05, "rfm">;

def RSLCX_sys : ISYS_0<0x0D, 0x09, "relck">;

def RSTV_sys : ISYS_0<0x2F, 0x00, "restore">;

def RSUB_rc : IRC_2<0x8B, 0x08, "rsub">;
def RSUB_sr : ISR_1<0x32, 0x05, "rsub">;

def RSUBS_rc   : IRC_2<0x8B, 0x0A, "rsubs">;
def RSUBS_U_rc : IRC_2<0x8B, 0x0B, "rsubs.u">;

multiclass mIRR_SR<bits<8> r1, bits<8> r2, bits<8> s1, bits<4> s2, string asmstr>{
  def _rr : IRR_DcDa<r1, r2, asmstr>;
  def _sr : ISR_1<s1, s2, asmstr>;
}

defm SAT_B  : mIRR_SR<0x0B, 0x5E, 0x32, 0x00, "sat.b">;
defm SAT_BU : mIRR_SR<0x0B, 0x5F, 0x32, 0x01, "sat.bu">;
defm SAT_H  : mIRR_SR<0x0B, 0x7E, 0x32, 0x02, "sat.h">;
defm SAT_HU : mIRR_SR<0x0B, 0x7F, 0x32, 0x03, "sat.hu">;

def SEL_rcr : IRCR_DcDdDa<0xAB, 0x04, "sel">;
def SEL_rrr : IRRR_DcDdDaDb<0x2B, 0x04, "sel">;

def SELN_rcr : IRCR_DcDdDa<0xAB, 0x05, "seln">;
def SELN_rrr : IRRR_DcDdDaDb<0x2B, 0x05, "seln">;

def SH_src : ISRC_1<0x06, "sh", DataRegs>;
defm SH : mIRR_RC<0x0F, 0x00, 0x8F, 0x00, "sh">;
defm SH_H : mIRR_RC<0x0F, 0x40, 0x8F, 0x40, "sh.h">;

defm SH_EQ : mIRR_RC<0x0B, 0x37, 0x8B, 0x37, "sh.eq">;
defm SH_NE : mIRR_RC<0x0B, 0x38, 0x8B, 0x38, "sh.lt">;
defm SH_GE : mIRR_RC<0x0B, 0x3B, 0x8B, 0x3B, "sh.ge">;
defm SH_GE_U : mIRR_RC<0x0B, 0x3C, 0x8B, 0x3C, "sh.ge.u">;
defm SH_LT : mIRR_RC<0x0B, 0x39, 0x8B, 0x39, "sh.lt">;
defm SH_LT_U : mIRR_RC<0x0B, 0x3A, 0x8B, 0x3A, "sh.lt.u">;

def SH_AND_T  : IBIT<0x27, 0x00, "sh.and.t">;
def SH_ANDN_T : IBIT<0x27, 0x03, "sh.andn.t">;
def SH_NAND_T : IBIT<0xA7, 0x00, "sh.nand.t">;
def SH_NOR_T  : IBIT<0x27, 0x02, "sh.nor.t">;
def SH_OR_T   : IBIT<0x27, 0x01, "sh.or.t">;
def SH_ORN_T  : IBIT<0xA7, 0x01, "sh.orn.t">;
def SH_XNOR_T : IBIT<0xA7, 0x02, "sh.xnor.t">;
def SH_XOR_T  : IBIT<0xA7, 0x03, "sh.xor.t">;


def SHA_src : ISRC_1<0x86, "sha", DataRegs>;
defm SHA : mIRR_RC<0x0F, 0x01, 0x8F, 0x01, "sha">;
defm SHA_H : mIRR_RC<0x0F, 0x41, 0x8F, 0x41, "sha.h">;
defm SHAS : mIRR_RC<0x0F, 0x02, 0x8F, 0x02, "shas">;

def SHUFFLE_rc : IRC_2<0x8F, 0x07, "shuffle">;

// A[b], off10, A[a] (BO)(Base + Short Offset Addressing Mode)
class IBO_bso_st<bits<8> op1, bits<6> op2, string asmstr, RegisterClass rc> 
    : BO<op1, op2, (outs rc:$d), (ins AddrRegs:$s1, s10imm:$off10),
      asmstr # " [$s1]$off10, $d", []>;
// P[b], A[a] (BO)(Bit-reverse Addressing Mode)
class IBO_r_st<bits<8> op1, bits<6> op2, string asmstr, RegisterClass rc>
    : BO<op1, op2, (outs AddrExtRegs:$d), (ins rc:$s1),
      asmstr # " $d, [${s1}+r]", []>;
// P[b], off10, A[a] (BO)(Circular Addressing Mode)
class IBO_c_st<bits<8> op1, bits<6> op2, string asmstr, RegisterClass rc> 
    : BO<op1, op2, (outs AddrExtRegs:$d), (ins rc:$s1, s10imm:$off10),
      asmstr # " $d, [${s1}+c]$off10", []>;
// A[b], off10, A[a] (BO)(Post-increment Addressing Mode)
class IBO_pos_st<bits<8> op1, bits<6> op2, string asmstr, RegisterClass rc>
    : BO<op1, op2, (outs), (ins rc:$s1, AddrRegs:$s2, s10imm:$off10),
      asmstr # " $s2, [${s1}+]$off10", []>;
// A[b], off10, A[a] (BO)(Pre-increment Addressing Mode)
class IBO_pre_st<bits<8> op1, bits<6> op2, string asmstr, RegisterClass rc>
    : BO<op1, op2, (outs), (ins rc:$s1, AddrRegs:$s2, s10imm:$off10),
      asmstr # " $s2, [+${s1}]$off10", []>;


multiclass mIBO_st<bits<8> prefix1, bits<8> prefix2,
                       bits<6> bso2, ///_bso
                       bits<6> pos_r, ///_pos|_r
                       bits<6> pre_c, ///_pre|_c
                       string asmstr, RegisterClass rc>{
  def _bo_bso  : IBO_bso_st<prefix1, bso2, asmstr, rc>;
  def _bo_pos  : IBO_pos_st<prefix1, pos_r, asmstr, rc>;
  def _bo_pre  : IBO_pre_st<prefix1, pre_c, asmstr, rc>;
  def _bo_r    : IBO_r_st<prefix2, pos_r, asmstr, rc>;
  def _bo_c    : IBO_c_st<prefix2, pre_c, asmstr, rc>;
}

multiclass mIABS_BO_st<bits<8> abs1, bits<2> abs2,   ///_abs
                    bits<8> prefix1, bits<8> prefix2,
                    bits<6> bso2, ///_bso
                    bits<6> pos_r, ///_pos|_r
                    bits<6> pre_c, ///_pre|_c
                    string asmstr, RegisterClass rc>
          : mIBO_st<prefix1, prefix2, bso2, pos_r, pre_c, asmstr, rc>{
  def _abs : IABS_OR<abs1, abs2, asmstr, rc>;
}

defm ST_A  : mIABS_BO_st<0xA5, 0x02, 0x89, 0xA9, 0x26, 0x06, 0x16, "st.a", AddrRegs>;
defm ST_B  : mIABS_BO_st<0x25, 0x00, 0x89, 0xA9, 0x20, 0x00, 0x10, "st.b", DataRegs>;
defm ST_D  : mIABS_BO_st<0xA5, 0x01, 0x89, 0xA9, 0x25, 0x05, 0x15, "st.d", ExtRegs>;
defm ST_DA : mIABS_BO_st<0xA5, 0x03, 0x89, 0xA9, 0x27, 0x07, 0x17, "st.da", AddrExtRegs>;
defm ST_H  : mIABS_BO_st<0x25, 0x02, 0x89, 0xA9, 0x22, 0x02, 0x12, "st.h", DataRegs>;
defm ST_Q  : mIABS_BO_st<0x65, 0x00, 0x89, 0xA9, 0x28, 0x08, 0x18, "st.q", DataRegs>;

multiclass mISRO_SSR_SSRO_st<bits<8> sro, bits<8> ssr, bits<8> ssrpos, bits<8> ssro,
                            string asmstr, RegisterClass rc>{
  def _sro     : ISRO_A15ROst<sro, asmstr, rc>;
  def _ssr     : SSR<ssr, (outs AddrRegs:$d), (ins rc:$s1),
                     asmstr # " [$d], $s1", []>;
  def _ssr_pos : SSR<ssrpos, (outs AddrRegs:$d), (ins rc:$s1),
                     asmstr # " [$d+], $s1", []>;
  def _ssro    : SSRO<ssro, (outs), (ins rc:$s1, s4imm:$off4),
                      asmstr # " %a15, $off4, $s1", []>;
}

multiclass mISRO_SSR_SSRO_stD<bits<8> sro, bits<8> ssr, bits<8> ssrpos, bits<8> ssro,
                            string asmstr, RegisterClass rc>{
  def _sro     : ISRO_D15ROst<sro, asmstr, AddrRegs>;
  def _ssr     : SSR<ssr, (outs AddrRegs:$d), (ins rc:$s1),
                     asmstr # " [$d], $s1", []>;
  def _ssr_pos : SSR<ssrpos, (outs AddrRegs:$d), (ins rc:$s1),
                     asmstr # " [$d+], $s1", []>;
  def _ssro    : SSRO<ssro, (outs), (ins rc:$s1, s4imm:$off4),
                      asmstr # " %a15, $off4, $s1", []>;
}

def ST_A_bol : IBOL_AbOR<0xB5, "st.a", AddrRegs>;
def ST_A_sc : ISC_A10CA15<0xF8, "st.a">;
defm ST_A : mISRO_SSR_SSRO_st<0xEC, 0xF4, 0xE4, 0xE8, "st.a", AddrRegs>;

def ST_B_bol : IBOL_AbOR<0xE9, "st.b", DataRegs>;
defm ST_B : mISRO_SSR_SSRO_stD<0x2C, 0x34, 0x24, 0x28, "st.b", DataRegs>;

def ST_H_bol : IBOL_AbOR<0xF9, "st.h", DataRegs>;
defm ST_H : mISRO_SSR_SSRO_stD<0xAC, 0xB4, 0xA4, 0xA8, "st.h", DataRegs>;

def ST_T : ABSB<0xD5, 0x00, (outs), (ins i32imm:$off18, i32imm:$bpos3, i32imm:$b),
                "st.t $off18, $bpos3, $b", []>;

defm ST_W : mIABS_BO_st<0xA5, 0x00, 0x89, 0xA9, 0x24, 0x04, 0x14, "st.w", DataRegs>;
def ST_W_bol : IBOL_AbOR<0x59, "st.w", DataRegs>;
defm ST_W : mISRO_SSR_SSRO_stD<0x6C, 0x74, 0x64, 0x68, "st.w", AddrRegs>;

def STLCX_abs : IABS_off18<0x15, 0x00, "stlcx">; 
def STLCX_bo_bso : IBO_bso<0x49, 0x26, "stlcx">; 

def STUCX_abs : IABS_off18<0x15, 0x01, "stucx">; 
def STUCX_bo_bso : IBO_bso<0x49, 0x27, "stucx">; 

def SUB_rr : IRR_DcDaDb<0x0B, 0x08, "sub">;
defm SUB : mISRR_a15a<0xA2, 0x52, 0x5A, "sub">
         , mIB_H<0x0B, 0x48, 0x0B, 0x68, "sub">;

def SUB_A_rr : IRR_2<0x01, 0x02, "sub.a", AddrRegs, AddrRegs, AddrRegs>;
def SUB_A_sc : ISC_A10<0x20, "sub.a">;

def SUBC_rr : IRR2_RcDaDb<0x0B, 0x0D, "subc", DataRegs>;

def SUBS_rr : IRR2_RcDaDb<0x0B, 0x0A, "subs", DataRegs>;
def SUBS_srr : ISRR<0x62, "subs">;

def SUBS_U_rr : IRR2_RcDaDb<0x0B, 0x0B, "subs.u", DataRegs>;
def SUBS_H_rr : IRR2_RcDaDb<0x0B, 0x6A, "subs.h", DataRegs>;
def SUBS_HU_rr : IRR2_RcDaDb<0x0B, 0x6B, "subs.hu", DataRegs>;
def SUBX_rr : IRR2_RcDaDb<0x0B, 0x0C, "subx", DataRegs>;

def SVLCX_sys : ISYS_0<0x0D, 0x08, "svlcx">;

defm SWAP_W    : mIABS_BO_st<0xE5, 0x00, 0x49, 0x69, 0x20, 0x00, 0x10, "swap.w", DataRegs>;
defm SWAPMSK_W : mIBO_st<0x49, 0x69, 0x22, 0x02, 0x12, "swapmsk.w", ExtRegs>;

def SYSCALL_rc : IRC<0xAD, 0x04, "syscall">;

def TRAPSV_sys : ISYS_0<0x0D, 0x15, "trapsv">;
def TRAPV_sys  : ISYS_0<0x0D, 0x14, "trapv">;

def UNPACK_rr : IRR_EcDa<0x4B, 0x08, "unpack">;

def WAIT_sys  : ISYS_0<0x0D, 0x16, "wait">;

defm XNOR : mIRR_RC<0x0F, 0x0D, 0x8F, 0x0D, "xnor">;
def XNOR_T : IBIT<0x07, 0x02, "xnor.t">;

defm XOR : mIRR_RC<0x0F, 0x0C, 0x8F, 0x0C, "xor">;
def XOR_srr : ISRR<0xC6, "xor">;
def XOR_T : IBIT<0x07, 0x03, "xor.t">;

defm XOR_EQ   : mIRR_RC<0x0B, 0x2F, 0x8B, 0x2F, "xor.eq">;
defm XOR_NE   : mIRR_RC<0x0B, 0x30, 0x8B, 0x30, "xor.ne">;
defm XOR_GE   : mIRR_RC<0x0B, 0x33, 0x8B, 0x33, "xor.ge">;
defm XOR_GE_U : mIRR_RC<0x0B, 0x34, 0x8B, 0x34, "xor.ge.u">;
defm XOR_LT   : mIRR_RC<0x0B, 0x31, 0x8B, 0x31, "xor.lt">;
defm XOR_LT_U : mIRR_RC<0x0B, 0x32, 0x8B, 0x32, "xor.lt.u">;



/// FPU Instructions

def MADD_F_rrr : IRRR_DcDdDaDb<0x6B, 0x06, "madd.f">;
def MSUB_F_rrr : IRRR_DcDdDaDb<0x6B, 0x07, "msub.f">;
def ADD_F_rrr : IRRR_DcDdDa<0x6B, 0x02, "add.f">;
def SUB_F_rrr : IRRR_DcDdDa<0x6B, 0x03, "sub.f">;
def MUL_F_rrr : IRR_DcDaDb<0x4B, 0x04, "mul.f">;
def DIV_F_rr  : IRR_DcDaDb<0x4B, 0x05, "div.f">;

def CMP_F_rr  : IRR_DcDaDb<0x4B, 0x00, "cmp.f">;
def FTOI_rr   : IRR_DcDa<0x4B, 0x10, "ftoi">;
def FTOIZ_rr  : IRR_DcDa<0x4B, 0x13, "ftoiz">;
def FTOQ31_rr : IRR_DcDaDb<0x4B, 0x11, "ftoq31">;
def FTOQ31Z_rr: IRR_DcDaDb<0x4B, 0x18, "ftoq31z">;
def FTOU_rr   : IRR_DcDa<0x4B, 0x12, "ftou">;
def FTOUZ_rr  : IRR_DcDa<0x4B, 0x17, "ftouz">;
def FTOHP_rr  : IRR_DcDa<0x4B, 0x25, "ftohp">;
def HPTOF_rr  : IRR_DcDa<0x4B, 0x24, "hptof">;
def ITOF_rr   : IRR_DcDa<0x4B, 0x14, "itof">;

def Q31TOF_rr  : IRR_DcDaDb<0x4B, 0x15, "q31tof">;
def QSEED_F_rr : IRR_DcDa<0x4B, 0x19, "qseed.f">;

def UPDFL_rr   : IRR_Ra<0x4B, 0x0C, "updfl", DataRegs>;
def UTOF_rr    : IRR_DcDa<0x4B, 0x16, "utof">;

// let Defs = [PSW], Uses = [PSW] in {
// def SUBCrr : RR<0x0B, 0x0D, (outs DataRegs:$d),
//   (ins DataRegs:$s1, DataRegs:$s2),
//   "subc $d, $s1, $s2",
//   [(set DataRegs:$d, (subc DataRegs:$s1, DataRegs:$s2)),
//   (implicit PSW)]>;

// def SUBXrr : RR<0x0B, 0x0C, (outs DataRegs:$d),
//   (ins DataRegs:$s1, DataRegs:$s2),
//   "subx $d, $s1, $s2",
//   [(set DataRegs:$d, (sube DataRegs:$s1, DataRegs:$s2)),
//   (implicit PSW)]>;

// } // let Defs = [PSW], Uses = [PSW]

def imml_32_h_32 : Operand<i64>, PatLeaf<(imm), [{

 int64_t val = N->getSExtValue();
 int32_t lByte = val & 0xffffffff;
 int32_t hByte = (val >> 32) & 0xffffffff;

 return (lByte >=-256 && lByte < 256 && hByte >=-256 && hByte < 256);

}]>;

// let Defs = [PSW] in {
// def ADDi64C : Pseudo<(outs ExtRegs:$d),
//            (ins ExtRegs:$s1, imml_32_h_32:$const64),
//            "ADDi64C Pseudo",
//            [(set ExtRegs:$d, (add ExtRegs:$s1, imml_32_h_32:$const64)),
//           (implicit PSW)]>;

// def ADDi64 : Pseudo<(outs ExtRegs:$d),
//            (ins ExtRegs:$s1, ExtRegs:$s2),
//            "ADDi64 Pseudo",
//            [(set ExtRegs:$d, (add ExtRegs:$s1, ExtRegs:$s2)),
//           (implicit PSW)]>;

// def SUBi64 : Pseudo<(outs ExtRegs:$d),
//            (ins ExtRegs:$s1, ExtRegs:$s2),
//            "SUBi64 Pseudo",
//            [(set ExtRegs:$d, (sub ExtRegs:$s1, ExtRegs:$s2)),
//           (implicit PSW)]>;

// } //let Defs = [PSW]

// let Defs = [A10], Uses = [A10] in
// def SUB_Asc : SC<0x20, (outs), (ins u8imm:$const8), "sub.a %sp, $const8",
//   [(set A10, (sub A10, immZExt8:$const8) )]>;

// def SUB_Arr : RR<0x01, 0x02, (outs AddrRegs:$d),
//   (ins AddrRegs:$s1, AddrRegs:$s2), "sub.a $d, $s1, $s2",
//   [(set AddrRegs:$d, (sub AddrRegs:$s1, AddrRegs:$s2) )]>;

// def RSUBrc : RC<0x8B, 0x08, (outs DataRegs:$d),
//   (ins DataRegs:$s1, s9imm:$const9) ,"rsub $d, $s1, $const9",
//   [(set DataRegs:$d, (sub immSExt9:$const9, DataRegs:$s1)) ]>;

// let Constraints="$d = $s1" in
//   def RSUBsr : SR<0x32, 0x05, (outs DataRegs:$d), (ins DataRegs:$s1),
//   "rsub $d", [(set DataRegs:$d, (sub (i32 0), DataRegs:$s1)) ]>;

// let Defs=[PSW] in {

//  let Constraints="$d = $fksrc" in
//  def MULsrr : SRR<0xE2, (outs DataRegs:$d),
//     (ins DataRegs:$fksrc, DataRegs:$s2), "mul $d, $s2",
//     [(set DataRegs:$d, (mul DataRegs:$fksrc, DataRegs:$s2) )]>;

//  def MULrr2 : RR2<0x73, 0x00A, (outs DataRegs:$d),
//    (ins DataRegs:$s1, DataRegs:$s2), "mul $d, $s1, $s2",
//    [(set DataRegs:$d, (mul DataRegs:$s1, DataRegs:$s2) )]>;

//  def MULrc : RC<0x53, 0x001, (outs DataRegs:$d),
//    (ins DataRegs:$s1, s9imm:$const9),  "mul $d, $s1, $const9",
//    [(set DataRegs:$d, (mul DataRegs:$s1, immSExt9:$const9) )]>;
// }

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

// defm AND : Logical64_Pseudo<and>;
// defm OR  : Logical64_Pseudo<or>;
// defm XOR : Logical64_Pseudo<xor>;

// defm AND : Logical16<0x16, 0x26, "and", and>;
// defm AND : Logical32_0<0x08, "and", and>;

// defm NAND : Logical32_1<0x09, "nand", and, not>;
// defm NOR  : Logical32_1<0x0B, "nor", or, not>;
// defm XNOR : Logical32_1<0x0B, "nxor", xor, not>;

// defm OR : Logical32_0<0x0a, "or", or>;
// defm OR : Logical16<0x96, 0xA6, "or", or>;

// defm XOR : Logical32_0<0x0c, "xor", xor>;

// let Constraints = "$s1 = $d", isCommutable = 1 in
//   def XORsrr : SRR<0xc6, (outs DataRegs:$d),
//   (ins DataRegs:$s1, DataRegs:$s2), "xor $d, $s2",
//   [(set DataRegs:$d, (xor DataRegs:$s1, DataRegs:$s2))]>;

def imm_from_0_to_neg512 : Operand<i32>, PatLeaf<(imm), [{
 int64_t val = N->getSExtValue();
 return (val >=-512 && val <= 0);
}]>;

class LOGICALN_RC <bits<7> op2, string asmstring, SDNode OpNode>
 : RC<0x8f, op2, (outs DataRegs:$d),
    (ins DataRegs:$s1, imm_from_0_to_neg512:$const9),
  !strconcat(asmstring," $d, $s1, $const9"),
  [(set i32:$d, (OpNode i32:$s1, imm_from_0_to_neg512:$const9 ))]>;

// // def ANDNrc : LOGICALN_RC<0x0e, "andn", and>;
// def ORNrc  : LOGICALN_RC<0x0f, "orn", or>;
// def XNORrc : LOGICALN_RC<0x0d, "xnor", xor>;

// let Constraints = "$s1 = $d" in {
// def NOTsr : SR<0x46, 0x0, (outs DataRegs: $d), (ins DataRegs:$s1),
//       "not $d", [(set DataRegs:$d, (not DataRegs:$s1))]>;

// def NOTrr64: Pseudo<(outs ExtRegs:$d), (ins ExtRegs:$s1),
//   "##NAME## Pseudo", [(set ExtRegs:$d, (not ExtRegs:$s1))]>;
// } // let Constraints = "$s1 = $d" in

// def ANDNrc64: Pseudo<(outs ExtRegs:$d),
//   (ins ExtRegs:$s1, imml_neg_32_h_32_const64:$const64),
//   "##NAME## Pseudo",
//   [(set ExtRegs:$d, (and ExtRegs:$s1, imml_neg_32_h_32_const64:$const64))]>;

// def ORNrc64: Pseudo<(outs ExtRegs:$d),
//   (ins ExtRegs:$s1, imml_neg_32_h_32_const64:$const64),
//   "##NAME## Pseudo",
//   [(set ExtRegs:$d, (or ExtRegs:$s1, imml_neg_32_h_32_const64:$const64))]>;

// def XORrcneg64: Pseudo<(outs ExtRegs:$d),
//   (ins ExtRegs:$s1, imml_neg_32_h_32_const64:$const64),
//   "##NAME## Pseudo",
//   [(set ExtRegs:$d, (xor ExtRegs:$s1, imml_neg_32_h_32_const64:$const64))]>;

// Move Immediate Instructions
// class MOV_RR<bits<8> op1, bits<8> op2, string opstr,
// RegisterClass outregClass, RegisterClass inregClass>
// : RR<op1, op2,
//  (outs outregClass:$d),
//  (ins inregClass:$s2),
//  !strconcat(opstr, " $d, $s2"), [/* No Pattern*/]>;

// class MOV_CONST<bits<8> opcode, string opstr, dag ins, list<dag> pattern>
// : RLC<opcode, (outs DataRegs:$d), ins,
//  !strconcat(opstr, " $d, $const16"), pattern>;

// def MOVrr   : MOV_RR<0x0B, 0x1F, "mov", DataRegs, DataRegs>;
// def MOV_Drr  : MOV_RR<0x01, 0x4C, "mov.d", DataRegs, AddrRegs>;
// def MOV_Arr  : MOV_RR<0x01, 0x63, "mov.a", AddrRegs, DataRegs>;

// def MOV_AAsrr : SRR<0x40, (outs AddrRegs:$d),
//             (ins AddrRegs:$s2),
//             "mov.aa $d, $s2", [] >;

// def MOV_AArr : MOV_RR<0x01, 0x00, "mov.aa", AddrRegs, AddrRegs>;


// def MOVsrc : SRC<0x82, (outs DataRegs:$d),
//         (ins s4imm:$const4),
//         "mov $d, $const4",
//          [(set DataRegs:$d, immSExt4:$const4)]>;

// def MOVrlc  : MOV_CONST<0x3B,"mov", (ins s16imm:$const16),
//               [(set DataRegs:$d, immSExt16:$const16)]>;
// def MOV_Urlc : MOV_CONST<0xBB,"mov.u", (ins u16imm:$const16),
//               [(set DataRegs:$d, immZExt16:$const16)]>;

// def MOVHrlc : MOV_CONST<0x7B, "movh", (ins i32imm:$const16), [/* No Pattern*/]>;

// //let isReMaterializable = 1, isAsCheapAsAMove = 1 in
// def MOVi32 : Pseudo<(outs DataRegs:$d), (ins i32imm:$const32), "##NAME## Pseudo",
//                      [(set DataRegs:$d, (movei32 imm:$const32))]>;

// def IMASKrcpw :  RCPW<0xB7, 0b01, (outs ExtRegs:$d),
//   (ins u4imm:$const4, i32imm:$pos, i32imm:$width),
//   "imask $d, $const4, $pos, $width",
//   [(set ExtRegs:$d, (TriCoreImask immZExt4:$const4, imm:$pos, imm:$width))]>;

// def DEXTRrrpw :  RRPW<0x77, 0b00, (outs DataRegs:$d),
//   (ins DataRegs:$s1, DataRegs:$s2, i32imm:$pos),
//   "dextr $d, $s1, $s2, $pos",
//   [(set DataRegs:$d, (TriCoreExtr DataRegs:$s1, DataRegs:$s2, immZExt4:$pos))]>;

// def EXTRrrpw :  RRPW<0x37, 0b10, (outs DataRegs:$d),
//   (ins DataRegs:$s1, i32imm:$pos, i32imm:$width),
//   "extr $d, $s1, $pos, $width",
//   [(set DataRegs:$d, (TriCoreExtr DataRegs:$s1, immZExt4:$pos,
//   immZExt4:$width))]>;

// // Load/Store Instructions
// class LoadABS<bits<8> op1, bits<2> op2, string opstr, PatFrag PF,
//          RegisterClass RC = DataRegs, ValueType intType = i32>
//         : ABS<op1, op2, (outs RC:$d),
//          (ins i32imm:$memri),
//          !strconcat(opstr, " $d, $memri"),
//          [(set RC:$d, (intType (PF imm:$memri)))]>{ let mayLoad = 1; }

// def LD_Babs  : LoadABS<0x05, 0x00, "ld.b"  , sextloadi8>;
// def LD_BUabs : LoadABS<0x05, 0x01, "ld.bu" , zextloadi8>;
// def LD_Habs  : LoadABS<0x05, 0x02, "ld.h"  , sextloadi16>;
// def LD_HUabs : LoadABS<0x05, 0x03, "ld.hu" , zextloadi16>;
// def LD_Wabs  : LoadABS<0x85, 0x00, "ld.w"  , load>;
// def LD_Dabs  : LoadABS<0x85, 0x01, "ld.d"  , load, ExtRegs,i64>;
// def LD_Aabs  : LoadABS<0x85, 0x02, "ld.a"  , load, AddrRegs>;
// def LD_DAabs : ABS<0x85, 0x03, (outs PairAddrRegsOp:$d),
//          (ins i32imm:$memri), "ld.da $d, $memri",
//          [(set PairAddrRegsOp:$d, (i64 (load imm:$memri)))]>{ let mayLoad = 1; }
// def LD_Qabs  : LoadABS<0x45, 0x00, "ld.q"  , load>;

// class LoadBO<bits<6> op2, string opstr, PatFrag PF,
//          RegisterClass RC = DataRegs, ValueType intType = i32>
//         : BO<0x09, op2, (outs RC:$d),
//          (ins bo:$memri),
//          !strconcat(opstr, " $d, $memri"),
//          [(set RC:$d, (intType (PF addr:$memri)))]>{ let mayLoad = 1; }

// def LD_Bbo  : LoadBO<0x20, "ld.b"  , sextloadi8>;
// def LD_BUbo : LoadBO<0x21, "ld.bu" , zextloadi8>;
// def LD_Hbo  : LoadBO<0x22, "ld.h"  , sextloadi16>;
// def LD_HUbo : LoadBO<0x23, "ld.hu" , zextloadi16>;
// def LD_Wbo  : LoadBO<0x24, "ld.w"  , load>;
// def LD_Dbo  : LoadBO<0x25, "ld.d"  , load, ExtRegs, i64>;
// def LD_Abo  : LoadBO<0x26, "ld.a"  , load, AddrRegs>;
// def LD_DAbo : BO<0x09, 0x27, (outs PairAddrRegsOp:$d),
//          (ins bo:$memri), "ld.da $d, $memri",
//          [(set PairAddrRegsOp:$d, (i64 (load addr:$memri)))]>{ let mayLoad = 1; }
// def LD_Qbo  : LoadBO<0x28, "ld.q"  , load>;

// class LoadPreIncBO<bits<6> op2, string opstr, PatFrag PF,
//          RegisterClass RC = DataRegs, ValueType intType = i32>
//         : BO<0x09, op2, (outs RC:$d),
//          (ins preincbo:$memri),
//          !strconcat(opstr, " $d, $memri"),
//          [(set RC:$d, (intType (PF addr:$memri)))]>{ let mayLoad = 1; }

// def LD_Bpreincbo  : LoadPreIncBO<0x10, "ld.b"  , sextloadi8>;
// def LD_BUpreincbo : LoadPreIncBO<0x11, "ld.bu" , zextloadi8>;
// def LD_Hpreincbo  : LoadPreIncBO<0x12, "ld.h"  , sextloadi16>;
// def LD_HUpreincbo : LoadPreIncBO<0x13, "ld.hu" , zextloadi16>;
// def LD_Wpreincbo  : LoadPreIncBO<0x14, "ld.w"  , load>;
// def LD_Dpreincbo  : LoadPreIncBO<0x15, "ld.d"  , load, ExtRegs, i64>;
// def LD_Apreincbo  : LoadPreIncBO<0x16, "ld.a"  , load, AddrRegs>;
// def LD_DApreincbo : BO<0x09, 0x17, (outs PairAddrRegsOp:$d),
//          (ins preincbo:$memri),
//          "ld.da $d, $memri",
//          [(set PairAddrRegsOp:$d, (i64 (load addr:$memri)))]>{ let mayLoad = 1; }
// def LD_Qpreincbo  : LoadPreIncBO<0x18, "ld.q"  , load>;

// class LoadPostIncBO<bits<6> op2, string opstr, PatFrag PF,
//          RegisterClass RC = DataRegs, ValueType intType = i32>
//         : BO<0x09, op2, (outs RC:$d),
//          (ins postincbo:$memri),
//          !strconcat(opstr, " $d, $memri"),
//          [(set RC:$d, (intType (PF addr:$memri)))]>{ let mayLoad = 1; }

// def LD_Bpostincbo  : LoadPostIncBO<0x00, "ld.b"  , sextloadi8>;
// def LD_BUpostincbo : LoadPostIncBO<0x01, "ld.bu" , zextloadi8>;
// def LD_Hpostincbo  : LoadPostIncBO<0x02, "ld.h"  , sextloadi16>;
// def LD_HUpostincbo : LoadPostIncBO<0x03, "ld.hu" , zextloadi16>;
// def LD_Wpostincbo  : LoadPostIncBO<0x04, "ld.w"  , load>;
// def LD_Dpostincbo  : LoadPostIncBO<0x05, "ld.d"  , load, ExtRegs, i64>;
// def LD_Apostincbo  : LoadPostIncBO<0x06, "ld.a"  , load, AddrRegs>;
// def LD_DApostincbo : BO<0x09, 0x07, (outs PairAddrRegsOp:$d),
//          (ins postincbo:$memri),
//          "ld.da $d, $memri",
//          [(set PairAddrRegsOp:$d, (i64 (load addr:$memri)))]>{ let mayLoad = 1; }
// def LD_Qpostincbo  : LoadPostIncBO<0x08, "ld.q"  , load>;

// class LoadCircBO<bits<6> op2, string opstr, PatFrag PF,
//          RegisterClass RC = DataRegs, ValueType intType = i32>
//         : BO<0x29, op2, (outs RC:$d),
//          (ins circbo:$memri),
//          !strconcat(opstr, " $d, $memri"),
//          [(set RC:$d, (intType (PF addr:$memri)))]>{ let mayLoad = 1; }

// def LD_Bcircbo  : LoadCircBO<0x10, "ld.b"  , sextloadi8>;
// def LD_BUcircbo : LoadCircBO<0x11, "ld.bu" , zextloadi8>;
// def LD_Hcircbo  : LoadCircBO<0x12, "ld.h"  , sextloadi16>;
// def LD_HUcircbo : LoadCircBO<0x13, "ld.hu" , zextloadi16>;
// def LD_Wcircbo  : LoadCircBO<0x14, "ld.w"  , load>;
// def LD_Dcircbo  : LoadCircBO<0x15, "ld.d"  , load, ExtRegs, i64>;
// def LD_Acircbo  : LoadCircBO<0x16, "ld.a"  , load, AddrRegs>;
// def LD_DAcircbo : BO<0x29, 0x17, (outs PairAddrRegsOp:$d),
//          (ins circbo:$memri),
//          "ld.da $d, $memri",
//          [(set PairAddrRegsOp:$d, (i64 (load addr:$memri)))]>{ let mayLoad = 1; }
// def LD_Qcircbo  : LoadCircBO<0x18, "ld.q"  , load>;

// class LoadBitRevBO<bits<6> op2, string opstr, PatFrag PF,
//          RegisterClass RC = DataRegs, ValueType intType = i32>
//         : BO<0x29, op2, (outs RC:$d),
//          (ins bitrevbo:$memri),
//          !strconcat(opstr, " $d, $memri"),
//          [(set RC:$d, (intType (PF addr:$memri)))]>{ let mayLoad = 1; }

// def LD_Bbitrevbo  : LoadBitRevBO<0x00, "ld.b"  , sextloadi8>;
// def LD_BUbitrevbo : LoadBitRevBO<0x01, "ld.bu" , zextloadi8>;
// def LD_Hbitrevbo  : LoadBitRevBO<0x02, "ld.h"  , sextloadi16>;
// def LD_HUbitrevbo : LoadBitRevBO<0x03, "ld.hu" , zextloadi16>;
// def LD_Wbitrevbo  : LoadBitRevBO<0x04, "ld.w"  , load>;
// def LD_Dbitrevbo  : LoadBitRevBO<0x05, "ld.d"  , load, ExtRegs, i64>;
// def LD_Abitrevbo  : LoadBitRevBO<0x06, "ld.a"  , load, AddrRegs>;
// def LD_DAbitrevbo : BO<0x29, 0x07, (outs PairAddrRegsOp:$d),
//          (ins bitrevbo:$memri),
//          "ld.da $d, $memri",
//          [(set PairAddrRegsOp:$d, (i64 (load addr:$memri)))]>{ let mayLoad = 1; }
// def LD_Qbitrevbo  : LoadBitRevBO<0x08, "ld.q"  , load>;

// def LD_Wbol : BOL<0x19, (outs DataRegs:$d),
//    (ins bo:$memri),
//    "ld.w $d, $memri",
//    [(set DataRegs:$d, (load addr:$memri))]>{ let mayLoad = 1; }
// def LD_Abol : BOL<0x99, (outs AddrRegs:$d),
//    (ins bo:$memri),
//    "ld.a $d, $memri",
//    [(set AddrRegs:$d, (load addr:$memri))]>{ let mayLoad = 1; }

// def : Pat<(extloadi8 addr:$src), (LD_Bbo addr:$src)>;
// def : Pat<(extloadi16 addr:$src), (LD_Hbo addr:$src)>;

// let Predicates = [isnotPointer] in {
//  def ST_Babs : ABS<0x25, 0x00,(outs), (ins DataRegs:$d, i32imm:$memri),
//    "st.b $memri, $d",
//    [(truncstorei8 DataRegs:$d, imm:$memri)]>;
//  def ST_Habs : ABS<0x25, 0x02,(outs), (ins DataRegs:$d, i32imm:$memri),
//    "st.h $memri, $d",
//    [(truncstorei16 DataRegs:$d, imm:$memri)]>;
//  def ST_Wabs : ABS<0xA5, 0x00, (outs), (ins DataRegs:$d, i32imm:$memri),
//    "st.w $memri, $d",
//    [(store DataRegs:$d, imm:$memri)]>;
//  def ST_Dabs : ABS<0xA5, 0x01, (outs), (ins ExtRegs:$d, i32imm:$memri),
//    "st.d $memri, $d",
//    [(store ExtRegs:$d, imm:$memri)]>;
//  def ST_Qabs : ABS<0x65, 0x00, (outs), (ins DataRegs:$d, i32imm:$memri),
//    "st.q $memri, $d",
//    [(store DataRegs:$d, imm:$memri)]>;

//  def ST_Bbo : BO<0x89, 0x20,(outs), (ins DataRegs:$d, bo:$memri),
//    "st.b $memri, $d",
//    [(truncstorei8 DataRegs:$d, addr:$memri)]>;
//  def ST_Hbo : BO<0x89, 0x22,(outs), (ins DataRegs:$d, bo:$memri),
//    "st.h $memri, $d",
//    [(truncstorei16 DataRegs:$d, addr:$memri)]>;
//  def ST_Wbo : BO<0x89, 0x24, (outs), (ins DataRegs:$d, bo:$memri),
//    "st.w $memri, $d",
//    [(store DataRegs:$d, addr:$memri)]>;
//  def ST_Dbo : BO<0x89, 0x25, (outs), (ins ExtRegs:$d, bo:$memri),
//    "st.d $memri, $d",
//    [(store ExtRegs:$d, addr:$memri)]>;
//  def ST_Qbo : BO<0x89, 0x28, (outs), (ins DataRegs:$d, bo:$memri),
//    "st.q $memri, $d",
//    [(store DataRegs:$d, addr:$memri)]>;

//  def ST_Bpreincbo : BO<0x89, 0x10,(outs), (ins DataRegs:$d, preincbo:$memri),
//    "st.b $memri, $d",
//    [(truncstorei8 DataRegs:$d, addr:$memri)]>;
//  def ST_Hpreincbo : BO<0x89, 0x12,(outs), (ins DataRegs:$d, preincbo:$memri),
//    "st.h $memri, $d",
//    [(truncstorei16 DataRegs:$d, addr:$memri)]>;
//  def ST_Wpreincbo : BO<0x89, 0x14, (outs), (ins DataRegs:$d, preincbo:$memri),
//    "st.w $memri, $d",
//    [(store DataRegs:$d, addr:$memri)]>;
//  def ST_Dpreincbo : BO<0x89, 0x15, (outs), (ins ExtRegs:$d, preincbo:$memri),
//    "st.d $memri, $d",
//    [(store ExtRegs:$d, addr:$memri)]>;
//  def ST_Qpreincbo : BO<0x89, 0x18, (outs), (ins DataRegs:$d, preincbo:$memri),
//    "st.q $memri, $d",
//    [(store DataRegs:$d, addr:$memri)]>;

//  def ST_Bpostincbo : BO<0x89, 0x00,(outs), (ins DataRegs:$d, postincbo:$memri),
//    "st.b $memri, $d",
//    [(truncstorei8 DataRegs:$d, addr:$memri)]>;
//  def ST_Hpostincbo : BO<0x89, 0x02,(outs), (ins DataRegs:$d, postincbo:$memri),
//    "st.h $memri, $d",
//    [(truncstorei16 DataRegs:$d, addr:$memri)]>;
//  def ST_Wpostincbo : BO<0x89, 0x04, (outs), (ins DataRegs:$d, postincbo:$memri),
//    "st.w $memri, $d",
//    [(store DataRegs:$d, addr:$memri)]>;
//  def ST_Dpostincbo : BO<0x89, 0x05, (outs), (ins ExtRegs:$d, postincbo:$memri),
//    "st.d $memri, $d",
//    [(store ExtRegs:$d, addr:$memri)]>;
//  def ST_Qpostincbo : BO<0x89, 0x08, (outs), (ins DataRegs:$d, postincbo:$memri),
//    "st.q $memri, $d",
//    [(store DataRegs:$d, addr:$memri)]>;

//  def ST_Bcircbo : BO<0xA9, 0x10,(outs), (ins DataRegs:$d, circbo:$memri),
//    "st.b $memri, $d",
//    [(truncstorei8 DataRegs:$d, addr:$memri)]>;
//  def ST_Hcircbo : BO<0xA9, 0x12,(outs), (ins DataRegs:$d, circbo:$memri),
//    "st.h $memri, $d",
//    [(truncstorei16 DataRegs:$d, addr:$memri)]>;
//  def ST_Wcircbo : BO<0xA9, 0x14, (outs), (ins DataRegs:$d, circbo:$memri),
//    "st.w $memri, $d",
//    [(store DataRegs:$d, addr:$memri)]>;
//  def ST_Dcircbo : BO<0xA9, 0x15, (outs), (ins ExtRegs:$d, circbo:$memri),
//    "st.d $memri, $d",
//    [(store ExtRegs:$d, addr:$memri)]>;
//  def ST_Qcircbo : BO<0xA9, 0x18, (outs), (ins DataRegs:$d, circbo:$memri),
//    "st.q $memri, $d",
//    [(store DataRegs:$d, addr:$memri)]>;

//  def ST_Bbitrevbo : BO<0xA9, 0x00,(outs), (ins DataRegs:$d, bitrevbo:$memri),
//    "st.b $memri, $d",
//    [(truncstorei8 DataRegs:$d, addr:$memri)]>;
//  def ST_Hbitrevbo : BO<0xA9, 0x02,(outs), (ins DataRegs:$d, bitrevbo:$memri),
//    "st.h $memri, $d",
//    [(truncstorei16 DataRegs:$d, addr:$memri)]>;
//  def ST_Wbitrevbo : BO<0xA9, 0x04, (outs), (ins DataRegs:$d, bitrevbo:$memri),
//    "st.w $memri, $d",
//    [(store DataRegs:$d, addr:$memri)]>;
//  def ST_Dbitrevbo : BO<0xA9, 0x05, (outs), (ins ExtRegs:$d, bitrevbo:$memri),
//    "st.d $memri, $d",
//    [(store ExtRegs:$d, addr:$memri)]>;
//  def ST_Qbitrevbo : BO<0xA9, 0x08, (outs), (ins DataRegs:$d, bitrevbo:$memri),
//    "st.q $memri, $d",
//    [(store DataRegs:$d, addr:$memri)]>;

//  def : Pat<(truncstorei32 ExtRegs:$d, addr:$memri),
//     (ST_Wbo (EXTRACT_SUBREG ExtRegs:$d, subreg_even), addr:$memri)>;

// //  def : Pat<(truncstorei8 ExtRegs:$d, addr:$memri),
// //      (ST_Wbo (ANDrc (EXTRACT_SUBREG ExtRegs:$d, subreg_even),
// //      (i32 255)), addr:$memri)>;
// } // let Predicates = [isnotPointer]


// let Predicates = [isPointer] in {
//   def ST_Aabs : ABS<0xA5, 0x02,(outs), (ins AddrRegs:$d, i32imm:$memri),
//    "st.a $memri, $d",
//    [(truncstorei8 i32:$d, imm:$memri)]>;

//   def ST_DAabs : ABS<0xA5, 0x03,(outs), (ins PairAddrRegsOp:$d, i32imm:$memri),
//    "st.da $memri, $d",
//    [(truncstorei8 i64:$d, imm:$memri)]>;

//   def ST_Abo : BO<0x89, 0x26, (outs), (ins AddrRegs:$d, bo:$memri),
//   "st.a $memri, $d",
//   [(store i32:$d, addr:$memri)]>;

//   def ST_DAbo : BO<0x89, 0x27, (outs), (ins PairAddrRegsOp:$d, bo:$memri),
//   "st.da $memri, $d",
//   [(store i64:$d, addr:$memri)]>;

//   def ST_Apreincbo : BO<0x89, 0x16,(outs), (ins AddrRegs:$d, preincbo:$memri),
//    "st.a $memri, $d",
//    [(store i32:$d, addr:$memri)]>;

//   def ST_DApreincbo : BO<0x89, 0x17,(outs), (ins PairAddrRegsOp:$d, preincbo:$memri),
//    "st.da $memri, $d",
//    [(store i64:$d, addr:$memri)]>;

//    def ST_Apostincbo : BO<0x89, 0x06,(outs), (ins AddrRegs:$d, postincbo:$memri),
//    "st.a $memri, $d",
//    [(store i32:$d, addr:$memri)]>;

//    def ST_DApostincbo : BO<0x89, 0x07,(outs), (ins PairAddrRegsOp:$d, postincbo:$memri),
//    "st.da $memri, $d",
//    [(store i64:$d, addr:$memri)]>;
   
//    def ST_Acircbo : BO<0xA9, 0x16,(outs), (ins AddrRegs:$d, circbo:$memri),
//    "st.a $memri, $d",
//    [(store i32:$d, addr:$memri)]>;

//    def ST_DAcircbo : BO<0xA9, 0x17,(outs), (ins PairAddrRegsOp:$d, circbo:$memri),
//    "st.da $memri, $d",
//    [(store i64:$d, addr:$memri)]>;

//    def ST_Abitrevbo : BO<0xA9, 0x06,(outs), (ins AddrRegs:$d, bitrevbo:$memri),
//    "st.a $memri, $d",
//    [(store i32:$d, addr:$memri)]>;

//    def ST_DAbitrevbo : BO<0xA9, 0x07,(outs), (ins PairAddrRegsOp:$d, bitrevbo:$memri),
//    "st.da $memri, $d",
//    [(store i64:$d, addr:$memri)]>;

// } // let Predicates = [isPointer]

// // Shift Instructions

// // only const9[5:0] is of importance
// def SHrc : RC<0x8F,0x00, (outs DataRegs:$d), (ins DataRegs:$s1, s9imm:$const9),
//   "sh $d, $s1, $const9",
//   [(set DataRegs:$d, (TriCoreSh DataRegs:$s1, immSExt6:$const9))]>;

// def SHrr : RR<0x0F, 0x00, (outs DataRegs:$d), (ins DataRegs:$s1, DataRegs:$s2),
//   "sh $d, $s1, $s2",
//   [(set DataRegs:$d, (TriCoreSh DataRegs:$s1, DataRegs:$s2))]>;

// def SHArc : RC<0x8F,0x01, (outs DataRegs:$d), (ins DataRegs:$s1, s9imm:$const9),
//   "sha $d, $s1, $const9",
//   [(set DataRegs:$d, (TriCoreSha DataRegs:$s1, immSExt6:$const9))]>;

// def SHArr : RR<0x0F, 0x01, (outs DataRegs:$d), (ins DataRegs:$s1, DataRegs:$s2),
//   "sha $d, $s1, $s2",
//   [(set DataRegs:$d, (TriCoreSha DataRegs:$s1, DataRegs:$s2))]>;

// // Return Instructions
// let isTerminator = 1, isReturn = 1, isBarrier = 1 in
//    def RET : T32<(outs), (ins variable_ops), "ret",  [(TriCoreRetFlag)]>;

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

// def : Pat<(TriCoreCall (i32 tglobaladdr:$dst)),
//       (CALL_b tglobaladdr:$dst)>;
// def : Pat<(i32 (TriCoreWrapper tglobaladdr:$dst)),
//       (MOVi32 tglobaladdr:$dst)>;

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

// defm EQ : COMPARE_32<0x10, "eq", TriCore_COND_EQ>;
// defm NE : COMPARE_32<0x11, "ne", TriCore_COND_NE>;
// defm LT : COMPARE_32<0x12, "lt", TriCore_COND_LT>;
// defm GE : COMPARE_32<0x14, "ge", TriCore_COND_GE>;


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

// defm AND_EQ    : LOGIC_COMPARE_S<0x20, "and.eq",  TriCore_LOGIC_AND_EQ>;
// defm AND_NE    : LOGIC_COMPARE_S<0x21, "and.ne",  TriCore_LOGIC_AND_NE>;
// defm AND_LT    : LOGIC_COMPARE_S<0x22, "and.lt", TriCore_LOGIC_AND_LT>;
// defm AND_LT_U  : LOGIC_COMPARE_U<0x23, "and.lt.u", TriCore_LOGIC_AND_LT>;
// defm AND_GE    : LOGIC_COMPARE_S<0x24, "and.ge", TriCore_LOGIC_AND_GE>;
// defm AND_GE_U  : LOGIC_COMPARE_U<0x25, "and.ge.u", TriCore_LOGIC_AND_GE>;

// defm OR_EQ     : LOGIC_COMPARE_S<0x27, "or.eq",  TriCore_LOGIC_OR_EQ>;
// defm OR_NE     : LOGIC_COMPARE_S<0x28, "or.ne",  TriCore_LOGIC_OR_NE>;
// defm OR_LT     : LOGIC_COMPARE_S<0x29, "or.lt",  TriCore_LOGIC_OR_LT>;
// defm OR_LT_U   : LOGIC_COMPARE_U<0x2A, "or.lt.u",  TriCore_LOGIC_OR_LT>;
// defm OR_GE     : LOGIC_COMPARE_S<0x2B, "or.ge",  TriCore_LOGIC_OR_GE>;
// defm OR_GE_U   : LOGIC_COMPARE_U<0x2C, "or.ge.u",  TriCore_LOGIC_OR_GE>;

// defm XOR_EQ    : LOGIC_COMPARE_S<0x2F, "xor.eq",  TriCore_LOGIC_OR_EQ>;
// defm XOR_NE    : LOGIC_COMPARE_S<0x30, "xor.ne",  TriCore_LOGIC_OR_NE>;
// defm XOR_LT    : LOGIC_COMPARE_S<0x31, "xor.lt",  TriCore_LOGIC_OR_LT>;
// defm XOR_LT_U  : LOGIC_COMPARE_U<0x32, "xor.lt.u",  TriCore_LOGIC_OR_LT>;
// defm XOR_GE    : LOGIC_COMPARE_S<0x33, "xor.ge",  TriCore_LOGIC_OR_GE>;
// defm XOR_GE_U  : LOGIC_COMPARE_U<0x34, "xor.ge.u",  TriCore_LOGIC_OR_GE>;

// Branch Instructions
// let Uses = [PC], Defs = [PC] in
// multiclass JUMP_16<bits<8> op1_sb, bits<8> op1_sbr,
//          string asmstring, PatLeaf PF>
// {
//   let Uses = [D15] in
//   def sb: SB<op1_sb, (outs),
//      (ins jmptarget:$disp8),
//      !strconcat(asmstring, " %d15, $disp8"),
//      [(TriCoreBrCC bb:$disp8, D15, PF)]>;

//   def sbr: SBR<op1_sbr, (outs),
//      (ins DataRegs:$s1, jmptarget:$disp4),
//      !strconcat(asmstring, " $s1, $disp4"),
//      [(TriCoreBrCC bb:$disp4, DataRegs:$s1, PF)]>;
// }

// let isBranch = 1, isTerminator = 1 in {
// // Direct branch
// let isBarrier = 1 in {
//   def Jb : B<0x1D, (outs), (ins jmptarget:$dst),
//                 "j $dst",
//         [(br bb:$dst)]>;
// }

// // Conditional branches

//  defm JNZ : JUMP_16<0xEE, 0xF6, "jnz", TriCore_COND_NE>;
//  defm JZ : JUMP_16<0x6E, 0x76, "jz", TriCore_COND_EQ>;

// } // isBranch, isTerminator


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


// let usesCustomInserter = 1 in {
//   def Select8  : Pseudo<(outs DataRegs:$dst),
//              (ins DataRegs:$src, DataRegs:$src2, i32imm:$cc, DataRegs:$src1 ),
//              "# Select8 PSEUDO",
//             [(set DataRegs:$dst,
//             (TriCoreSelectCC DataRegs:$src, DataRegs:$src2, imm:$cc,
//             DataRegs:$src1))]>;
// }

//===----------------------------------------------------------------------===//
// Non-Instruction Patterns
//===----------------------------------------------------------------------===//

// TODO: Also write a pattern when we have a zero shift
// def : Pat<(shl ExtRegs:$src, (i32 imm32_64:$amt)),
//           (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//                        (SHrc (EXTRACT_SUBREG ExtRegs:$src, subreg_even),
//                          (SHIFTAMT (imm32_64:$amt))), subreg_odd)),
//                        (MOVrlc (i32 0)), subreg_even)>;

// def : Pat<(shl ExtRegs:$src, (i32 imm0_31:$amt)),
//           (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//                        (DEXTRrrpw (EXTRACT_SUBREG ExtRegs:$src, subreg_odd),
//                          (EXTRACT_SUBREG ExtRegs:$src, subreg_even),
//                  (i32 imm0_31:$amt)), subreg_odd)),
//                    (SHrc (EXTRACT_SUBREG ExtRegs:$src, subreg_even),
//                  ( i32 imm0_31:$amt)), subreg_even)>;

// def : Pat<(srl ExtRegs:$src, (i32 imm0_31:$amt)),
//           (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//                        (DEXTRrrpw (EXTRACT_SUBREG ExtRegs:$src, subreg_odd),
//                          (EXTRACT_SUBREG ExtRegs:$src, subreg_even),
//                  (SHIFTAMT_POS (imm0_31:$amt))), subreg_even)),
//                    (SHrc (EXTRACT_SUBREG ExtRegs:$src, subreg_odd),
//                  (INVERT_VAL imm0_31:$amt)), subreg_odd)>;

// def : Pat<(srl ExtRegs:$src, (i32 imm32_64:$amt)),
//           (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//                        (SHrc (EXTRACT_SUBREG ExtRegs:$src, subreg_odd),
//                          (SHIFTAMT_NEG (imm32_64:$amt))), subreg_even)),
//                        (MOVrlc (i32 0)), subreg_odd)>;

// def : Pat<(sra ExtRegs:$src, (i32 imm32_64:$amt)),
//           (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//            (SHArc ( EXTRACT_SUBREG (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//              (SHArc (EXTRACT_SUBREG ExtRegs:$src, subreg_odd),
//                (SHIFTAMT_NEG (imm32_64:$amt))), subreg_even), subreg_even),
//                   (i32 -31)), subreg_odd)>;

// def : Pat<(sra ExtRegs:$src, (i32 imm0_31:$amt)),
//           (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//                        (DEXTRrrpw (EXTRACT_SUBREG ExtRegs:$src, subreg_odd),
//                          (EXTRACT_SUBREG ExtRegs:$src, subreg_even),
//                  (SHIFTAMT_POS (imm0_31:$amt))), subreg_even)),
//                    (SHArc (EXTRACT_SUBREG ExtRegs:$src, subreg_odd),
//                  (INVERT_VAL imm0_31:$amt)), subreg_odd)>;

// def : Pat<(shl DataRegs:$src, (i32 0)),
//      (MOVrr DataRegs:$src)>;

// // This extracts the even register from an extended register
// def : Pat<(i32 (trunc ExtRegs:$src)),
//      (EXTRACT_SUBREG ExtRegs:$src, subreg_even)>;

// // sext
// def : Pat<(sext DataRegs:$src),
//      (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//         (i32 DataRegs:$src), subreg_even)),
//         (SHArc (i32 DataRegs:$src), (i32 -31)), subreg_odd)>;

// // sext_inreg for i16
// def : Pat<(sext_inreg DataRegs:$src, i16),
//           (MOVrr (i32 DataRegs:$src))>;

// // sext_inreg for i8
// def : Pat<(sext_inreg DataRegs:$src, i8),
//           (MOVrr (i32 DataRegs:$src))>;

// // sext_inreg from i8 to i64
// def : Pat<(sext_inreg ExtRegs:$src, i8),
//   (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//     (SHArc ( EXTRACT_SUBREG (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//       ( EXTRrrpw (EXTRACT_SUBREG ExtRegs:$src, subreg_even),
//         (i32 0), (i32 8) ), subreg_even), subreg_even),
//          (i32 -31)), subreg_odd)>;

// // sext_inreg from i16 to i64
// def : Pat<(sext_inreg ExtRegs:$src, i16),
//   (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//     (SHArc ( EXTRACT_SUBREG (INSERT_SUBREG (i64 (IMPLICIT_DEF)) ,
//       ( EXTRrrpw (EXTRACT_SUBREG ExtRegs:$src, subreg_even),
//         (i32 0), (i32 16) ), subreg_even), subreg_even)
//       , (i32 -31)), subreg_odd)>;

// // anyext
// def : Pat<(anyext DataRegs:$src),
//   (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//     (SHArc ( EXTRACT_SUBREG (INSERT_SUBREG (i64 (IMPLICIT_DEF)) ,
//       (i32 DataRegs:$src), subreg_even), subreg_even)
//       , (i32 -31)), subreg_odd)>;

// // zext
// def : Pat<(zext DataRegs:$src),
//   (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//     (SHArc ( EXTRACT_SUBREG (INSERT_SUBREG (i64 (IMPLICIT_DEF)) ,
//       (i32 DataRegs:$src), subreg_even), subreg_even)
//       , (i32 -31)), subreg_odd)>;

// // This extracts the odd register from an extended register
// // odd_reg = (Extended Register >> 32)
// def : Pat<(i32 (trunc (srl ExtRegs:$src, (i32 32)))),
//      (EXTRACT_SUBREG ExtRegs:$src, subreg_odd)>;

// def : Pat<(i64 imm:$src),
//     (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//                  (MOVi32( LO32 imm:$src)), subreg_even)),
//                  (MOVi32( HI32 imm:$src)), subreg_odd)>;

// def : Pat<(i64 (sextloadi32 addr:$offset)),
//   (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//              (SHArc ( EXTRACT_SUBREG (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//                (LD_Wbo addr:$offset), subreg_even), subreg_even),
//                (i32 -31)), subreg_odd)>;

// def : Pat<(i64 (zextloadi32 addr:$offset)),
//   (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//                          (LD_Wbo addr:$offset), subreg_even)),
//                          (MOVrlc 0), subreg_odd)>;

// def : Pat<(i64 (sextloadi16 addr:$offset)),
//   (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//              (SHArc ( EXTRACT_SUBREG (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//                ( EXTRrrpw (LD_Hbo addr:$offset),
//                  (i32 0), (i32 16) ), subreg_even), subreg_even)
//              , (i32 -31)), subreg_odd)>;

// def : Pat<(i64 (zextloadi16 addr:$offset)),
//   (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//                          (LD_Wbo addr:$offset), subreg_even)),
//                          (MOVrlc 0), subreg_odd)>;


// def : Pat<(i64 (sextloadi8 addr:$offset)),
//   (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//              (SHArc ( EXTRACT_SUBREG (INSERT_SUBREG (i64 (IMPLICIT_DEF)) ,
//                ( EXTRrrpw (LD_Bbo addr:$offset),
//                  (i32 0), (i32 8) ), subreg_even), subreg_even)
//              , (i32 -31)), subreg_odd)>;

// def : Pat<(i64 (zextloadi8 addr:$offset)),
//   (INSERT_SUBREG( i64 (INSERT_SUBREG (i64 (IMPLICIT_DEF)),
//                          (LD_BUbo addr:$offset), subreg_even)),
//                          (MOVrlc 0), subreg_odd)>;
