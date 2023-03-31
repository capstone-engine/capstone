//===-- TriCore.td - Describe the TriCore Target Machine ---*- tablegen -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This is the top level entry point for the TriCore target.
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
// Target-independent interfaces which we are implementing
//===----------------------------------------------------------------------===//

include "llvm/Target/Target.td"

//===----------------------------------------------------------------------===//
// Descriptions
//===----------------------------------------------------------------------===//

include "TriCoreRegisterInfo.td"
include "TriCoreInstrInfo.td"
include "TriCoreCallingConv.td"

def TriCoreInstrInfo : InstrInfo;

class Architecture<string fname, string aname, list<SubtargetFeature> features = []>
  : SubtargetFeature<fname, "TriCoreArch", aname,
                     !strconcat(aname, " architecture"), features>;

class ProcNoItin<string Name, list<SubtargetFeature> Features>
  : Processor<Name, NoItineraries, Features>;


def TRICORE_RIDER_A : Architecture<"tricore-v1_1",    "TRICOREv110">;
def TRICORE_V1_2    : Architecture<"tricore-V1_2",    "TRICOREv120">;
def TRICORE_V1_3    : Architecture<"tricore-V1_3",    "TRICOREv130">;
def TRICORE_V1_3_1  : Architecture<"tricore-V1_3_1",  "TRICOREv131">;
def TRICORE_V1_6    : Architecture<"tricore-V1_6",    "TRICOREv160">;
def TRICORE_V1_6_1  : Architecture<"tricore-V1_6_1",  "TRICOREv161">;
def TRICORE_V1_6_2  : Architecture<"tricore-V1_6_2",  "TRICOREv162">;
def TRICORE_PCP     : Architecture<"tricore-PCP",     "TRICOREvpcp">;
def TRICORE_PCP2    : Architecture<"tricore-PCP2",    "TRICOREvpcp2">;

def : ProcNoItin<"tricore-generic", []>;


//===----------------------------------------------------------------------===//
// TriCore processors supported.
//===----------------------------------------------------------------------===//

def TriCoreAsmWriter : AsmWriter {
  int PassSubtarget = 1;
}

//===----------------------------------------------------------------------===//
// Declare the target which we are implementing
//===----------------------------------------------------------------------===//

def TriCore : Target {
  let InstructionSet = TriCoreInstrInfo;
  let AssemblyWriters = [TriCoreAsmWriter];
}
