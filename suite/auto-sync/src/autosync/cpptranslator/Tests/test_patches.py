#!/usr/bin/env python3

# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import unittest

from pathlib import Path
from tree_sitter import Node, Query

from autosync.cpptranslator import CppTranslator

from autosync.cpptranslator.Configurator import Configurator
from autosync.cpptranslator.patches.AddCSDetail import AddCSDetail
from autosync.cpptranslator.patches.AddOperand import AddOperand
from autosync.cpptranslator.patches.Assert import Assert
from autosync.cpptranslator.patches.BitCastStdArray import BitCastStdArray
from autosync.cpptranslator.patches.CheckDecoderStatus import CheckDecoderStatus
from autosync.cpptranslator.patches.ClassesDef import ClassesDef
from autosync.cpptranslator.patches.ConstMCInstParameter import ConstMCInstParameter
from autosync.cpptranslator.patches.ConstMCOperand import ConstMCOperand
from autosync.cpptranslator.patches.CppInitCast import CppInitCast
from autosync.cpptranslator.patches.CreateOperand0 import CreateOperand0
from autosync.cpptranslator.patches.CreateOperand1 import CreateOperand1
from autosync.cpptranslator.patches.Data import Data
from autosync.cpptranslator.patches.DeclarationInConditionClause import (
    DeclarationInConditionalClause,
)
from autosync.cpptranslator.patches.DecodeInstruction import DecodeInstruction
from autosync.cpptranslator.patches.DecoderCast import DecoderCast
from autosync.cpptranslator.patches.DecoderParameter import DecoderParameter
from autosync.cpptranslator.patches.FallThrough import FallThrough
from autosync.cpptranslator.patches.FeatureBits import FeatureBits
from autosync.cpptranslator.patches.FeatureBitsDecl import FeatureBitsDecl
from autosync.cpptranslator.patches.FieldFromInstr import FieldFromInstr
from autosync.cpptranslator.patches.GetNumOperands import GetNumOperands
from autosync.cpptranslator.patches.GetOpcode import GetOpcode
from autosync.cpptranslator.patches.GetOperand import GetOperand
from autosync.cpptranslator.patches.GetOperandRegImm import GetOperandRegImm
from autosync.cpptranslator.patches.GetRegClass import GetRegClass
from autosync.cpptranslator.patches.GetRegFromClass import GetRegFromClass
from autosync.cpptranslator.patches.GetSubReg import GetSubReg
from autosync.cpptranslator.patches.Includes import Includes
from autosync.cpptranslator.patches.InlineToStaticInline import InlineToStaticInline
from autosync.cpptranslator.patches.IsOptionalDef import IsOptionalDef
from autosync.cpptranslator.patches.IsPredicate import IsPredicate
from autosync.cpptranslator.patches.IsRegImm import IsOperandRegImm
from autosync.cpptranslator.patches.LLVMFallThrough import LLVMFallThrough
from autosync.cpptranslator.patches.LLVM_DEBUG import LLVM_DEBUG
from autosync.cpptranslator.patches.LLVMunreachable import LLVMUnreachable
from autosync.cpptranslator.patches.Override import Override
from autosync.cpptranslator.patches.MethodToFunctions import MethodToFunction
from autosync.cpptranslator.patches.MethodTypeQualifier import MethodTypeQualifier
from autosync.cpptranslator.patches.NamespaceAnon import NamespaceAnon
from autosync.cpptranslator.patches.NamespaceArch import NamespaceArch
from autosync.cpptranslator.patches.NamespaceLLVM import NamespaceLLVM
from autosync.cpptranslator.patches.OutStreamParam import OutStreamParam
from autosync.cpptranslator.patches.PredicateBlockFunctions import (
    PredicateBlockFunctions,
)
from autosync.cpptranslator.patches.PrintAnnotation import PrintAnnotation
from autosync.cpptranslator.patches.PrintRegImmShift import PrintRegImmShift
from autosync.cpptranslator.patches.QualifiedIdentifier import QualifiedIdentifier
from autosync.cpptranslator.patches.ReferencesDecl import ReferencesDecl
from autosync.cpptranslator.patches.RegClassContains import RegClassContains
from autosync.cpptranslator.patches.SetOpcode import SetOpcode
from autosync.cpptranslator.patches.SignExtend import SignExtend
from autosync.cpptranslator.patches.Size import Size
from autosync.cpptranslator.patches.SizeAssignments import SizeAssignment
from autosync.cpptranslator.patches.STIArgument import STIArgument
from autosync.cpptranslator.patches.STIFeatureBits import STIFeatureBits
from autosync.cpptranslator.patches.STParameter import SubtargetInfoParam
from autosync.cpptranslator.patches.StreamOperation import StreamOperations
from autosync.cpptranslator.patches.TemplateDeclaration import TemplateDeclaration
from autosync.cpptranslator.patches.TemplateDefinition import TemplateDefinition
from autosync.cpptranslator.patches.TemplateParamDecl import TemplateParamDecl
from autosync.cpptranslator.patches.TemplateRefs import TemplateRefs
from autosync.cpptranslator.patches.UseMarkup import UseMarkup
from autosync.cpptranslator.patches.UsingDeclaration import UsingDeclaration
from autosync.cpptranslator.TemplateCollector import TemplateCollector
from autosync.cpptranslator.patches.BadConditionCode import BadConditionCode
from autosync.Helper import get_path
from autosync.cpptranslator.patches.isUInt import IsUInt
from autosync.cpptranslator.tree_sitter_compatibility import query_captures_22_3


class TestPatches(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configurator = Configurator("ARCH", get_path("{PATCHES_TEST_CONFIG}"))
        cls.translator = CppTranslator.Translator(configurator, False)
        cls.ts_cpp_lang = configurator.get_cpp_lang()
        cls.parser = configurator.get_parser()
        cls.template_collector = TemplateCollector(
            configurator.get_parser(), configurator.get_cpp_lang(), [], []
        )

    def check_patching_result(
        self, patch, syntax, expected, filename: Path = None, tree: dict = None
    ):
        kwargs = self.translator.get_patch_kwargs(patch)
        if filename:
            kwargs["filename"] = filename

        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        tree = self.parser.parse(syntax)
        kwargs["tree"] = tree
        captures_bundle: [[(Node, str)]] = list()
        for q in query_captures_22_3(query, tree.root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)

        self.assertGreater(len(captures_bundle), 0)
        for cb in captures_bundle:
            actual = patch.get_patch(cb, syntax, **kwargs)
            self.assertEqual(actual, expected)

    def test_addcsdetail(self):
        patch = AddCSDetail(0, "ARCH")
        syntax = b"int i = x; void printThumbLdrLabelOperand(MCInst *MI, unsigned OpNo, SStream *O) { int i = OpNo; }"
        self.check_patching_result(
            patch,
            syntax,
            b"static inline void printThumbLdrLabelOperand(MCInst *MI, unsigned OpNo, SStream *O){ "
            b"ARCH_add_cs_detail_0(MI, ARCH_OP_GROUP_ThumbLdrLabelOperand, OpNo); "
            b"int i = OpNo; "
            b"}",
        )

    def test_addoperand(self):
        patch = AddOperand(0)
        syntax = b"MI.addOperand(OPERAND)"
        self.check_patching_result(
            patch,
            syntax,
            b"MCInst_addOperand2(MI, (OPERAND))",
        )

    def test_assert(self):
        patch = Assert(0)
        syntax = b"assert(0 == 0);"
        self.check_patching_result(patch, syntax, b"CS_ASSERT(0 == 0);")

    def test_bitcaststdarray(self):
        patch = BitCastStdArray(0)
        syntax = b"auto S = bit_cast<std::array<int32_t, 2>>(Imm);"
        self.check_patching_result(
            patch,
            syntax,
            b"union {\n"
            b"    typeof(Imm) In;\n"
            b"    int32_t Out[ 2];\n"
            b"} U_S;\n"
            b"U_S.In = Imm"
            b";\n"
            b"int32_t *S = U_S.Out;",
        )

    def test_checkdecoderstatus(self):
        patch = CheckDecoderStatus(0)
        syntax = b"Check(S, functions())"
        self.check_patching_result(patch, syntax, b"Check(&S, functions())")

    def test_classesdef(self):
        patch = ClassesDef(0)
        syntax = b"""class AArch64Disassembler : public MCDisassembler {
  std::unique_ptr<const MCInstrInfo> const MCII;

public:
  AArch64Disassembler(const MCSubtargetInfo &STI, MCContext &Ctx,
                      MCInstrInfo const *MCII)
      : MCDisassembler(STI, Ctx), MCII(MCII) {}

  ~AArch64Disassembler() override = default;

  MCDisassembler::DecodeStatus
  getInstruction(MCInst &Instr, uint64_t &Size, ArrayRef<uint8_t> Bytes,
                 uint64_t Address, raw_ostream &CStream) const override;

  uint64_t suggestBytesToSkip(ArrayRef<uint8_t> Bytes,
                              uint64_t Address) const override;
};
"""
        self.check_patching_result(
            patch,
            syntax,
            b"MCDisassembler::DecodeStatus\n"
            b"  getInstruction(MCInst &Instr, uint64_t &Size, ArrayRef<uint8_t> Bytes,\n"
            b"                 uint64_t Address, raw_ostream &CStream) const override;\n"
            b"uint64_t suggestBytesToSkip(ArrayRef<uint8_t> Bytes,\n"
            b"                              uint64_t Address) const override;\n",
        )

    def test_constmcinstparameter(self):
        patch = ConstMCInstParameter(0)
        syntax = b"void function(const MCInst *MI);"
        expected = b"MCInst *MI"
        self.check_patching_result(patch, syntax, expected)

    def test_constmcoperand(self):
        patch = ConstMCOperand(0)
        syntax = b"const MCOperand op = { 0 };"
        self.check_patching_result(patch, syntax, b"MCOperand op = { 0 };")

    def test_cppinitcast(self):
        patch = CppInitCast(0)
        syntax = b"int(0x0000)"
        self.check_patching_result(patch, syntax, b"((int)(0x0000))")

    def test_createoperand0(self):
        patch = CreateOperand0(0)
        syntax = b"Inst.addOperand(MCOperand::createReg(REGISTER));"
        self.check_patching_result(
            patch,
            syntax,
            b"MCOperand_CreateReg0(Inst, (REGISTER))",
        )

    def test_createoperand1(self):
        patch = CreateOperand1(0)
        syntax = b"MI.insert(I, MCOperand::createReg(REGISTER));"
        self.check_patching_result(
            patch,
            syntax,
            b"MCInst_insert0(MI, I, MCOperand_CreateReg1(MI, (REGISTER)))",
        )

    def test_data(self):
        patch = Data(0)
        syntax = b"Bytes.data()"
        self.check_patching_result(patch, syntax, b"Bytes")

    def test_declarationinconditionclause(self):
        patch = DeclarationInConditionalClause(0)
        syntax = b"if (int i = 0) {}"
        self.check_patching_result(patch, syntax, b"int i = 0;\nif (i)\n{}")

    def test_decodeinstruction(self):
        patch = DecodeInstruction(0)
        syntax = (
            b"decodeInstruction(DecoderTableThumb16, MI, Insn16, Address, this, STI);"
        )
        self.check_patching_result(
            patch,
            syntax,
            b"decodeInstruction_2(DecoderTableThumb16,  MI,  Insn16,  Address,  NULL)",
        )

        syntax = b"decodeInstruction(Table[i], MI, Insn16, Address, this, STI);"
        self.check_patching_result(
            patch,
            syntax,
            b"decodeInstruction_2(Table[i],  MI,  Insn16,  Address,  NULL)",
        )

    def test_decodercast(self):
        patch = DecoderCast(0)
        syntax = (
            b"const MCDisassembler *Dis = static_cast<const MCDisassembler*>(Decoder);"
        )
        self.check_patching_result(patch, syntax, b"")

    def test_decoderparameter(self):
        patch = DecoderParameter(0)
        syntax = b"void function(const MCDisassembler *Decoder);"
        self.check_patching_result(patch, syntax, b"const void *Decoder")

    def test_fallthrough(self):
        patch = FallThrough(0)
        syntax = b"[[fallthrough]]"
        self.check_patching_result(patch, syntax, b"// fall through")

    def test_featurebitsdecl(self):
        patch = FeatureBitsDecl(0)
        syntax = b"const FeatureBitset &FeatureBits = ((const MCDisassembler*)Decoder)->getSubtargetInfo().getFeatureBits();"
        self.check_patching_result(patch, syntax, b"")

    def test_featurebits(self):
        patch = FeatureBits(0, b"ARCH")
        syntax = b"bool hasD32 = featureBits[ARCH::HasV8Ops];"
        self.check_patching_result(
            patch,
            syntax,
            b"ARCH_getFeatureBits(Inst->csh->mode, ARCH::HasV8Ops)",
        )

    def test_fieldfrominstr(self):
        patch = FieldFromInstr(0)
        syntax = b"unsigned Rm = fieldFromInstruction(Inst16, 0, 4);"
        self.check_patching_result(
            patch,
            syntax,
            b"fieldFromInstruction_2(Inst16, 0, 4)",
        )

        syntax = b"void function(MCInst *MI, unsigned Val) { unsigned Rm = fieldFromInstruction(Val, 0, 4); }"
        self.check_patching_result(
            patch,
            syntax,
            b"fieldFromInstruction_4(Val, 0, 4)",
        )

        syntax = b"static unsigned function(unsigned Insn) { return fieldFromInstruction(Insn, 6, 6); }"
        self.check_patching_result(
            patch,
            syntax,
            b"fieldFromInstruction_4(Insn, 6, 6)",
        )

    def test_getnumoperands(self):
        patch = GetNumOperands(0)
        syntax = b"MI.getNumOperands();"
        self.check_patching_result(patch, syntax, b"MCInst_getNumOperands(MI)")

    def test_getopcode(self):
        patch = GetOpcode(0)
        syntax = b"Inst.getOpcode();"
        self.check_patching_result(patch, syntax, b"MCInst_getOpcode(Inst)")

    def test_getoperand(self):
        patch = GetOperand(0)
        syntax = b"MI.getOperand(0);"
        self.check_patching_result(patch, syntax, b"MCInst_getOperand(MI, (0))")

    def test_getoperandreg(self):
        patch = GetOperandRegImm(0)
        syntax = b"OPERAND.getReg()"
        self.check_patching_result(patch, syntax, b"MCOperand_getReg(OPERAND)")

    def test_getoperandimm(self):
        patch = GetOperandRegImm(0)
        syntax = b"OPERAND.getImm()"
        self.check_patching_result(patch, syntax, b"MCOperand_getImm(OPERAND)")

    def test_getoperandexpr(self):
        patch = GetOperandRegImm(0)
        syntax = b"OPERAND.getExpr()"
        self.check_patching_result(patch, syntax, b"MCOperand_getExpr(OPERAND)")

    def test_getregclass(self):
        patch = GetRegClass(0)
        syntax = b"MRI.getRegClass(RegClass);"
        expected = b"MCRegisterInfo_getRegClass(Inst->MRI, RegClass)"
        self.check_patching_result(patch, syntax, expected)

    def test_getregfromclass(self):
        patch = GetRegFromClass(0)
        syntax = b"ARCHMCRegisterClasses[ARCH::FPR128RegClassID].getRegister(RegNo);"
        self.check_patching_result(
            patch,
            syntax,
            b"ARCHMCRegisterClasses[ARCH::FPR128RegClassID].RegsBegin[RegNo]",
        )

    def test_getsubreg(self):
        patch = GetSubReg(0)
        syntax = b"MRI.getSubReg(REGISTER);"
        self.check_patching_result(
            patch,
            syntax,
            b"MCRegisterInfo_getSubReg(Inst->MRI, REGISTER)",
        )

    def test_includes(self):
        patch = Includes(0, "TEST_ARCH")
        syntax = b'#include "some_llvm_header.h"'
        self.check_patching_result(
            patch,
            syntax,
            b"#include <stdio.h>\n"
            b"#include <string.h>\n"
            b"#include <stdlib.h>\n"
            b"#include <capstone/platform.h>\n\n"
            b"test_output",
            filename=Path("filename"),
        )

    def test_inlinetostaticinline(self):
        patch = InlineToStaticInline(0)
        syntax = b"inline void FUNCTION() {}"
        self.check_patching_result(
            patch,
            syntax,
            b"static inline void FUNCTION() {}",
        )

    def test_isoptionaldef(self):
        patch = IsOptionalDef(0)
        syntax = b"OpInfo[i].isOptionalDef()"
        self.check_patching_result(
            patch,
            syntax,
            b"MCOperandInfo_isOptionalDef(&OpInfo[i])",
        )

    def test_ispredicate(self):
        patch = IsPredicate(0)
        syntax = b"OpInfo[i].isPredicate()"
        self.check_patching_result(
            patch,
            syntax,
            b"MCOperandInfo_isPredicate(&OpInfo[i])",
        )

    def test_isreg(self):
        patch = IsOperandRegImm(0)
        syntax = b"OPERAND.isReg()"
        self.check_patching_result(patch, syntax, b"MCOperand_isReg(OPERAND)")

    def test_isimm(self):
        patch = IsOperandRegImm(0)
        syntax = b"OPERAND.isImm()"
        self.check_patching_result(patch, syntax, b"MCOperand_isImm(OPERAND)")

    def test_isexpr(self):
        patch = IsOperandRegImm(0)
        syntax = b"OPERAND.isExpr()"
        self.check_patching_result(patch, syntax, b"MCOperand_isExpr(OPERAND)")

    def test_llvmfallthrough(self):
        patch = LLVMFallThrough(0)
        syntax = b"LLVM_FALLTHROUGH;"
        self.check_patching_result(patch, syntax, b"")

    def test_llvmunreachable(self):
        patch = LLVMUnreachable(0)
        syntax = b'llvm_unreachable("Error msg")'
        self.check_patching_result(patch, syntax, b'CS_ASSERT(0 && "Error msg")')

    def test_llvmdebug(self):
        patch = LLVM_DEBUG(0)
        syntax = b'LLVM_DEBUG(dbgs() << "Error msg")'
        self.check_patching_result(patch, syntax, b"")

    def test_methodtofunctions(self):
        patch = MethodToFunction(0)
        syntax = b"void CLASS::METHOD_NAME(int a) {}"
        self.check_patching_result(patch, syntax, b"METHOD_NAME(int a)")

    def test_methodtypequalifier(self):
        patch = MethodTypeQualifier(0)
        syntax = b"void a_const_method() const {}"
        self.check_patching_result(patch, syntax, b"a_const_method()")

    def test_namespaceanon(self):
        patch = NamespaceAnon(0)
        syntax = b"namespace { int a = 0; }"
        self.check_patching_result(patch, syntax, b" int a = 0; ")

    def test_namespacearch(self):
        patch = NamespaceArch(0)
        syntax = b"namespace ArchSpecificNamespace { int a = 0; }"
        self.check_patching_result(
            patch,
            syntax,
            b"// CS namespace begin: ArchSpecificNamespace\n\n"
            b"int a = 0;\n\n"
            b"// CS namespace end: ArchSpecificNamespace\n\n",
        )

    def test_namespacellvm(self):
        patch = NamespaceLLVM(0)
        syntax = b"namespace llvm {int a = 0}"
        self.check_patching_result(patch, syntax, b"int a = 0")

    def test_outstreamparam(self):
        patch = OutStreamParam(0)
        syntax = b"void function(int a, raw_ostream &OS);"
        self.check_patching_result(patch, syntax, b"(int a, SStream *OS)")

    def test_override(self):
        patch = Override(0)
        syntax = b"class a { void function(int a) override; };"
        self.check_patching_result(patch, syntax, b"function(int a)")

    def test_predicateblockfunctions(self):
        patch = PredicateBlockFunctions(0)
        syntax = b"void function(MCInst *MI) { VPTBlock.instrInVPTBlock(); }"
        self.check_patching_result(
            patch,
            syntax,
            b"VPTBlock_instrInVPTBlock(&(MI->csh->VPTBlock))",
        )

    def test_predicateblockfunctions(self):
        patch = PrintAnnotation(0)
        syntax = b"printAnnotation();"
        self.check_patching_result(patch, syntax, b"")

    def test_printregimmshift(self):
        patch = PrintRegImmShift(0)
        syntax = b"printRegImmShift(0)"
        self.check_patching_result(patch, syntax, b"printRegImmShift(Inst, 0)")

    def test_qualifiedidentifier(self):
        patch = QualifiedIdentifier(0)
        syntax = b"NAMESPACE::ID"
        self.check_patching_result(patch, syntax, b"NAMESPACE_ID")

    def test_referencesdecl(self):
        patch = ReferencesDecl(0)
        syntax = b"int &Param = 0;"
        self.check_patching_result(patch, syntax, b"*Param")

    def test_regclasscontains(self):
        patch = RegClassContains(0)
        syntax = b"if (MRI.getRegClass(AArch64::GPR32RegClassID).contains(Reg)) {}"
        self.check_patching_result(
            patch,
            syntax,
            b"MCRegisterClass_contains(MRI.getRegClass(AArch64::GPR32RegClassID), Reg)",
        )

    def test_setopcode(self):
        patch = SetOpcode(0)
        syntax = b"Inst.setOpcode(0)"
        self.check_patching_result(patch, syntax, b"MCInst_setOpcode(Inst, (0))")

    def test_signextend(self):
        patch = SignExtend(0)
        syntax = b"SignExtend32<A>(0)"
        self.check_patching_result(patch, syntax, b"SignExtend32((0), A)")

    def test_size(self):
        patch = Size(0)
        syntax = b"Bytes.size()"
        self.check_patching_result(patch, syntax, b"BytesLen")

    def test_sizeassignments(self):
        patch = SizeAssignment(0)
        syntax = b"void function(int &Size) { Size = 0; }"
        self.check_patching_result(patch, syntax, b"*Size = 0")

    def test_stiargument(self):
        patch = STIArgument(0)
        syntax = b"printSomeOperand(MI, NUM, STI, NUM)"
        self.check_patching_result(patch, syntax, b"(MI, NUM, NUM)")

    def test_stifeaturebits(self):
        patch = STIFeatureBits(0, b"ARCH")
        syntax = b"STI.getFeatureBits()[ARCH::FLAG];"
        self.check_patching_result(
            patch,
            syntax,
            b"ARCH_getFeatureBits(Inst->csh->mode, ARCH::FLAG)",
        )

    def test_streamoperation(self):
        patch = StreamOperations(0)
        syntax = b"{ OS << 'a'; }"
        self.check_patching_result(patch, syntax, b'SStream_concat0(OS, "a");\n')

        syntax = b'{ OS << "aaaa" << "bbbb" << "cccc"; }'
        self.check_patching_result(
            patch,
            syntax,
            b'SStream_concat(OS, "%s%s", "aaaa", "bbbb");\nSStream_concat0(OS, "cccc");',
        )

        syntax = b'{ OS << "aaaa" << \'a\' << "cccc"; }'
        self.check_patching_result(
            patch,
            syntax,
            b'SStream_concat(OS, "%s", "aaaa");\n'
            b"SStream_concat1(OS, 'a');\n"
            b'SStream_concat0(OS, "cccc");',
        )

        syntax = b"{ int y = 1; int x = 1; OS << x; }"
        self.check_patching_result(patch, syntax, b"printInt32(OS, x);")

    def test_templatedeclaration(self):
        patch = TemplateDeclaration(0, self.template_collector)
        syntax = b"template<A, B> void tfunction();"
        self.check_patching_result(
            patch,
            syntax,
            b"#define DECLARE_tfunction(A, B) \\\n"
            b"  void CONCAT(tfunction, CONCAT(A, B))();\n"
            b"DECLARE_tfunction(int, int);\n"
            b"DECLARE_tfunction(int, char);\n",
        )

    def test_templatedefinition(self):
        patch = TemplateDefinition(0, self.template_collector)
        syntax = b"template<A, B> void tfunction() {}"
        self.check_patching_result(
            patch,
            syntax,
            b"#define DEFINE_tfunction(A, B) \\\n"
            b"  void CONCAT(tfunction, CONCAT(A, B))(){}\n"
            b"DEFINE_tfunction(int, int);\n"
            b"DEFINE_tfunction(int, char);\n",
        )

    def test_templateparamdecl(self):
        patch = TemplateParamDecl(0)
        syntax = b"void function(ArrayRef<uint8_t> x);"
        self.check_patching_result(patch, syntax, b"const uint8_t *x, size_t xLen")

    def test_templaterefs(self):
        patch = TemplateRefs(0)
        syntax = b"TemplateFunction<A, B>();"
        self.check_patching_result(
            patch,
            syntax,
            b"CONCAT(TemplateFunction, CONCAT(A, B))",
        )

    def test_usemarkup(self):
        patch = UseMarkup(0)
        syntax = b"UseMarkup()"
        self.check_patching_result(patch, syntax, b"getUseMarkup()")

    def test_usingdecl(self):
        patch = UsingDeclaration(0)
        syntax = b"using namespace llvm;"
        self.check_patching_result(patch, syntax, b"")

    def test_isuintn(self):
        patch = IsUInt(0)
        syntax = b"isUInt<RegUnitBits>(FirstRU);"
        self.check_patching_result(patch, syntax, b"isUIntN(RegUnitBits, FirstRU)")

    def test_badconditioncode(self):
        patch = BadConditionCode(0)
        syntax = b"return BadConditionCode(BRCC)"
        self.check_patching_result(
            patch, syntax, b'CS_ASSERT(0 && "Unknown condition code passed");'
        )
