#!/usr/bin/env python3

# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3
# SPDX-License-Identifier: LGPL-3.0-only

import unittest

from tree_sitter import Node, Query

import autosync.cpptranslator.patches as Patches
from autosync.cpptranslator import CppTranslator

from autosync.cpptranslator.Configurator import Configurator
from autosync.cpptranslator.TemplateCollector import TemplateCollector
from autosync.Helper import get_path


class TestPatches(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configurator = Configurator("ARCH", get_path("{CPP_TRANSLATOR_TEST_CONFIG}"))
        cls.translator = CppTranslator.Translator(configurator)
        cls.ts_cpp_lang = configurator.get_cpp_lang()
        cls.parser = configurator.get_parser()
        cls.template_collector = TemplateCollector(
            configurator.get_parser(), configurator.get_cpp_lang(), [], []
        )

    def check_patching_result(self, patch, syntax, expected, filename=""):
        if filename:
            kwargs = {"filename": filename}
        else:
            kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)

        self.assertGreater(len(captures_bundle), 0)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), expected)

    def test_addcsdetail(self):
        patch = Patches.AddCSDetail.AddCSDetail(0, "ARCH")
        syntax = b"int i = x; void printThumbLdrLabelOperand(MCInst *MI, unsigned OpNo, SStream *O) { int i = OpNo; }"
        self.check_patching_result(
            patch,
            syntax,
            b"void printThumbLdrLabelOperand(MCInst *MI, unsigned OpNo, SStream *O){ "
            b"add_cs_detail(MI, ARCH_OP_GROUP_ThumbLdrLabelOperand, OpNo); "
            b"int i = OpNo; "
            b"}",
        )

    def test_addoperand(self):
        patch = Patches.AddOperand.AddOperand(0)
        syntax = b"MI.addOperand(OPERAND)"
        self.check_patching_result(
            patch,
            syntax,
            b"MCInst_addOperand2(MI, (OPERAND))",
        )

    def test_assert(self):
        patch = Patches.Assert.Assert(0)
        syntax = b"assert(0 == 0)"
        self.check_patching_result(patch, syntax, b"")

    def test_bitcaststdarray(self):
        patch = Patches.BitCastStdArray.BitCastStdArray(0)
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
        patch = Patches.CheckDecoderStatus.CheckDecoderStatus(0)
        syntax = b"Check(S, functions())"
        self.check_patching_result(patch, syntax, b"Check(&S, functions())")

    def test_classesdef(self):
        patch = Patches.ClassesDef.ClassesDef(0)
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
        patch = Patches.ConstMCInstParameter.ConstMCInstParameter(0)
        syntax = b"void function(const MCInst *MI);"
        expected = b"MCInst *MI"
        self.check_patching_result(patch, syntax, expected)

    def test_constmcoperand(self):
        patch = Patches.ConstMCOperand.ConstMCOperand(0)
        syntax = b"const MCOperand op = { 0 };"
        self.check_patching_result(patch, syntax, b"MCOperand op = { 0 };")

    def test_cppinitcast(self):
        patch = Patches.CppInitCast.CppInitCast(0)
        syntax = b"int(0x0000)"
        self.check_patching_result(patch, syntax, b"((int)(0x0000))")

    def test_createoperand0(self):
        patch = Patches.CreateOperand0.CreateOperand0(0)
        syntax = b"Inst.addOperand(MCOperand::createReg(REGISTER));"
        self.check_patching_result(
            patch,
            syntax,
            b"MCOperand_CreateReg0(Inst, (REGISTER))",
        )

    def test_createoperand1(self):
        patch = Patches.CreateOperand1.CreateOperand1(0)
        syntax = b"MI.insert(I, MCOperand::createReg(REGISTER));"
        self.check_patching_result(
            patch,
            syntax,
            b"MCInst_insert0(MI, I, MCOperand_CreateReg1(MI, (REGISTER)))",
        )

    def test_declarationinconditionclause(self):
        patch = Patches.DeclarationInConditionClause.DeclarationInConditionalClause(0)
        syntax = b"if (int i = 0) {}"
        self.check_patching_result(patch, syntax, b"int i = 0;\nif (i)\n{}")

    def test_decodeinstruction(self):
        patch = Patches.DecodeInstruction.DecodeInstruction(0)
        syntax = (
            b"decodeInstruction(DecoderTableThumb16, MI, Insn16, Address, this, STI);"
        )
        self.check_patching_result(
            patch,
            syntax,
            b"decodeInstruction_2(DecoderTableThumb16,  MI,  Insn16,  Address)",
        )

        syntax = b"decodeInstruction(Table[i], MI, Insn16, Address, this, STI);"
        self.check_patching_result(
            patch,
            syntax,
            b"decodeInstruction_2(Table[i],  MI,  Insn16,  Address)",
        )

    def test_decodercast(self):
        patch = Patches.DecoderCast.DecoderCast(0)
        syntax = (
            b"const MCDisassembler *Dis = static_cast<const MCDisassembler*>(Decoder);"
        )
        self.check_patching_result(patch, syntax, b"")

    def test_decoderparameter(self):
        patch = Patches.DecoderParameter.DecoderParameter(0)
        syntax = b"void function(const MCDisassembler *Decoder);"
        self.check_patching_result(patch, syntax, b"const void *Decoder")

    def test_fallthrough(self):
        patch = Patches.FallThrough.FallThrough(0)
        syntax = b"[[fallthrough]]"
        self.check_patching_result(patch, syntax, b"// fall through")

    def test_featurebitsdecl(self):
        patch = Patches.FeatureBitsDecl.FeatureBitsDecl(0)
        syntax = b"const FeatureBitset &FeatureBits = ((const MCDisassembler*)Decoder)->getSubtargetInfo().getFeatureBits();"
        self.check_patching_result(patch, syntax, b"")

    def test_featurebits(self):
        patch = Patches.FeatureBits.FeatureBits(0, b"ARCH")
        syntax = b"bool hasD32 = featureBits[ARCH::HasV8Ops];"
        self.check_patching_result(
            patch,
            syntax,
            b"ARCH_getFeatureBits(Inst->csh->mode, ARCH::HasV8Ops)",
        )

    def test_fieldfrominstr(self):
        patch = Patches.FieldFromInstr.FieldFromInstr(0)
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

    def test_getnumoperands(self):
        patch = Patches.GetNumOperands.GetNumOperands(0)
        syntax = b"MI.getNumOperands();"
        self.check_patching_result(patch, syntax, b"MCInst_getNumOperands(MI)")

    def test_getopcode(self):
        patch = Patches.GetOpcode.GetOpcode(0)
        syntax = b"Inst.getOpcode();"
        self.check_patching_result(patch, syntax, b"MCInst_getOpcode(Inst)")

    def test_getoperand(self):
        patch = Patches.GetOperand.GetOperand(0)
        syntax = b"MI.getOperand(0);"
        self.check_patching_result(patch, syntax, b"MCInst_getOperand(MI, (0))")

    def test_getoperandregimm(self):
        patch = Patches.GetOperandRegImm.GetOperandRegImm(0)
        syntax = b"OPERAND.getReg()"
        self.check_patching_result(patch, syntax, b"MCOperand_getReg(OPERAND)")

    def test_getregclass(self):
        patch = Patches.GetRegClass.GetRegClass(0)
        syntax = b"MRI.getRegClass(RegClass);"
        expected = b"MCRegisterInfo_getRegClass(Inst->MRI, RegClass)"
        self.check_patching_result(patch, syntax, expected)

    def test_getregfromclass(self):
        patch = Patches.GetRegFromClass.GetRegFromClass(0)
        syntax = b"ARCHMCRegisterClasses[ARCH::FPR128RegClassID].getRegister(RegNo);"
        self.check_patching_result(
            patch,
            syntax,
            b"ARCHMCRegisterClasses[ARCH::FPR128RegClassID].RegsBegin[RegNo]",
        )

    def test_getsubreg(self):
        patch = Patches.GetSubReg.GetSubReg(0)
        syntax = b"MRI.getSubReg(REGISTER);"
        self.check_patching_result(
            patch,
            syntax,
            b"MCRegisterInfo_getSubReg(Inst->MRI, REGISTER)",
        )

    def test_includes(self):
        patch = Patches.Includes.Includes(0, "TEST_ARCH")
        syntax = b'#include "some_llvm_header.h"'
        self.check_patching_result(
            patch,
            syntax,
            b"#include <stdio.h>\n"
            b"#include <string.h>\n"
            b"#include <stdlib.h>\n"
            b"#include <capstone/platform.h>\n\n"
            b"test_output",
            "filename",
        )

    def test_inlinetostaticinline(self):
        patch = Patches.InlineToStaticInline.InlineToStaticInline(0)
        syntax = b"inline void FUNCTION() {}"
        self.check_patching_result(
            patch,
            syntax,
            b"static inline void FUNCTION() {}",
        )

    def test_isoptionaldef(self):
        patch = Patches.IsOptionalDef.IsOptionalDef(0)
        syntax = b"OpInfo[i].isOptionalDef()"
        self.check_patching_result(
            patch,
            syntax,
            b"MCOperandInfo_isOptionalDef(&OpInfo[i])",
        )

    def test_ispredicate(self):
        patch = Patches.IsPredicate.IsPredicate(0)
        syntax = b"OpInfo[i].isPredicate()"
        self.check_patching_result(
            patch,
            syntax,
            b"MCOperandInfo_isPredicate(&OpInfo[i])",
        )

    def test_isregimm(self):
        patch = Patches.IsRegImm.IsOperandRegImm(0)
        syntax = b"OPERAND.isReg()"
        self.check_patching_result(patch, syntax, b"MCOperand_isReg(OPERAND)")

    def test_llvmfallthrough(self):
        patch = Patches.LLVMFallThrough.LLVMFallThrough(0)
        syntax = b"LLVM_FALLTHROUGH;"
        self.check_patching_result(patch, syntax, b"")

    def test_llvmunreachable(self):
        patch = Patches.LLVMunreachable.LLVMUnreachable(0)
        syntax = b'llvm_unreachable("Error msg")'
        self.check_patching_result(patch, syntax, b'assert(0 && "Error msg")')

    def test_methodtofunctions(self):
        patch = Patches.MethodToFunctions.MethodToFunction(0)
        syntax = b"void CLASS::METHOD_NAME(int a) {}"
        self.check_patching_result(patch, syntax, b"METHOD_NAME(int a)")

    def test_methodtypequalifier(self):
        patch = Patches.MethodTypeQualifier.MethodTypeQualifier(0)
        syntax = b"void a_const_method() const {}"
        self.check_patching_result(patch, syntax, b"a_const_method()")

    def test_namespaceanon(self):
        patch = Patches.NamespaceAnon.NamespaceAnon(0)
        syntax = b"namespace { int a = 0; }"
        self.check_patching_result(patch, syntax, b" int a = 0; ")

    def test_namespacearch(self):
        patch = Patches.NamespaceArch.NamespaceArch(0)
        syntax = b"namespace ArchSpecificNamespace { int a = 0; }"
        self.check_patching_result(
            patch,
            syntax,
            b"// CS namespace begin: ArchSpecificNamespace\n\n"
            b"int a = 0;\n\n"
            b"// CS namespace end: ArchSpecificNamespace\n\n",
        )

    def test_namespacellvm(self):
        patch = Patches.NamespaceLLVM.NamespaceLLVM(0)
        syntax = b"namespace llvm {int a = 0}"
        self.check_patching_result(patch, syntax, b"int a = 0")

    def test_outstreamparam(self):
        patch = Patches.OutStreamParam.OutStreamParam(0)
        syntax = b"void function(int a, raw_ostream &OS);"
        self.check_patching_result(patch, syntax, b"(int a, SStream *OS)")

    def test_predicateblockfunctions(self):
        patch = Patches.PredicateBlockFunctions.PredicateBlockFunctions(0)
        syntax = b"void function(MCInst *MI) { VPTBlock.instrInVPTBlock(); }"
        self.check_patching_result(
            patch,
            syntax,
            b"VPTBlock_instrInVPTBlock(&(MI->csh->VPTBlock))",
        )

    def test_predicateblockfunctions(self):
        patch = Patches.PrintAnnotation.PrintAnnotation(0)
        syntax = b"printAnnotation();"
        self.check_patching_result(patch, syntax, b"")

    def test_printregimmshift(self):
        patch = Patches.PrintRegImmShift.PrintRegImmShift(0)
        syntax = b"printRegImmShift(0)"
        self.check_patching_result(patch, syntax, b"printRegImmShift(Inst, 0)")

    def test_qualifiedidentifier(self):
        patch = Patches.QualifiedIdentifier.QualifiedIdentifier(0)
        syntax = b"NAMESPACE::ID"
        self.check_patching_result(patch, syntax, b"NAMESPACE_ID")

    def test_referencesdecl(self):
        patch = Patches.ReferencesDecl.ReferencesDecl(0)
        syntax = b"int &Param = 0;"
        self.check_patching_result(patch, syntax, b"*Param")

    def test_regclasscontains(self):
        patch = Patches.RegClassContains.RegClassContains(0)
        syntax = b"if (MRI.getRegClass(AArch64::GPR32RegClassID).contains(Reg)) {}"
        self.check_patching_result(
            patch,
            syntax,
            b"MCRegisterClass_contains(MRI.getRegClass(AArch64::GPR32RegClassID), Reg)",
        )

    def test_setopcode(self):
        patch = Patches.SetOpcode.SetOpcode(0)
        syntax = b"Inst.setOpcode(0)"
        self.check_patching_result(patch, syntax, b"MCInst_setOpcode(Inst, (0))")

    def test_signextend(self):
        patch = Patches.SignExtend.SignExtend(0)
        syntax = b"SignExtend32<A>(0)"
        self.check_patching_result(patch, syntax, b"SignExtend32((0), A)")

    def test_sizeassignments(self):
        patch = Patches.SizeAssignments.SizeAssignment(0)
        syntax = b"void function(int &Size) { Size = 0; }"
        self.check_patching_result(patch, syntax, b"*Size = 0")

    def test_stiargument(self):
        patch = Patches.STIArgument.STIArgument(0)
        syntax = b"printSomeOperand(MI, NUM, STI, NUM)"
        self.check_patching_result(patch, syntax, b"(MI, NUM, NUM)")

    def test_stifeaturebits(self):
        patch = Patches.STIFeatureBits.STIFeatureBits(0, b"ARCH")
        syntax = b"STI.getFeatureBits()[ARCH::FLAG];"
        self.check_patching_result(
            patch,
            syntax,
            b"ARCH_getFeatureBits(Inst->csh->mode, ARCH::FLAG)",
        )

    def test_stifeaturebits(self):
        patch = Patches.STParameter.SubtargetInfoParam(0)
        syntax = b"void function(MCSubtargetInfo &STI);"
        self.check_patching_result(patch, syntax, b"()")

    def test_streamoperation(self):
        patch = Patches.StreamOperation.StreamOperations(0)
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

    def test_templatedeclaration(self):
        patch = Patches.TemplateDeclaration.TemplateDeclaration(
            0, self.template_collector
        )
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
        patch = Patches.TemplateDefinition.TemplateDefinition(
            0, self.template_collector
        )
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
        patch = Patches.TemplateParamDecl.TemplateParamDecl(0)
        syntax = b"void function(ArrayRef<uint8_t> x);"
        self.check_patching_result(patch, syntax, b"const uint8_t *x")

    def test_templaterefs(self):
        patch = Patches.TemplateRefs.TemplateRefs(0)
        syntax = b"TemplateFunction<A, B>();"
        self.check_patching_result(
            patch,
            syntax,
            b"CONCAT(TemplateFunction, CONCAT(A, B))",
        )

    def test_usemarkup(self):
        patch = Patches.UseMarkup.UseMarkup(0)
        syntax = b"UseMarkup()"
        self.check_patching_result(patch, syntax, b"getUseMarkup()")

    def test_usingdecl(self):
        patch = Patches.UsingDeclaration.UsingDeclaration(0)
        syntax = b"using namespace llvm;"
        self.check_patching_result(patch, syntax, b"")
