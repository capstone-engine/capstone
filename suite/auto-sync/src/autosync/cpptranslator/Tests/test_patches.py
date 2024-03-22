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

    def test_addcsdetail(self):
        patch = Patches.AddCSDetail.AddCSDetail(0, "ARCH")
        syntax = b"int i = x; void printThumbLdrLabelOperand(MCInst *MI, unsigned OpNo, SStream *O) { int i = OpNo; }"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                (
                    b"void printThumbLdrLabelOperand(MCInst *MI, unsigned OpNo, SStream *O){ "
                    b"add_cs_detail(MI, ARCH_OP_GROUP_ThumbLdrLabelOperand, OpNo); "
                    b"int i = OpNo; "
                    b"}"
                ),
            )

    def test_addoperand(self):
        patch = Patches.AddOperand.AddOperand(0)
        syntax = b"MI.addOperand(OPERAND)"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                b"MCInst_addOperand2(MI, (OPERAND))",
            )

    def test_assert(self):
        patch = Patches.Assert.Assert(0)
        syntax = b"assert(0 == 0)"
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
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_bitcaststdarray(self):
        patch = Patches.BitCastStdArray.BitCastStdArray(0)
        syntax = b"auto S = bit_cast<std::array<int32_t, 2>>(Imm);"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                (
                    b"union {\n"
                    b"    typeof(Imm) In;\n"
                    b"    int32_t Out[ 2];\n"
                    b"} U_S;\n"
                    b"U_S.In = Imm"
                    b";\n"
                    b"int32_t *S = U_S.Out;"
                ),
            )

    def test_checkdecoderstatus(self):
        patch = Patches.CheckDecoderStatus.CheckDecoderStatus(0)
        syntax = b"Check(S, functions())"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs), b"Check(&S, functions())"
            )

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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                (
                    b"MCDisassembler::DecodeStatus\n"
                    b"  getInstruction(MCInst &Instr, uint64_t &Size, ArrayRef<uint8_t> Bytes,\n"
                    b"                 uint64_t Address, raw_ostream &CStream) const override;\n"
                    b"uint64_t suggestBytesToSkip(ArrayRef<uint8_t> Bytes,\n"
                    b"                              uint64_t Address) const override;\n"
                ),
            )

    def test_constmcinstparameter(self):
        patch = Patches.ConstMCInstParameter.ConstMCInstParameter(0)
        syntax = b"void function(const MCInst *MI);"
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
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"MCInst *MI")

    def test_constmcoperand(self):
        patch = Patches.ConstMCOperand.ConstMCOperand(0)
        syntax = b"const MCOperand op = { 0 };"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs), b"MCOperand op = { 0 };"
            )

    def test_cppinitcast(self):
        patch = Patches.CppInitCast.CppInitCast(0)
        syntax = b"int(0x0000)"
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
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"((int)(0x0000))")

    def test_createoperand0(self):
        patch = Patches.CreateOperand0.CreateOperand0(0)
        syntax = b"Inst.addOperand(MCOperand::createReg(REGISTER));"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                b"MCOperand_CreateReg0(Inst, (REGISTER))",
            )

    def test_createoperand1(self):
        patch = Patches.CreateOperand1.CreateOperand1(0)
        syntax = b"MI.insert(I, MCOperand::createReg(REGISTER));"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                b"MCInst_insert0(MI, I, MCOperand_CreateReg1(MI, (REGISTER)))",
            )

    def test_declarationinconditionclause(self):
        patch = Patches.DeclarationInConditionClause.DeclarationInConditionalClause(0)
        syntax = b"if (int i = 0) {}"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs), b"int i = 0;\nif (i)\n{}"
            )

    def test_decodeinstruction(self):
        patch = Patches.DecodeInstruction.DecodeInstruction(0)
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        syntax = (
            b"decodeInstruction(DecoderTableThumb16, MI, Insn16, Address, this, STI);"
        )
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        self.assertGreater(len(captures_bundle), 0)
        for cb in captures_bundle:
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                b"decodeInstruction_2(DecoderTableThumb16,  MI,  Insn16,  Address)",
            )

        syntax = b"decodeInstruction(Table[i], MI, Insn16, Address, this, STI);"
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        self.assertGreater(len(captures_bundle), 0)
        for cb in captures_bundle:
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                b"decodeInstruction_2(Table[i],  MI,  Insn16,  Address)",
            )

    def test_decodercast(self):
        patch = Patches.DecoderCast.DecoderCast(0)
        syntax = (
            b"const MCDisassembler *Dis = static_cast<const MCDisassembler*>(Decoder);"
        )
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
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_decoderparameter(self):
        patch = Patches.DecoderParameter.DecoderParameter(0)
        syntax = b"void function(const MCDisassembler *Decoder);"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs), b"const void *Decoder"
            )

    def test_fallthrough(self):
        patch = Patches.FallThrough.FallThrough(0)
        syntax = b"[[fallthrough]]"
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
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"// fall through")

    def test_featurebitsdecl(self):
        patch = Patches.FeatureBitsDecl.FeatureBitsDecl(0)
        syntax = b"const FeatureBitset &FeatureBits = ((const MCDisassembler*)Decoder)->getSubtargetInfo().getFeatureBits();"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        ast = self.parser.parse(syntax, keep_text=True)
        for q in query.captures(ast.root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        self.assertGreater(len(captures_bundle), 0)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_featurebits(self):
        patch = Patches.FeatureBits.FeatureBits(0, b"ARCH")
        syntax = b"bool hasD32 = featureBits[ARCH::HasV8Ops];"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                b"ARCH_getFeatureBits(Inst->csh->mode, ARCH::HasV8Ops)",
            )

    def test_fieldfrominstr(self):
        patch = Patches.FieldFromInstr.FieldFromInstr(0)
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        syntax = b"unsigned Rm = fieldFromInstruction(Inst16, 0, 4);"
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        self.assertGreater(len(captures_bundle), 0)
        for cb in captures_bundle:
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                b"fieldFromInstruction_2(Inst16, 0, 4)",
            )

        syntax = b"void function(MCInst *MI, unsigned Val) { unsigned Rm = fieldFromInstruction(Val, 0, 4); }"
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        self.assertGreater(len(captures_bundle), 0)
        for cb in captures_bundle:
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                b"fieldFromInstruction_4(Val, 0, 4)",
            )

    def test_getnumoperands(self):
        patch = Patches.GetNumOperands.GetNumOperands(0)
        syntax = b"MI.getNumOperands();"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs), b"MCInst_getNumOperands(MI)"
            )

    def test_getopcode(self):
        patch = Patches.GetOpcode.GetOpcode(0)
        syntax = b"Inst.getOpcode();"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs), b"MCInst_getOpcode(Inst)"
            )

    def test_getoperand(self):
        patch = Patches.GetOperand.GetOperand(0)
        syntax = b"MI.getOperand(0);"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs), b"MCInst_getOperand(MI, (0))"
            )

    def test_getoperandregimm(self):
        patch = Patches.GetOperandRegImm.GetOperandRegImm(0)
        syntax = b"OPERAND.getReg()"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs), b"MCOperand_getReg(OPERAND)"
            )

    def test_getregclass(self):
        patch = Patches.GetRegClass.GetRegClass(0)
        syntax = b"MRI.getRegClass(RegClass);"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                b"MCRegisterInfo_getRegClass(Inst->MRI, RegClass)",
            )

    def test_getregfromclass(self):
        patch = Patches.GetRegFromClass.GetRegFromClass(0)
        syntax = b"ARCHMCRegisterClasses[ARCH::FPR128RegClassID].getRegister(RegNo);"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                b"ARCHMCRegisterClasses[ARCH::FPR128RegClassID].RegsBegin[RegNo]",
            )

    def test_getsubreg(self):
        patch = Patches.GetSubReg.GetSubReg(0)
        syntax = b"MRI.getSubReg(REGISTER);"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                b"MCRegisterInfo_getSubReg(Inst->MRI, REGISTER)",
            )

    def test_includes(self):
        patch = Patches.Includes.Includes(0, "TEST_ARCH")
        syntax = b'#include "some_llvm_header.h"'
        kwargs = {"filename": "test_filename"}
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        self.assertGreater(len(captures_bundle), 0)
        for cb in captures_bundle:
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                (
                    b"#include <stdio.h>\n"
                    b"#include <string.h>\n"
                    b"#include <stdlib.h>\n"
                    b"#include <capstone/platform.h>\n\n"
                    b"test_output"
                ),
            )

    def test_inlinetostaticinline(self):
        patch = Patches.InlineToStaticInline.InlineToStaticInline(0)
        syntax = b"inline void FUNCTION() {}"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                b"static inline void FUNCTION() {}",
            )

    def test_isoptionaldef(self):
        patch = Patches.IsOptionalDef.IsOptionalDef(0)
        syntax = b"OpInfo[i].isOptionalDef()"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                b"MCOperandInfo_isOptionalDef(&OpInfo[i])",
            )

    def test_ispredicate(self):
        patch = Patches.IsPredicate.IsPredicate(0)
        syntax = b"OpInfo[i].isPredicate()"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                b"MCOperandInfo_isPredicate(&OpInfo[i])",
            )

    def test_isregimm(self):
        patch = Patches.IsRegImm.IsOperandRegImm(0)
        syntax = b"OPERAND.isReg()"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs), b"MCOperand_isReg(OPERAND)"
            )

    def test_llvmfallthrough(self):
        patch = Patches.LLVMFallThrough.LLVMFallThrough(0)
        syntax = b"LLVM_FALLTHROUGH;"
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
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_llvmunreachable(self):
        patch = Patches.LLVMunreachable.LLVMUnreachable(0)
        syntax = b'llvm_unreachable("Error msg")'
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs), b'assert(0 && "Error msg")'
            )

    def test_methodtofunctions(self):
        patch = Patches.MethodToFunctions.MethodToFunction(0)
        syntax = b"void CLASS::METHOD_NAME(int a) {}"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs), b"METHOD_NAME(int a)"
            )

    def test_methodtypequalifier(self):
        patch = Patches.MethodTypeQualifier.MethodTypeQualifier(0)
        syntax = b"void a_const_method() const {}"
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
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"a_const_method()")

    def test_namespaceanon(self):
        patch = Patches.NamespaceAnon.NamespaceAnon(0)
        syntax = b"namespace { int a = 0; }"
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
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b" int a = 0; ")

    def test_namespacearch(self):
        patch = Patches.NamespaceArch.NamespaceArch(0)
        syntax = b"namespace ArchSpecificNamespace { int a = 0; }"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                (
                    b"// CS namespace begin: ArchSpecificNamespace\n\n"
                    b"int a = 0;\n\n"
                    b"// CS namespace end: ArchSpecificNamespace\n\n"
                ),
            )

    def test_namespacellvm(self):
        patch = Patches.NamespaceLLVM.NamespaceLLVM(0)
        syntax = b"namespace llvm {int a = 0}"
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
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"int a = 0")

    def test_outstreamparam(self):
        patch = Patches.OutStreamParam.OutStreamParam(0)
        syntax = b"void function(int a, raw_ostream &OS);"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs), b"(int a, SStream *OS)"
            )

    def test_predicateblockfunctions(self):
        patch = Patches.PredicateBlockFunctions.PredicateBlockFunctions(0)
        syntax = b"void function(MCInst *MI) { VPTBlock.instrInVPTBlock(); }"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                b"VPTBlock_instrInVPTBlock(&(MI->csh->VPTBlock))",
            )

    def test_predicateblockfunctions(self):
        patch = Patches.PrintAnnotation.PrintAnnotation(0)
        syntax = b"printAnnotation();"
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
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_printregimmshift(self):
        patch = Patches.PrintRegImmShift.PrintRegImmShift(0)
        syntax = b"printRegImmShift(0)"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs), b"printRegImmShift(Inst, 0)"
            )

    def test_qualifiedidentifier(self):
        patch = Patches.QualifiedIdentifier.QualifiedIdentifier(0)
        syntax = b"NAMESPACE::ID"
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
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"NAMESPACE_ID")

    def test_referencesdecl(self):
        patch = Patches.ReferencesDecl.ReferencesDecl(0)
        syntax = b"int &Param = 0;"
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
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"*Param")

    def test_regclasscontains(self):
        patch = Patches.RegClassContains.RegClassContains(0)
        syntax = b"if (MRI.getRegClass(AArch64::GPR32RegClassID).contains(Reg)) {}"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                b"MCRegisterClass_contains(MRI.getRegClass(AArch64::GPR32RegClassID), Reg)",
            )

    def test_setopcode(self):
        patch = Patches.SetOpcode.SetOpcode(0)
        syntax = b"Inst.setOpcode(0)"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs), b"MCInst_setOpcode(Inst, (0))"
            )

    def test_signextend(self):
        patch = Patches.SignExtend.SignExtend(0)
        syntax = b"SignExtend32<A>(0)"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs), b"SignExtend32((0), A)"
            )

    def test_sizeassignments(self):
        patch = Patches.SizeAssignments.SizeAssignment(0)
        syntax = b"void function(int &Size) { Size = 0; }"
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
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"*Size = 0")

    def test_stiargument(self):
        patch = Patches.STIArgument.STIArgument(0)
        syntax = b"printSomeOperand(MI, NUM, STI, NUM)"
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
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"(MI, NUM, NUM)")

    def test_stifeaturebits(self):
        patch = Patches.STIFeatureBits.STIFeatureBits(0, b"ARCH")
        syntax = b"STI.getFeatureBits()[ARCH::FLAG];"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                b"ARCH_getFeatureBits(Inst->csh->mode, ARCH::FLAG)",
            )

    def test_stifeaturebits(self):
        patch = Patches.STParameter.SubtargetInfoParam(0)
        syntax = b"void function(MCSubtargetInfo &STI);"
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
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"()")

    def test_streamoperation(self):
        patch = Patches.StreamOperation.StreamOperations(0)
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        syntax = b"{ OS << 'a'; }"
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        self.assertGreater(len(captures_bundle), 0)
        for cb in captures_bundle:
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs), b'SStream_concat0(OS, "a");\n'
            )

        syntax = b'{ OS << "aaaa" << "bbbb" << "cccc"; }'
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        self.assertGreater(len(captures_bundle), 0)
        for cb in captures_bundle:
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                (
                    b'SStream_concat(OS, "%s%s", "aaaa", "bbbb");\nSStream_concat0(OS, "cccc");'
                ),
            )

        syntax = b'{ OS << "aaaa" << \'a\' << "cccc"; }'
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        self.assertGreater(len(captures_bundle), 0)
        for cb in captures_bundle:
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                (
                    b'SStream_concat(OS, "%s", "aaaa");\n'
                    b"SStream_concat1(OS, 'a');\n"
                    b'SStream_concat0(OS, "cccc");'
                ),
            )

    def test_templatedeclaration(self):
        patch = Patches.TemplateDeclaration.TemplateDeclaration(
            0, self.template_collector
        )
        syntax = b"template<A, B> void tfunction();"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                (
                    b"#define DECLARE_tfunction(A, B) \\\n"
                    b"  void CONCAT(tfunction, CONCAT(A, B))();\n"
                    b"DECLARE_tfunction(int, int);\n"
                    b"DECLARE_tfunction(int, char);\n"
                ),
            )

    def test_templatedefinition(self):
        patch = Patches.TemplateDefinition.TemplateDefinition(
            0, self.template_collector
        )
        syntax = b"template<A, B> void tfunction() {}"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                (
                    b"#define DEFINE_tfunction(A, B) \\\n"
                    b"  void CONCAT(tfunction, CONCAT(A, B))(){}\n"
                    b"DEFINE_tfunction(int, int);\n"
                    b"DEFINE_tfunction(int, char);\n"
                ),
            )

    def test_templateparamdecl(self):
        patch = Patches.TemplateParamDecl.TemplateParamDecl(0)
        syntax = b"void function(ArrayRef<uint8_t> x);"
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
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"const uint8_t *x")

    def test_templaterefs(self):
        patch = Patches.TemplateRefs.TemplateRefs(0)
        syntax = b"TemplateFunction<A, B>();"
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
            self.assertEqual(
                patch.get_patch(cb, syntax, **kwargs),
                b"CONCAT(TemplateFunction, CONCAT(A, B))",
            )

    def test_usemarkup(self):
        patch = Patches.UseMarkup.UseMarkup(0)
        syntax = b"UseMarkup()"
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
            assert patch.get_patch(cb, syntax, **kwargs) == b"getUseMarkup()"

    def test_usingdecl(self):
        patch = Patches.UsingDeclaration.UsingDeclaration(0)
        syntax = b"using namespace llvm;"
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
            assert patch.get_patch(cb, syntax, **kwargs) == b""
