#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: LGPL-3.0-only
import unittest
from pathlib import Path

from tree_sitter import Node, Query

import autosync.cpptranslator.Patches as Patches
from autosync.cpptranslator import CppTranslator

from autosync.cpptranslator.Configurator import Configurator
from autosync.Helper import get_path


class TestPatches(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configurator = Configurator("ARCH", get_path("{CPP_TRANSLATOR_TEST_CONFIG}"))
        cls.translator = CppTranslator.Translator(configurator)
        cls.ts_cpp_lang = configurator.get_cpp_lang()
        cls.parser = configurator.get_parser()

    def test_addcsdetail(self):
        patch = Patches.AddCSDetail.AddCSDetail(0, "ARCH")
        syntax = b"void printThumbLdrLabelOperand(MCInst *MI, unsigned OpNo, SStream *O) { int i = OpNo; }"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

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
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

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
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

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
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_classesdef(self):
        patch = Patches.ClassesDef.ClassesDef(0)
        syntax = b"Class definitions"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_constmcinstparameter(self):
        patch = Patches.ConstMCInstParameter.ConstMCInstParameter(0)
        syntax = b"const MCInst *MI"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_constmcoperand(self):
        patch = Patches.ConstMCOperand.ConstMCOperand(0)
        syntax = b"const MCOperand op"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

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
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

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
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_createoperand1(self):
        patch = Patches.CreateOperand1.CreateOperand1(0)
        syntax = b"MI.insert(0, MCOperand::createReg(REGISTER));"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_declarationinconditionclause(self):
        patch = Patches.DeclarationInConditionClause.DeclarationInConditionalClause(0)
        syntax = b"if (int i = 0) {}}"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_decodeinstruction(self):
        patch = Patches.DecodeInstruction.DecodeInstruction(0)
        syntax = b"decodeInstruction(MI, this, STI)"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

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
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_decoderparameter(self):
        patch = Patches.DecoderParameter.DecoderParameter(0)
        syntax = b"const MCDisassembler *Decoder"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

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
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_featurebitsdecl(self):
        patch = Patches.FeatureBitsDecl.FeatureBitsDecl(0)
        syntax = b"featureBits = 0x00"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_featurebits(self):
        patch = Patches.FeatureBits.FeatureBits(0, b"ARCH")
        syntax = b"featureBits[FLAG]"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_fieldfrominstr(self):
        patch = Patches.FieldFromInstr.FieldFromInstr(0)
        syntax = b"fieldFromInstr(...)"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_getnumoperands(self):
        patch = Patches.GetNumOperands.GetNumOperands(0)
        syntax = b"MI.getNumOperands()"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_getopcode(self):
        patch = Patches.GetOpcode.GetOpcode(0)
        syntax = b"Inst.getOpcode()"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_getoperand(self):
        patch = Patches.GetOperand.GetOperand(0)
        syntax = b"MI.getOperand(...)"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

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
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_getregclass(self):
        patch = Patches.GetRegClass.GetRegClass(0)
        syntax = b"MRI.getRegClass(RegClass)"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

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
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_getsubreg(self):
        patch = Patches.GetSubReg.GetSubReg(0)
        syntax = b"MRI.getSubReg(...);"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_includes(self):
        patch = Patches.Includes.Includes(0, "ARCH")
        syntax = b"#include some_llvm_header.h"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_inlinetostaticinline(self):
        patch = Patches.InlineToStaticInline.InlineToStaticInline(0)
        syntax = b"inline void FUNCTION(...) {...}"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

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
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

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
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

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
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_llvmfallthrough(self):
        patch = Patches.LLVMFallThrough.LLVMFallThrough(0)
        syntax = b"LLVM_FALLTHROUGH"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
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
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

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
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

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
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_namespaceanon(self):
        patch = Patches.NamespaceAnon.NamespaceAnon(0)
        syntax = b"namespace {CONTENT}"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_namespacearch(self):
        patch = Patches.NamespaceArch.NamespaceArch(0)
        syntax = b"namespace ArchSpecificNamespace {CONTENT}"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_namespacellvm(self):
        patch = Patches.NamespaceLLVM.NamespaceLLVM(0)
        syntax = b"namespace {CONTENT}"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_outstreamparam(self):
        patch = Patches.OutStreamParam.OutStreamParam(0)
        syntax = b"raw_ostream &OS"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_predicateblockfunctions(self):
        patch = Patches.PredicateBlockFunctions.PredicateBlockFunctions(0)
        syntax = b"VPTBlock.instrInVPTBlock()"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_printregimmshift(self):
        patch = Patches.PrintRegImmShift.PrintRegImmShift(0)
        syntax = b"printRegImmShift(...)"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

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
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_referencesdecl(self):
        patch = Patches.ReferencesDecl.ReferencesDecl(0)
        syntax = b"TYPE &Param"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_regclasscontains(self):
        patch = Patches.RegClassContains.RegClassContains(0)
        syntax = b"...getRegClass(CLASS).contains(Reg)"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_setopcode(self):
        patch = Patches.SetOpcode.SetOpcode(0)
        syntax = b"Inst.setOpcode(...)"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_signextend(self):
        patch = Patches.SignExtend.SignExtend(0)
        syntax = b"SignExtend32<A>(...)"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_sizeassignments(self):
        patch = Patches.SizeAssignments.SizeAssignment(0)
        syntax = b"Size = <num>"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

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
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_stifeaturebits(self):
        patch = Patches.STIFeatureBits.STIFeatureBits(0, b"ARCH")
        syntax = b"STI.getFeatureBits()[FLAG]"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_streamoperation(self):
        patch = Patches.STParameter.SubtargetInfoParam(0)
        syntax = b"OS << ..."
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_templatedeclaration(self):
        patch = Patches.StreamOperation.StreamOperations(0)
        syntax = b"template<A, B> void func();"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_templatedefinition(self):
        patch = Patches.TemplateDeclaration.TemplateDeclaration(0)
        syntax = b"template<A, B> void func() {}"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_templateparamdecl(self):
        patch = Patches.TemplateDefinition.TemplateDefinition(0)
        syntax = b"ArrayRef<uint8_t> x;"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_templaterefs(self):
        patch = Patches.TemplateParamDecl.TemplateParamDecl(0)
        syntax = b"TemplateFunction<A, B>"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            self.assertEqual(patch.get_patch(cb, syntax, **kwargs), b"")

    def test_usemarkup(self):
        patch = Patches.TemplateRefs.TemplateRefs(0)
        syntax = b"UseMarkup()"
        kwargs = self.translator.get_patch_kwargs(patch)
        query: Query = self.ts_cpp_lang.query(patch.get_search_pattern())
        captures_bundle: [[(Node, str)]] = list()
        for q in query.captures(self.parser.parse(syntax, keep_text=True).root_node):
            if q[1] == patch.get_main_capture_name():
                captures_bundle.append([q])
            else:
                captures_bundle[-1].append(q)
        for cb in captures_bundle:
            assert patch.get_patch(cb, syntax, **kwargs) == b""
