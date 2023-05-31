#!/usr/bin/env python3
from pathlib import Path

import termcolor
from tree_sitter import Language, Parser, Tree, Node
import argparse
import logging as log
import sys

from tree_sitter.binding import Query

from Configurator import Configurator
from Helper import convert_loglevel, print_prominent_warning, get_header, run_clang_format, get_path
from Patches.AArch64GetRegFromClass import AArch64GetRegFromClass
from Patches.AddCSDetail import AddCSDetail
from Patches.AddOperand import AddOperand
from Patches.Assert import Assert
from Patches.BitCastStdArray import BitCastStdArray
from Patches.CheckDecoderStatus import CheckDecoderStatus
from Patches.ClassConstructorDef import ClassConstructorDef
from Patches.ClassesDef import ClassesDef
from Patches.ConstMCInstParameter import ConstMCInstParameter
from Patches.ConstMCOperand import ConstMCOperand
from Patches.CppInitCast import CppInitCast
from Patches.CreateOperand0 import CreateOperand0
from Patches.CreateOperand1 import CreateOperand1
from Patches.DeclarationInConditionClause import DeclarationInConditionalClause
from Patches.DecodeInstruction import DecodeInstruction
from Patches.DecoderCast import DecoderCast
from Patches.DecoderParameter import DecoderParameter
from Patches.FallThrough import FallThrough
from Patches.FeatureBits import FeatureBits
from Patches.FeatureBitsDecl import FeatureBitsDecl
from Patches.FieldFromInstr import FieldFromInstr
from Patches.GetNumOperands import GetNumOperands
from Patches.GetOpcode import GetOpcode
from Patches.GetOperandRegImm import GetOperandRegImm
from Patches.GetOperand import GetOperand
from Patches.GetRegClass import GetRegClass
from Patches.GetSubReg import GetSubReg
from Patches.Includes import Includes
from Patches.InlineToStaticInline import InlineToStaticInline
from Patches.IsRegImm import IsOperandRegImm
from Patches.IsOptionalDef import IsOptionalDef
from Patches.IsPredicate import IsPredicate
from Patches.LLVMFallThrough import LLVMFallThrough
from Patches.LLVMunreachable import LLVMUnreachable
from Patches.MethodToFunctions import MethodToFunction
from Patches.MethodTypeQualifier import MethodTypeQualifier
from Patches.NamespaceLLVM import NamespaceLLVM
from Patches.NamespaceAnon import NamespaceAnon
from Patches.NamespaceArch import NamespaceArch
from Patches.OutStreamParam import OutStreamParam
from Patches.PredicateBlockFunctions import PredicateBlockFunctions
from Patches.PrintAnnotation import PrintAnnotation
from Patches.PrintRegImmShift import PrintRegImmShift
from Patches.QualifiedIdentifier import QualifiedIdentifier
from Patches.Patch import Patch
from Patches.ReferencesDecl import ReferencesDecl
from Patches.RegClassContains import RegClassContains
from Patches.STIArgument import STIArgument
from Patches.STIFeatureBits import STIFeatureBits
from Patches.STParameter import SubtargetInfoParam
from Patches.SetOpcode import SetOpcode
from Patches.SignExtend import SignExtend
from Patches.SizeAssignments import SizeAssignment
from Patches.StreamOperation import StreamOperations
from Patches.TemplateDeclaration import TemplateDeclaration
from Patches.TemplateDefinition import TemplateDefinition
from Patches.TemplateParamDecl import TemplateParamDecl
from Patches.TemplateRefs import TemplateRefs
from Patches.UseMarkup import UseMarkup
from Patches.UsingDeclaration import UsingDeclaration
from TemplateCollector import TemplateCollector


class Translator:
    ts_cpp_lang: Language = None
    parser: Parser = None
    template_collector: TemplateCollector = None
    src_paths: [Path]
    out_paths: [Path]
    conf: dict
    src = b""
    current_src_path_in: Path = None
    current_src_path_out: Path = None
    tree: Tree = None

    # Patch priorities: The bigger the number the later the patch will be applied.
    # Patches which create templates must always be executed last. Since syntax
    # in macros is no longer parsed as such (but is only recognized as macro body).
    #
    # If a patch must be executed before another patch (because the matching rules depend on it)
    # mark this dependency as you see below.
    patches: [Patch] = list()

    patch_priorities: {str: int} = {
        RegClassContains.__name__: 0,
        GetRegClass.__name__: 0,
        AArch64GetRegFromClass.__name__: 0,
        CppInitCast.__name__: 0,
        BitCastStdArray.__name__: 0,
        PrintRegImmShift.__name__: 0,
        InlineToStaticInline.__name__: 0,
        GetSubReg.__name__: 0,
        UseMarkup.__name__: 0,
        ConstMCOperand.__name__: 0,
        ClassConstructorDef.__name__: 0,
        ConstMCInstParameter.__name__: 0,
        PrintAnnotation.__name__: 0,
        GetNumOperands.__name__: 0,
        STIArgument.__name__: 0,
        DecodeInstruction.__name__: 0,
        FallThrough.__name__: 0,
        SizeAssignment.__name__: 0,
        FieldFromInstr.__name__: 0,
        FeatureBitsDecl.__name__: 0,
        FeatureBits.__name__: 0,
        STIFeatureBits.__name__: 0,
        Includes.__name__: 0,
        CreateOperand0.__name__: 0,  # ◁───┐ `CreateOperand0` removes most calls to MI.addOperand().
        AddOperand.__name__: 1,  # ────────┘ The ones left are fixed with the `AddOperand` patch.
        CreateOperand1.__name__: 0,
        GetOpcode.__name__: 0,
        SetOpcode.__name__: 0,
        GetOperand.__name__: 0,
        GetOperandRegImm.__name__: 0,
        IsOperandRegImm.__name__: 0,
        SignExtend.__name__: 0,
        DecoderParameter.__name__: 0,
        UsingDeclaration.__name__: 0,
        DecoderCast.__name__: 0,
        IsPredicate.__name__: 0,
        IsOptionalDef.__name__: 0,
        Assert.__name__: 0,  # ◁─────────┐ The llvm_unreachable calls are replaced with asserts.
        LLVMUnreachable.__name__: 1,  # ─┘ Those assert should stay.
        LLVMFallThrough.__name__: 0,
        DeclarationInConditionalClause.__name__: 0,
        StreamOperations.__name__: 0,
        OutStreamParam.__name__: 0,  # ◁──────┐ add_cs_detail() is added to printOperand functions with a certain
        SubtargetInfoParam.__name__: 0,  # ◁──┤ signature. This signature depends on those patches.
        MethodToFunction.__name__: 0,  # ◁────┤
        AddCSDetail.__name__: 1,  # ──────────┘
        NamespaceAnon.__name__: 0,  # ◁─────┐ "llvm" and anonymous namespaces must be removed first,
        NamespaceLLVM.__name__: 0,  # ◁─────┤ so they don't match in NamespaceArch.
        NamespaceArch.__name__: 1,  # ──────┘
        PredicateBlockFunctions.__name__: 0,
        ClassesDef.__name__: 0,  # ◁────────┐ Declarations must be extracted first from the classes.
        MethodTypeQualifier.__name__: 1,  # ┘
        # All previous patches can contain qualified identifiers (Ids with the "::" operator) in their search patterns.
        # After this patch they are removed.
        QualifiedIdentifier.__name__: 2,
        ReferencesDecl.__name__: 3,  # ◁────┐
        CheckDecoderStatus.__name__: 4,  # ─┘ Reference declarations must be removed first.
        TemplateParamDecl.__name__: 5,
        TemplateRefs.__name__: 5,
        # Template declarations are replaced with macros.
        # Those declarations are parsed as macro afterwards
        TemplateDeclaration.__name__: 5,
        # Template definitions are replaced with macros.
        # Those template functions are parsed as macro afterwards.
        TemplateDefinition.__name__: 6,
    }

    def __init__(self, configure: Configurator):
        self.configurator = configure
        self.arch = self.configurator.get_arch()
        self.conf = self.configurator.get_arch_config()
        self.conf_general = self.configurator.get_general_config()
        self.ts_cpp_lang = self.configurator.get_cpp_lang()
        self.parser = self.configurator.get_parser()

        self.src_paths: [Path] = [get_path(sp["in"]) for sp in self.conf["files_to_translate"]]
        t_out_dir: Path = get_path(self.conf_general["translation_out_dir"])
        self.out_paths: [Path] = [t_out_dir.joinpath(sp["out"]) for sp in self.conf["files_to_translate"]]

        self.collect_template_instances()
        self.init_patches()

    def read_src_file(self, src_path: Path) -> None:
        """Reads the file at src_path into self.src"""
        log.debug(f"Read {src_path}")
        if not Path.exists(src_path):
            log.fatal(f"Could not open the source file '{src_path}'")
            exit(1)
        with open(src_path) as f:
            self.src = bytes(f.read(), "utf8")

    def init_patches(self):
        log.debug("Init patches")
        priorities = dict(sorted(self.patch_priorities.items(), key=lambda item: item[1]))
        for ptype, p in priorities.items():
            match ptype:
                case RegClassContains.__name__:
                    patch = RegClassContains(p)
                case GetRegClass.__name__:
                    patch = GetRegClass(p)
                case AArch64GetRegFromClass.__name__:
                    patch = AArch64GetRegFromClass(p)
                case CppInitCast.__name__:
                    patch = CppInitCast(p)
                case BitCastStdArray.__name__:
                    patch = BitCastStdArray(p)
                case CheckDecoderStatus.__name__:
                    patch = CheckDecoderStatus(p)
                case ReferencesDecl.__name__:
                    patch = ReferencesDecl(p)
                case FieldFromInstr.__name__:
                    patch = FieldFromInstr(p)
                case FeatureBitsDecl.__name__:
                    patch = FeatureBitsDecl(p)
                case FeatureBits.__name__:
                    patch = FeatureBits(p, bytes(self.arch, "utf8"))
                case STIFeatureBits.__name__:
                    patch = STIFeatureBits(p, bytes(self.arch, "utf8"))
                case QualifiedIdentifier.__name__:
                    patch = QualifiedIdentifier(p)
                case Includes.__name__:
                    patch = Includes(p, self.arch)
                case ClassesDef.__name__:
                    patch = ClassesDef(p)
                case CreateOperand0.__name__:
                    patch = CreateOperand0(p)
                case CreateOperand1.__name__:
                    patch = CreateOperand1(p)
                case GetOpcode.__name__:
                    patch = GetOpcode(p)
                case SetOpcode.__name__:
                    patch = SetOpcode(p)
                case GetOperand.__name__:
                    patch = GetOperand(p)
                case SignExtend.__name__:
                    patch = SignExtend(p)
                case TemplateDeclaration.__name__:
                    patch = TemplateDeclaration(p, self.template_collector)
                case TemplateDefinition.__name__:
                    patch = TemplateDefinition(p, self.template_collector)
                case DecoderParameter.__name__:
                    patch = DecoderParameter(p)
                case TemplateRefs.__name__:
                    patch = TemplateRefs(p)
                case TemplateParamDecl.__name__:
                    patch = TemplateParamDecl(p)
                case MethodTypeQualifier.__name__:
                    patch = MethodTypeQualifier(p)
                case UsingDeclaration.__name__:
                    patch = UsingDeclaration(p)
                case NamespaceLLVM.__name__:
                    patch = NamespaceLLVM(p)
                case DecoderCast.__name__:
                    patch = DecoderCast(p)
                case IsPredicate.__name__:
                    patch = IsPredicate(p)
                case IsOptionalDef.__name__:
                    patch = IsOptionalDef(p)
                case Assert.__name__:
                    patch = Assert(p)
                case LLVMFallThrough.__name__:
                    patch = LLVMFallThrough(p)
                case DeclarationInConditionalClause.__name__:
                    patch = DeclarationInConditionalClause(p)
                case OutStreamParam.__name__:
                    patch = OutStreamParam(p)
                case MethodToFunction.__name__:
                    patch = MethodToFunction(p)
                case GetOperandRegImm.__name__:
                    patch = GetOperandRegImm(p)
                case StreamOperations.__name__:
                    patch = StreamOperations(p)
                case SubtargetInfoParam.__name__:
                    patch = SubtargetInfoParam(p)
                case SizeAssignment.__name__:
                    patch = SizeAssignment(p)
                case NamespaceArch.__name__:
                    patch = NamespaceArch(p)
                case NamespaceAnon.__name__:
                    patch = NamespaceAnon(p)
                case PredicateBlockFunctions.__name__:
                    patch = PredicateBlockFunctions(p)
                case FallThrough.__name__:
                    patch = FallThrough(p)
                case DecodeInstruction.__name__:
                    patch = DecodeInstruction(p)
                case STIArgument.__name__:
                    patch = STIArgument(p)
                case GetNumOperands.__name__:
                    patch = GetNumOperands(p)
                case AddOperand.__name__:
                    patch = AddOperand(p)
                case PrintAnnotation.__name__:
                    patch = PrintAnnotation(p)
                case ConstMCInstParameter.__name__:
                    patch = ConstMCInstParameter(p)
                case LLVMUnreachable.__name__:
                    patch = LLVMUnreachable(p)
                case ClassConstructorDef.__name__:
                    patch = ClassConstructorDef(p)
                case ConstMCOperand.__name__:
                    patch = ConstMCOperand(p)
                case UseMarkup.__name__:
                    patch = UseMarkup(p)
                case GetSubReg.__name__:
                    patch = GetSubReg(p)
                case InlineToStaticInline.__name__:
                    patch = InlineToStaticInline(p)
                case AddCSDetail.__name__:
                    patch = AddCSDetail(p, self.arch)
                case PrintRegImmShift.__name__:
                    patch = PrintRegImmShift(p)
                case IsOperandRegImm.__name__:
                    patch = IsOperandRegImm(p)
                case _:
                    log.fatal(f"Patch type {ptype} not in Patch init routine.")
                    exit(1)
            self.patches.append(patch)

    def parse(self, src_path: Path) -> None:
        self.read_src_file(src_path)
        log.debug("Parse source code")
        self.tree = self.parser.parse(self.src, keep_text=True)

    def patch_src(self, p_list: [(bytes, Node)]) -> None:
        if len(p_list) == 0:
            return
        # Sort list of patches descending so the patches which are last in the file
        # get patched first. This way the indices of the code snippets before
        # don't change.
        patches = sorted(p_list, key=lambda x: x[1].start_byte, reverse=True)

        new_src = b""
        patch: bytes
        node: Node
        for patch, node in patches:
            start_byte: int = node.start_byte
            old_end_byte: int = node.end_byte
            start_point: (int, int) = node.start_point
            old_end_point: (int, int) = node.end_point

            new_src = self.src[:start_byte] + patch + self.src[old_end_byte:]
            self.src = new_src
            d = len(patch) - (old_end_byte - start_byte)
            self.tree.edit(
                start_byte=start_byte,
                old_end_byte=old_end_byte,
                new_end_byte=old_end_byte + d,
                start_point=start_point,
                old_end_point=old_end_point,
                new_end_point=(old_end_point[0], old_end_point[1] + d),
            )
        self.tree = self.parser.parse(new_src, self.tree, keep_text=True)

    def apply_patch(self, patch: Patch) -> bool:
        """Tests if the given patch should be applied for the current architecture or file."""
        has_apply_only = len(patch.apply_only_to["files"]) > 0 or len(patch.apply_only_to["archs"]) > 0
        has_do_not_apply = len(patch.do_not_apply["files"]) > 0 or len(patch.do_not_apply["archs"]) > 0

        if not (has_apply_only or has_do_not_apply):
            # Lists empty.
            return True

        if has_apply_only:
            if self.arch in patch.apply_only_to["archs"]:
                return True
            elif self.current_src_path_in.name in patch.apply_only_to["files"]:
                return True
            return False
        elif has_do_not_apply:
            if self.arch in patch.do_not_apply["archs"]:
                return False
            elif self.current_src_path_in.name in patch.do_not_apply["files"]:
                return False
            return True
        log.fatal("Logical error.")
        exit(1)

    def translate(self) -> None:
        for self.current_src_path_in, self.current_src_path_out in zip(self.src_paths, self.out_paths):
            log.info(f"Translate '{self.current_src_path_in}'")
            self.parse(self.current_src_path_in)
            patch: Patch
            for patch in self.patches:
                if not self.apply_patch(patch):
                    log.debug(f"Skip patch {patch.__class__.__name__}")
                    continue
                pattern: str = patch.get_search_pattern()

                # Each patch has a capture which includes the whole subtree searched for.
                # Additionally, it can include captures within this subtree.
                # Here we bundle these captures together.
                query: Query = self.ts_cpp_lang.query(pattern)
                captures_bundle: [[(Node, str)]] = list()
                for q in query.captures(self.tree.root_node):
                    if q[1] == patch.get_main_capture_name():
                        # The main capture the patch is looking for.
                        captures_bundle.append([q])
                    else:
                        # A capture which is part of the main capture.
                        # Add it to the bundle.
                        captures_bundle[-1].append(q)

                log.debug(f"Patch {patch.__class__.__name__} (to patch: {len(captures_bundle)}).")

                p_list: (bytes, Node) = list()
                cb: [(Node, str)]
                for cb in captures_bundle:
                    patch_kwargs = self.get_patch_kwargs(patch)
                    bytes_patch: bytes = patch.get_patch(cb, self.src, **patch_kwargs)
                    p_list.append((bytes_patch, cb[0][0]))
                self.patch_src(p_list)
                if self.tree.root_node.type == "ERROR":
                    log.fatal(
                        f"Patch {patch.__class__.__name__} corrupts the tree for {self.current_src_path_in.name}!"
                    )
                    exit(1)
            log.info(f"Patched file at '{self.current_src_path_out}'")
            with open(self.current_src_path_out, "w") as f:
                f.write(get_header())
                f.write(self.src.decode("utf8"))
        run_clang_format(self.out_paths, get_path(self.conf_general["clang_format_file"]))

    def collect_template_instances(self):
        search_paths = [get_path(p) for p in self.conf["files_for_template_search"]]
        temp_arg_deduction = [p.encode("utf8") for p in self.conf["templates_with_arg_deduction"]]
        self.template_collector = TemplateCollector(self.parser, self.ts_cpp_lang, search_paths, temp_arg_deduction)
        self.template_collector.collect()

    def get_patch_kwargs(self, patch):
        if isinstance(patch, Includes):
            return {"filename": self.current_src_path_in.name}
        return dict()

    def remark_manual_files(self) -> None:
        manual_edited = self.conf["manually_edited_files"]
        msg = ""
        if len(manual_edited) > 0:
            msg += (
                termcolor.colored(
                    "The following files are too complex to translate! Please check them by hand.", attrs=["bold"]
                )
                + "\n"
            )
        else:
            return
        for f in manual_edited:
            msg += get_path(f).name + "\n"
        print_prominent_warning(msg)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="CppTranslator",
        description="Capstones C++ to C translator for LLVM source files",
    )
    parser.add_argument(
        "-a", dest="arch", help="Name of target architecture.", choices=["ARM", "PPC", "AArch64"], required=True
    )
    parser.add_argument(
        "-v",
        dest="verbosity",
        help="Verbosity of the log messages.",
        choices=["debug", "info", "warning", "fatal"],
        default="info",
    )
    parser.add_argument(
        "-c", dest="config_path", help="Config file for architectures.", default="arch_config.json", type=Path
    )
    parser.add_argument(
        "-g", dest="grammar", help="Path to the tree-sitter C++ grammar.", default="vendor/tree-sitter-cpp", type=Path
    )
    parser.add_argument(
        "-l", dest="lang_so", help="File to store the compiled C++ language.", default="build/ts-cpp.so", type=Path
    )
    arguments = parser.parse_args()
    return arguments


if __name__ == "__main__":
    if not sys.hexversion >= 0x030B00F0:
        log.fatal("Python >= v3.11 required.")
        exit(1)

    args = parse_args()
    log.basicConfig(
        level=convert_loglevel(args.verbosity),
        stream=sys.stdout,
        format="%(levelname)-5s - %(message)s",
    )
    configurator = Configurator(args.arch, args.config_path, args.grammar, args.lang_so)
    translator = Translator(configurator)
    translator.translate()
    translator.remark_manual_files()
