import json
from pathlib import Path

from Helper import get_path, fail_exit
from tree_sitter import Language, Parser
import logging as log


class Configurator:
    """
    Holds common setup procedures for the configuration.
    It reads the configuration file, compiles languages and initializes the Parser.
    """

    arch: str
    config_path: Path
    config: dict = None
    ts_cpp_lang: Language = None
    parser: Parser = None

    def __init__(self, arch: str, config_path: Path) -> None:
        self.arch = arch
        self.config_path = config_path
        self.ts_shared_object = get_path("{VENDOR_DIR}").joinpath("ts_cpp.so")
        self.load_config()
        self.ts_compile_cpp()
        self.ts_set_cpp_language()
        self.init_parser()

    def get_arch(self) -> str:
        return self.arch

    def get_cpp_lang(self) -> Language:
        if self.ts_cpp_lang:
            return self.ts_cpp_lang
        self.ts_set_cpp_language()
        return self.ts_cpp_lang

    def get_parser(self) -> Parser:
        if self.parser:
            return self.parser
        self.init_parser()
        return self.parser

    def get_arch_config(self) -> dict:
        if self.config:
            return self.config[self.arch]
        self.load_config()
        return self.config[self.arch]

    def get_general_config(self) -> dict:
        if self.config:
            return self.config["General"]
        self.load_config()
        return self.config["General"]

    def load_config(self) -> None:
        if not Path.exists(self.config_path):
            fail_exit(f"Could not load arch config file at '{self.config_path}'")
        with open(self.config_path) as f:
            conf = json.loads(f.read())
        if self.arch not in conf:
            fail_exit(f"{self.arch} has no configuration. Please add them in {self.config_path}!")
        self.config = conf

    def ts_compile_cpp(self) -> None:
        log.info("Compile Cpp language")
        ts_grammar_path = get_path("{VENDOR_DIR}").joinpath("tree-sitter-cpp")
        if not Path.exists(ts_grammar_path):
            fail_exit(f"Could not load the tree-sitter grammar at '{ts_grammar_path}'")
        Language.build_library(str(self.ts_shared_object), [ts_grammar_path])

    def ts_set_cpp_language(self) -> None:
        log.info(f"Load language '{self.ts_shared_object}'")
        if not Path.exists(self.ts_shared_object):
            fail_exit(f"Could not load the tree-sitter language shared object at '{self.ts_shared_object}'")
        self.ts_cpp_lang = Language(self.ts_shared_object, "cpp")

    def init_parser(self) -> None:
        log.debug("Init parser")
        self.parser = Parser()
        self.parser.set_language(self.ts_cpp_lang)
