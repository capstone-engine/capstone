import json
from pathlib import Path

from tree_sitter import Language, Parser
import logging as log


class Configurator:
    """
    Holds common setup procedures for the configuration.
    It reads the configuration file, compiles languages and initializes the Parser.
    """

    arch: str
    config_path: Path
    ts_so_path: Path
    ts_grammar_path: Path
    config: dict = None
    ts_cpp_lang: Language = None
    parser: Parser = None

    def __init__(self, arch: str, config_path: Path, ts_grammar_path: Path, ts_so_path: Path) -> None:
        self.arch = arch
        self.config_path = config_path
        self.ts_so_path = ts_so_path
        self.ts_grammar_path = ts_grammar_path
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
            log.fatal(f"Could not load arch config file at '{self.config_path}'")
            exit(1)
        with open(self.config_path) as f:
            conf = json.loads(f.read())
        if self.arch not in conf:
            log.fatal(f"{self.arch} has no configuration. Please add them in {self.config_path}!")
            exit(1)
        self.config = conf

    def ts_compile_cpp(self) -> None:
        log.info("Compile Cpp language")
        if not Path.exists(self.ts_grammar_path):
            log.fatal(f"Could not load the tree-sitter grammar at '{self.ts_grammar_path}'")
            exit(1)
        Language.build_library(str(self.ts_so_path), [self.ts_grammar_path])

    def ts_set_cpp_language(self) -> None:
        log.info(f"Load language '{self.ts_so_path}'")
        if not Path.exists(self.ts_so_path):
            log.fatal(f"Could not load the tree-sitter language shared object at '{self.ts_so_path}'")
            exit(1)
        self.ts_cpp_lang = Language(self.ts_so_path, "cpp")

    def init_parser(self) -> None:
        log.debug("Init parser")
        self.parser = Parser()
        self.parser.set_language(self.ts_cpp_lang)
