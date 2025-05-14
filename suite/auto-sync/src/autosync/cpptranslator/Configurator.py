# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import json
import logging as log
from pathlib import Path

import tree_sitter_cpp as ts_cpp
from tree_sitter import Language, Parser

from autosync.Helper import fail_exit


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
        self.load_config()
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

    def get_patch_config(self) -> dict:
        if self.config:
            return self.config["General"]["patching"]
        self.load_config()
        return self.config["General"]["patching"]

    def load_config(self) -> None:
        if not Path.exists(self.config_path):
            fail_exit(f"Could not load arch config file at '{self.config_path}'")
        with open(self.config_path) as f:
            conf = json.loads(f.read())
        if self.arch not in conf:
            fail_exit(
                f"{self.arch} has no configuration. Please add them in {self.config_path}!"
            )
        self.config = conf

    def ts_set_cpp_language(self) -> None:
        self.ts_cpp_lang = Language(ts_cpp.language())

    def init_parser(self) -> None:
        log.debug("Init parser")
        self.parser = Parser(self.ts_cpp_lang)
