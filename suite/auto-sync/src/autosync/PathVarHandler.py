# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import json
import logging as log
import re
import subprocess

from pathlib import Path


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class PathVarHandler(metaclass=Singleton):
    def __init__(self) -> None:
        try:
            res = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                check=True,
                stdout=subprocess.PIPE,
            )
        except subprocess.CalledProcessError:
            log.fatal("Could not get repository top level directory.")
            exit(1)
        repo_root = res.stdout.decode("utf8").strip("\n")
        # The main directories
        self.paths: dict[str:Path] = dict()
        self.paths["{CS_ROOT}"] = Path(repo_root)
        self.paths["{AUTO_SYNC_ROOT}"] = Path(repo_root).joinpath("suite/auto-sync/")
        self.paths["{AUTO_SYNC_SRC}"] = self.paths["{AUTO_SYNC_ROOT}"].joinpath(
            "src/autosync/"
        )
        path_config_file = self.paths["{AUTO_SYNC_SRC}"].joinpath("path_vars.json")

        # Load variables
        with open(path_config_file) as f:
            vars = json.load(f)

        paths = vars["paths"]
        self.create_during_runtime = vars["create_during_runtime"]

        missing = list()
        for p_name, path in paths.items():
            resolved = path
            for var_id in re.findall(r"\{.+}", resolved):
                if var_id not in self.paths:
                    log.fatal(
                        f"{var_id} hasn't been added to the PathVarsHandler, yet. The var must be defined in a previous entry."
                    )
                    exit(1)
                resolved: str = re.sub(var_id, str(self.paths[var_id]), resolved)
                log.debug(f"Set {p_name} = {resolved}")
                if not Path(resolved).exists() and (
                    p_name not in self.create_during_runtime
                    and p_name not in vars["ignore_missing"]
                ):
                    missing.append(resolved)
                elif var_id in self.create_during_runtime:
                    self.create_path(var_id, resolved)
                self.paths[p_name] = Path(resolved)
        if len(missing) > 0:
            log.fatal(f"Some paths from config file are missing!")
            for m in missing:
                log.fatal(f"\t{m}")
            exit(1)

    def test_only_overwrite_var(self, var_name: str, new_path: Path):
        if var_name not in self.paths:
            raise ValueError(f"PathVarHandler doesn't have a path for '{var_name}'")
        if not new_path.exists():
            raise ValueError(f"New path doesn't exists: '{new_path}")
        self.paths[var_name] = new_path

    def get_path(self, name: str) -> Path:
        if name not in self.paths:
            raise ValueError(f"Path variable {name} has no path saved.")
        if name in self.create_during_runtime:
            self.create_path(name, self.paths[name])
        return self.paths[name]

    def complete_path(self, path_str: str) -> Path:
        resolved = path_str
        for p_name in re.findall(r"\{.+}", path_str):
            resolved = re.sub(p_name, str(self.get_path(p_name)), resolved)
        return Path(resolved)

    @staticmethod
    def create_path(var_id: str, path: str):
        pp = Path(path)
        if pp.exists():
            return

        log.debug(f"Create path {var_id} @ {path}")
        postfix = var_id.strip("}").split("_")[-1]
        if postfix == "FILE":
            if not pp.parent.exists():
                pp.parent.mkdir(parents=True)
            pp.touch()
        elif postfix == "DIR":
            pp.mkdir(parents=True)
        else:
            from autosync.Helper import fail_exit

            fail_exit(
                f"The var_id: {var_id} must end in _FILE or _DIR. It ends in '{postfix}'"
            )
