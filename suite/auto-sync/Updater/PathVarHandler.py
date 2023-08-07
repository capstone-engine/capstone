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
    paths = {}

    def __init__(self) -> None:
        try:
            res = subprocess.run(["git", "rev-parse", "--show-toplevel"], check=True, stdout=subprocess.PIPE)
        except subprocess.CalledProcessError:
            log.fatal("Could not get repository top level directory.")
            exit(1)
        repo_root = res.stdout.decode("utf8").strip("\n")
        # The main directories
        self.paths["{CS_ROOT}"] = Path(repo_root)
        self.paths["{AUTO_SYNC_ROOT}"] = Path(repo_root).joinpath("suite/auto-sync/")
        self.paths["{AUTO_SYNC_UPDATER_DIR}"] = self.paths["{AUTO_SYNC_ROOT}"].joinpath("Updater/")
        path_config_file = self.paths["{AUTO_SYNC_UPDATER_DIR}"].joinpath("path_vars.json")

        # Load variables
        with open(path_config_file) as f:
            vars = json.load(f)
        for p_name, path in vars.items():
            resolved = path
            for var_id in re.findall(r"\{.+}", resolved):
                if var_id not in self.paths:
                    log.fatal(
                        f"{var_id} hasn't been added to the PathVarsHandler, yet. The var must be defined in a previous entry."
                    )
                    exit(1)
                resolved = re.sub(var_id, str(self.paths[var_id]), resolved)
                log.debug(f"Set {p_name} = {resolved}")
                if not Path(resolved).exists():
                    log.fatal(f"Path from config file does not exist! Path: {resolved}")
                    exit(1)
                self.paths[p_name] = resolved

    def get_path(self, name: str) -> Path:
        if name not in self.paths:
            raise ValueError(f"Path variable {name} has no path saved.")
        return self.paths[name]

    def complete_path(self, path_str: str) -> Path:
        resolved = path_str
        for p_name in re.findall(r"\{.+}", path_str):
            resolved = re.sub(p_name, self.get_path(p_name), resolved)
        return Path(resolved)
