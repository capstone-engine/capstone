#!/usr/bin/env python3

import ast
import sys
from pathlib import Path

ROOT: Path = Path(__file__).resolve().parent
CAPSTONE_DIR: Path = ROOT / "capstone"


def is_ctypes_class(node: ast.ClassDef) -> bool:
    for base in node.bases:
        if base.attr in ("Structure", "Union"):
            return True

    return False


def get_fields(node: ast.ClassDef) -> ast.expr | None:
    for child in node.body:
        if isinstance(child, ast.Assign):
            return child.value
    return None


def get_field_names(value: ast.Tuple):
    for entry in value.elts:
        name, ctype = entry.elts
        yield name.value, ctype, name.lineno


def get_annotations(node: ast.ClassDef) -> dict[str, ast.expr]:
    annotations: dict[str, ast.expr] = {}
    for child in node.body:
        if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
            annotations[child.target.id] = child.annotation
    return annotations


def expected_annotation(node: ast.expr, classes: set[str]) -> str | None:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        element = expected_annotation(node.left, classes)
        if element is not None:
            return f"Sequence[{element}]"
    elif isinstance(node, ast.Name) and node.id in classes:
        return node.id
    elif (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "ctypes"
    ):
        if node.attr in {
            "c_byte",
            "c_ubyte",
            "c_short",
            "c_ushort",
            "c_int",
            "c_uint",
            "c_long",
            "c_ulong",
            "c_longlong",
            "c_ulonglong",
            "c_int8",
            "c_uint8",
            "c_int16",
            "c_uint16",
            "c_int32",
            "c_uint32",
            "c_int64",
            "c_uint64",
            "c_size_t",
            "c_ssize_t",
        }:
            return "int"
        return {
            "c_bool": "bool",
            "c_float": "float",
            "c_double": "float",
            "c_longdouble": "float",
            "c_char": "bytes",
            "c_wchar": "str",
            "c_char_p": "bytes | None",
            "c_wchar_p": "str | None",
        }.get(node.attr)
    return None


def check_file(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    display_path: Path = path.relative_to(ROOT)
    errors: list[str] = []

    classes = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and is_ctypes_class(node)
    }
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or not is_ctypes_class(node):
            continue

        fields = get_fields(node)
        if fields is None:
            errors.append(
                f"{display_path}:{node.lineno}: {node.name} has no _fields_ assignment"
            )
            continue

        annotations = get_annotations(node)
        for field, ctype, lineno in get_field_names(fields):
            if field is None or ctype is None:
                errors.append(
                    f"{display_path}:{lineno}: {node.name} has a _fields_ entry "
                    "with an unknown name"
                )
            elif field not in annotations:
                errors.append(
                    f"{display_path}:{lineno}: {node.name}.{field} has no type annotation"
                )

            else:
                expected = expected_annotation(ctype, classes)
                actual = ast.unparse(annotations[field])
                if expected is None:
                    errors.append(
                        f"{display_path}:{lineno}: {node.name}.{field} has an "
                        f"unsupported ctypes type: {ast.unparse(ctype)}"
                    )
                elif actual != expected:
                    errors.append(
                        f"{display_path}:{lineno}: {node.name}.{field} "
                        f"has annotation {actual}, expected {expected}"
                    )

    return errors


def main():
    errors: list[str] = []

    for path in sorted(CAPSTONE_DIR.glob("*.py")):
        if path.name == "__init__.py":
            continue
        errors.extend(check_file(path))

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print("good hints")
    return 0


if __name__ == "__main__":
    sys.exit(main())
