#!/bin/sh

set -ex

find -name "*.[ch]" | grep -vE "autosync" > files_to_format.txt
clang-format-17 --files=files_to_format.txt --dry-run --Werror --verbose
