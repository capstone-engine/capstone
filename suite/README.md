This directory contains some tools used by developers of Capstone project.
Average users should ignore all the contents here.

_MC/_

Input files for the fuzzer. Generated from `<repo-root>/tests/MC/`.

_auto-sync/_

Capstone's updater for the architecture modules.

_cstest/_

Capstone's regression tests tool.
Consumes test files in `<repo-root>/tests/`

_fuzz/_

The fuzzer implementation. Runs on OSFuzz.

_run_clang_format.sh_

Helper script to run clang format on the code and check for issues.

_run_clang_tidy.sh_

Helper script to run clang tidy on the code and check for issues.

_run_invalid_cstool.sh_

Test script to check if `cstool` fails as expected for invalid input.

_run_tests.py_

Script to run all Python tests.

_test_corpus3.py_

Helper script for fuzzing.

_fuzz.py_

This simple script disassembles random code for all archs (or selected arch)
in order to find segfaults.
