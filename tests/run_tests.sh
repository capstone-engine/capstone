#!/bin/sh
#
# By Travis Finkenauer <tmfinken@gmail.com>, 2017
#
# Run Capstone tests, comparing to expected output
#
# Usage: run_tests.sh [TEST1 [TEST2 [...]]]
#
# Unless the names of specific tests are passed, all executable files with
# filennames matching "test_*" will be run.
#
# The following environment variables affect execution:
# - TEST_BIN_DIR: run test binaries in given directory
#   (defaults to tests/ directory)
# - UPDATE_EXPECTED: update expected test output, overwriting existing output;
#       set to a non-empty string to update expected output

set -eu

TEST_DIR="$(dirname "$0")"
TEST_BIN_DIR="${TEST_BIN_DIR:-$TEST_DIR}"

echo "Looking for test binaries in \"$TEST_BIN_DIR\""

EXPECTED_OUT_DIR="${TEST_DIR}/expected_output"
ACTUAL_OUT_DIR="${TEST_DIR}/actual_output"

# Use arguments as tests
if [ $# -gt 0 ]; then
    RUN_TESTS="$*"
else
    # Pipe to (xargs || echo) because GNU xargs will run the program without
    # arguments, which would cause a warning
    RUN_TESTS="$( \
        find "$TEST_BIN_DIR" -maxdepth 1 -name 'test_*' -type f -perm -o=x | \
        (xargs -n1 basename 2>/dev/null || echo))"
fi

# print whitespace separated list with indentation
print_list() {
    local indent="$1"; shift
    local items="$1"; shift
    echo "$items" | xargs -n1 | sed "s/^/$indent/"
}

if [ ! ${UPDATE_EXPECTED:-} = "" ]; then
    echo "Updating expected output"
    UPDATE_EXPECTED=:
else
    UPDATE_EXPECTED=
fi

mkdir -p "$ACTUAL_OUT_DIR"
mkdir -p "$EXPECTED_OUT_DIR"

PASSED_TESTS=
FAILED_TESTS=
NUM_PASSED_TESTS=0
NUM_TESTS=0
MISSING_EXPECTATION=

export LD_LIBRARY_PATH="${TEST_BIN_DIR}${LD_LIBRARY_PATH:+:}${LD_LIBRARY_PATH:-}"

RUN_TESTS="$(echo "$RUN_TESTS" | xargs -n1 | sort)"

for test_name in $(echo "$RUN_TESTS"); do
    if [ "$test_name" = "" ]; then
        break
    fi
    echo
    test="$TEST_BIN_DIR/$test_name"
    test_pass=:
    echo "===== $test_name ====="
    actual_test_output="${ACTUAL_OUT_DIR}/${test_name}"
    # Trim extensions to get expected output
    trimmed_test_name=${test_name%%.*}
    expected_test_output="${EXPECTED_OUT_DIR}/${trimmed_test_name}"

    # Emulate goto with a loop
    while :; do
        # Check if test exists
        if [ ! -f "$test" ]; then
            echo "  could not find test \"$test\""
            test_pass=
            break
        fi

        # Run test
        if ! "$test" > "$actual_test_output"; then
            echo "  test program failed"
            test_pass=
            break
        fi

        # Update exptected output
        if [ $UPDATE_EXPECTED ]; then
            # Only keep the expected output of the test without extensions
            if [ "$trimmed_test_name" = "$test_name" ]; then
                cp "$actual_test_output" "$expected_test_output"
            fi
            break
        fi

        if [ ! -f "$expected_test_output" ]; then
            MISSING_EXPECTATION="$MISSING_EXPECTATION $test_name"
            test_pass=
            break
        fi

        # Compare output
        if ! diff -u "$expected_test_output" "$actual_test_output"; then
            echo "  does not match expected output"
            test_pass=
            break
        fi

        # Only iterator once; we can break to simulate a goto
        break
    done

    # Update stats
    if [ $test_pass ]; then
        echo "  PASS"
        PASSED_TESTS="$PASSED_TESTS $test_name"
        NUM_PASSED_TESTS=$(expr $NUM_PASSED_TESTS + 1)
    else
        echo " FAIL"
        FAILED_TESTS="$FAILED_TESTS $test_name"
    fi
    NUM_TESTS=$(expr $NUM_TESTS + 1)
done

echo
echo "The following tests passed:"
print_list "  " "${PASSED_TESTS}"

if [ ${#FAILED_TESTS} -eq 0 ]; then
    RET_CODE=0
else
    RET_CODE=1
    echo
    echo "The following tests failed:"
    print_list "  " "${FAILED_TESTS}"
fi

if [ "$MISSING_EXPECTATION" != "" ]; then
    echo
    echo "The following expected outputs were missing:"
    print_list "  " "$MISSING_EXPECTATION"
    echo
    echo "Consider running script with UPDATE_EXPECTED=1"
fi

echo
echo "Results: (${NUM_PASSED_TESTS} / ${NUM_TESTS}) tests passed"

exit $RET_CODE
