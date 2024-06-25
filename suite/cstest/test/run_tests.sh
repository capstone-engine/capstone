#!/bin/sh

STDOUT_FILE="/tmp/cstest_stdout"
STDERR_FILE="/tmp/cstest_stderr"

print_stdout() {
  echo -n "\n###################### STDOUT ######################\n"
  cat $STDOUT_FILE
  echo -n "####################################################\n"
}

print_stderr() {
  echo -n "\n###################### STDERR ######################\n"
  cat $STDERR_FILE
  echo -n "####################################################\n"
}

cstest empty_test_file.yaml > "$STDOUT_FILE" 2> "$STDERR_FILE"
expected_err="Failed to parse test file 'empty_test_file.yaml'
Error: 'Empty file'"

if ! $(grep -q "$expected_err" "$STDERR_FILE"); then
  echo "Failed the empty file test"
  print_stdout
  print_stderr
  exit 1
fi

cstest missing_madatory_field.yaml > "$STDOUT_FILE" 2> "$STDERR_FILE"
expected_err="Error: 'Missing required mapping field'"

if ! $(grep -q "$expected_err" "$STDERR_FILE"); then
  echo "Failed the mandatory field test"
  print_stdout
  print_stderr
  exit 1
fi


cstest invalid_test_file.yaml > "$STDOUT_FILE" 2> "$STDERR_FILE"
expected_err="Error: 'libyaml parser error'"

if ! $(grep -q "$expected_err" "$STDERR_FILE"); then
  echo "Failed the invalid test file test"
  print_stdout
  print_stderr
  exit 1
fi

cstest min_valid_test_file.yaml > "$STDOUT_FILE" 2> "$STDERR_FILE"
expected_out="All tests succeeded."

if ! $(grep -q "$expected_out" "$STDOUT_FILE"); then
  echo "Failed the minimal valid parsing test"
  print_stdout
  print_stderr
  exit 1
fi

echo "Test succeeded"
exit 0
