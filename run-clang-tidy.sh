#!/bin/sh -x

if [ $# -ne 1 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
  echo "$0 <build-path>"
  exit 1
fi

BUILD_PATH="$1"

clang-tidy $(find ./arch ./*.c -type f -iregex ".*\.[c]") -p "$BUILD_PATH" -checks=clang-analyzer-*,-clang-analyzer-cplusplus* > ct-warnings.txt
if [ $? -ne 0 ]; then
  echo "clang-tidy failed"
  exit 1
fi

tmp=$(mktemp)
grep ": warning" ct-warnings.txt | grep -oE "^[/a-zA-Z0-9]*\.[ch]" | sort | uniq > $tmp
top_level=$(git rev-parse --show-toplevel)

echo "\n\n###### REPORT\n\n"

changed_files=$(git diff --name-only $base_sha..$head_sha)
if [ $? -ne 0 ]; then
  echo "Failed to get changed files."
  exit 1
fi

faulty_files=""
for modified in $changed_files; do
  files_changed=1
  full_path="$top_level/$modified"
  if grep -q "$full_path" $tmp; then
    faulty_files="$faulty_files $modified"
    echo "$full_path as warnings. Please fix them."
    needs_fixes=1
  fi
done

if [ -z $files_changed ]; then
  echo "No files changed."
  exit 0
fi

if [ -z $needs_fixes ]; then
  echo "None of the changed files has clang-tidy warnings."
  exit 0
fi

echo -e "\n\nclang-tidy warnings for: $faulty_files\n"
echo "Please fix them. Or, if completely unrelated, let us know."

exit 1
