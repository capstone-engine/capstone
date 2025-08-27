#!/bin/sh

set -ex

if [ $# -ne 1 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
  echo "$0 <build-path>"
  echo "Set env var 'base_sha'  to upstream/next hash and 'head_sha' and your current HEAD hash."
  exit 1
fi

if [ -z $base_sha ] || [ -z $head_sha ]; then
  echo "Set env var 'base_sha'  to upstream/next hash and 'head_sha' and your current HEAD hash."
  exit 0
fi

echo "Running with version:"
clang-tidy --version

BUILD_PATH="$1"

check_list="clang-analyzer-*,-clang-analyzer-cplusplus*,-clang-analyzer-optin.performance.Padding"

if $(hash clang-tidy-18); then
  echo -e "#############\nProduced by\n$(clang-tidy-18 --version)\n#############\n\n" > ct-warnings.txt
  clang-tidy-18 $(find ./arch ./*.c -type f -iregex ".*\.[c]") -p "$BUILD_PATH" -checks="$check_list" >> ct-warnings.txt
else
  echo -e "#############\nProduced by\n$(clang-tidy --version)\n#############\n\n" > ct-warnings.txt
  clang-tidy $(find ./arch ./*.c -type f -iregex ".*\.[c]") -p "$BUILD_PATH" -checks="$check_list" >> ct-warnings.txt
fi

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

cat ct-warnings.txt

echo -e "\n\nclang-tidy warnings for: $faulty_files\n"
echo "Please fix them. Or, if completely unrelated, let us know."

exit 1
