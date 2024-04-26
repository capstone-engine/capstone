#!/bin/sh 

if [ $# -ne 1 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
  echo "$0 <build-path>"
  exit 1
fi

BUILD_PATH="$1"

clang-tidy $(find ./arch ./*.c -type f -iregex ".*\.[c]") -p "$BUILD_PATH" -checks=clang-analyzer-*,-clang-analyzer-cplusplus* | tee ct-warnings.txt

tmp=$(mktemp)
grep ": warning" ct-warnings.txt | grep -oE "^[/a-zA-Z0-9]*\.[ch]" | sort | uniq > $tmp
top_level=$(git rev-parse --show-toplevel)

echo "\n\n###### REPORT\n\n"

for modified in $(git diff --name-only origin/next); do
  full_path="$top_level/$modified"
  if grep -q "$full_path" $tmp; then
    echo "$full_path as warnings. Please fix them."
    needs_fixes=1
  fi
done

if [ -z $needs_fixes ]; then
  echo "All good"
  exit 0
fi
exit 1
