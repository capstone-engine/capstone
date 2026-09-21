#!/bin/bash
# Wrap every arch/*.c translation unit that still lacks one in
# #ifdef CAPSTONE_HAS_<ARCH> ... #endif, so that disabling an architecture
# really removes its code from the build.
#
# The macro for each file is taken from a sibling file in the same directory
# that already carries a guard, never guessed from the directory name.
# Directories where no file carries a guard yet are listed in
# explicitMacroByDirectory below.
#
# Idempotent: a file that already opens with a CAPSTONE_HAS_ guard is skipped.
# Run it after every sync with upstream — upstream keeps adding architecture
# sources without a guard, because its own CMake build excludes them by file
# list instead, something SwiftPM cannot express.

set -euo pipefail

cd "$(dirname "$0")/../.."

# Directories where not a single file carries a guard yet, so no macro can be
# read off a sibling. Verified against CMakeLists.txt.
explicitMacroForDirectory() {
	case "$1" in
	arch/Xtensa) echo CAPSTONE_HAS_XTENSA ;;
	*) echo "" ;;
	esac
}

guardedCount=0
skippedCount=0

for sourceFile in $(find arch -name "*.c" | sort); do
	if grep -qE '^#ifdef CAPSTONE_HAS_|^#if defined\(CAPSTONE_HAS_' "$sourceFile"; then
		skippedCount=$((skippedCount + 1))
		continue
	fi

	architectureDirectory=$(dirname "$sourceFile")
	# No sibling carries a guard yet -> grep exits non-zero, which pipefail
	# would turn into a script abort. Fall through to the explicit table.
	guardMacro=$(grep -h -m1 -oE '^#ifdef CAPSTONE_HAS_[A-Z0-9_]+' "$architectureDirectory"/*.c 2>/dev/null |
		sed 's/#ifdef //' | sort -u | head -1 || true)

	if [ -z "$guardMacro" ]; then
		guardMacro=$(explicitMacroForDirectory "$architectureDirectory")
	fi

	if [ -z "$guardMacro" ]; then
		echo "ERROR: cannot determine guard macro for $sourceFile" >&2
		exit 1
	fi

	# Ensure the file ends with a newline before appending #endif.
	[ -n "$(tail -c1 "$sourceFile")" ] && printf '\n' >>"$sourceFile"

	printf '#ifdef %s\n' "$guardMacro" | cat - "$sourceFile" >"$sourceFile.guarded"
	printf '\n#endif // %s\n' "$guardMacro" >>"$sourceFile.guarded"
	mv "$sourceFile.guarded" "$sourceFile"

	echo "guarded $sourceFile with $guardMacro"
	guardedCount=$((guardedCount + 1))
done

echo "---"
echo "guarded: $guardedCount, already guarded: $skippedCount"
