#!/bin/bash
# Wrap every arch/*.c translation unit that still lacks one in
# #ifdef CAPSTONE_HAS_<ARCH> ... #endif, so that disabling an architecture
# really removes its code from the build.
#
# The macro for each file is taken from a sibling file in the same directory
# that already carries a guard, never guessed from the directory name.
# Directories where no file carries a guard yet are listed in
# explicitMacroForDirectory below.
#
# Not every CAPSTONE_HAS_* macro names an architecture: CAPSTONE_HAS_OSXKERNEL
# selects a kernel-side environment and appears in files that have no
# architecture guard at all. Treating it as one made this script skip
# arch/X86/X86InstPrinterCommon.c, which then stayed compiled with X86 disabled
# and failed to link against the guarded X86Mapping.c. Hence the explicit
# exclusion list rather than a bare CAPSTONE_HAS_ prefix match.
#
# Run with --check to report rather than edit; exits non-zero if any file is
# missing its guard. Use it after every sync with upstream — upstream keeps
# adding architecture sources without a guard, because its own CMake build
# excludes them by file list instead, something SwiftPM cannot express.

set -euo pipefail

cd "$(dirname "$0")/../.."

checkOnly=0
if [ "${1:-}" = "--check" ]; then
	checkOnly=1
fi

# CAPSTONE_HAS_* macros that do not name an architecture.
nonArchitectureMacros="CAPSTONE_HAS_OSXKERNEL"

isArchitectureMacro() {
	for excluded in $nonArchitectureMacros; do
		[ "$1" = "$excluded" ] && return 1
	done
	return 0
}

# Prints the architecture guard macro a file carries, empty if it carries none.
guardMacroIn() {
	local candidate
	while read -r candidate; do
		[ -z "$candidate" ] && continue
		if isArchitectureMacro "$candidate"; then
			echo "$candidate"
			return 0
		fi
	done < <(grep -hoE '^#(ifdef|if defined\()\s*CAPSTONE_HAS_[A-Z0-9_]+' "$1" 2>/dev/null |
		grep -oE 'CAPSTONE_HAS_[A-Z0-9_]+' || true)
	echo ""
}

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
missingCount=0

for sourceFile in $(find arch -name "*.c" | sort); do
	if [ -n "$(guardMacroIn "$sourceFile")" ]; then
		skippedCount=$((skippedCount + 1))
		continue
	fi

	architectureDirectory=$(dirname "$sourceFile")
	guardMacro=""
	for sibling in "$architectureDirectory"/*.c; do
		[ "$sibling" = "$sourceFile" ] && continue
		guardMacro=$(guardMacroIn "$sibling")
		[ -n "$guardMacro" ] && break
	done

	if [ -z "$guardMacro" ]; then
		guardMacro=$(explicitMacroForDirectory "$architectureDirectory")
	fi

	if [ -z "$guardMacro" ]; then
		echo "ERROR: cannot determine guard macro for $sourceFile" >&2
		exit 1
	fi

	if [ "$checkOnly" -eq 1 ]; then
		echo "missing guard: $sourceFile (expected $guardMacro)"
		missingCount=$((missingCount + 1))
		continue
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
if [ "$checkOnly" -eq 1 ]; then
	echo "missing: $missingCount, guarded: $skippedCount"
	[ "$missingCount" -eq 0 ] || exit 1
else
	echo "guarded: $guardedCount, already guarded: $skippedCount"
fi
