#!/bin/sh

pause() {
  echo "Press any key to exit"
  read -r dummyvar
  exit
}

print_and_pause() {
  echo "$1"
  pause
}

check_llvm() {
  llvm_root="$1"
  tblgen="$2"

  if [ ! -h "../vendor/llvm_root" ]; then
    echo "[*] Create symlink '../vendor/llvm_root -> $llvm_root'."
    ln -s "$llvm_root" ../vendor/llvm_root
  fi

  if [ ! -f "$tblgen" ]; then
    echo "[x] llvm-tblgen not found at '$tblgen'"
    pause
  fi
}

verify_status() {
  status=$1
  error_msg="$2"

  if [ "$status" != 0 ]; then
    echo "$error_msg"
    pause
  fi
}

fetch_llvm_root() {
  current_dir="$PWD"
  if [ $# -eq 2 ]; then
    if [ "$1" = "--wsl" ]; then
      has_wsl=1
    else
      has_wsl=0
    fi
    tblgen_dir=$(dirname "$2")
  elif [ $# -eq 1 ]; then
    tblgen_dir=$(dirname "$1")
    has_wsl=0
  else
    echo "[X] Invalid number of arguments passed to fetch_llvm_root"
    pause
  fi
  
  cd "$tblgen_dir" || print_and_pause "[X] Failed to enter the tblgen directory"
  llvm_root="$(git rev-parse --show-toplevel)/llvm"
  wsl_llvm_root="$llvm_root"
  cd "$current_dir" || print_and_pause "[X] Failed to re-enter the current working directory"

  if [ $has_wsl -ne 0 ]; then
    wsl_llvm_root=$(wslpath -m "$llvm_root")
  fi
}

build_dir="build"
llvm_c_inc_dir="llvm_c_inc"
llvm_inc_dir="llvm_inc"
translator_dir="trans_out"
ts_so_dir="ts_libs"
diff_dir="diff_out"

setup_build_dir() {
  if [ ! -d "$build_dir" ]; then
    echo "[*] Create ./$build_dir directory"
    mkdir $build_dir
  fi
  cd "$build_dir" || print_and_pause "[X] Failed to enter the build directory"

  if [ ! -d "$llvm_inc_dir" ]; then
    echo "[*] Create ./$build_dir/$llvm_inc_dir directory"
    mkdir $llvm_inc_dir
  fi  

  if [ ! -d "$llvm_c_inc_dir" ]; then
    echo "[*] Create ./$build_dir/$llvm_c_inc_dir directory"
    mkdir $llvm_c_inc_dir
  fi

  if [ ! -d "$translator_dir" ]; then
    echo "[*] Create ./$build_dir/$translator_dir directory"
    mkdir $translator_dir
  fi

  if [ ! -d "$ts_so_dir" ]; then
    echo "[*] Create ./$build_dir/$ts_so_dir directory"
    mkdir $ts_so_dir
  fi

  if [ ! -d "$diff_dir" ]; then
    echo "[*] Create ./$build_dir/$diff_dir directory"
    mkdir $diff_dir
  fi  
}

#
# Main
#

supported="ARM"

if [ $# -ne 3 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
  echo "$0 <arch> <path-llvm-tblgen> <llvm-release-commit>"
  echo "Currently supported architectures: $supported"
  pause
fi

# if we are executing this under wsl on windows we want to correct the path to the exe file
if [ -n "$WSL_DISTRO_NAME" ]; then
  tblgen=$(wslpath -u "$2")
  fetch_llvm_root --wsl "$tblgen"
else
  tblgen="$2"
  fetch_llvm_root "$2"
fi

arch="$1"
# path_to_llvm is passed to tblgen, so if we are running this under wsl we got to make sure the path is a valid windows path
# if we aren't in wsl this is identical to llvm_root
path_to_llvm="$wsl_llvm_root"
llvm_release_commit="$3"
llvm_target_dir="$1"

if ! echo "$supported" | grep -q -w "$arch" ; then
  echo "[x] $arch is not supported by the updater. Supported are: $supported"
  pause
fi

setup_build_dir
check_llvm "$llvm_root" "$tblgen"

echo "[*] Generate Disassembler tables..."
"$tblgen" --printerLang=CCS --gen-disassembler -I "$path_to_llvm/include/" -I "$path_to_llvm/lib/Target/$llvm_target_dir/" "$path_to_llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_c_inc_dir"/""$arch""GenDisassemblerTables.inc"
verify_status $? "[X] Failed to generate disassembler tables for capstone"
"$tblgen" --printerLang=C++ --gen-disassembler -I "$path_to_llvm/include/" -I "$path_to_llvm/lib/Target/$llvm_target_dir/" "$path_to_llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_inc_dir"/""$arch""GenDisassemblerTables.inc"
verify_status $? "[X] Failed to generate disassembler tables for llvm"

echo "[*] Generate AsmWriter tables..."
"$tblgen" --printerLang=CCS --gen-asm-writer -I "$path_to_llvm/include/" -I "$path_to_llvm/lib/Target/$llvm_target_dir/" "$path_to_llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_c_inc_dir"/""$arch""GenAsmWriter.inc"
verify_status $? "[X] Failed to generate AsmWriter tables for capstone"
"$tblgen" --printerLang=C++ --gen-asm-writer -I "$path_to_llvm/include/" -I "$path_to_llvm/lib/Target/$llvm_target_dir/" "$path_to_llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_inc_dir"/""$arch""GenAsmWriter.inc"
verify_status $? "[X] Failed to generate AsmWriter tables for llvm"

echo "[*] Generate RegisterInfo tables..."
"$tblgen" --printerLang=CCS --gen-register-info -I "$path_to_llvm/include/" -I "$path_to_llvm/lib/Target/$llvm_target_dir/" "$path_to_llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_c_inc_dir"/""$arch""GenRegisterInfo.inc"
verify_status $? "[X] Failed to generate RegisterInfo tables for capstone"

echo "[*] Generate InstrInfo tables..."
"$tblgen" --printerLang=CCS --gen-instr-info -I "$path_to_llvm/include/" -I "$path_to_llvm/lib/Target/$llvm_target_dir/" "$path_to_llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_c_inc_dir"/""$arch""GenInstrInfo.inc"
verify_status $? "[X] Failed to generate InstrInfo tables for capstone"

echo "[*] Generate SubtargetInfo tables..."
"$tblgen" --printerLang=CCS --gen-subtarget -I "$path_to_llvm/include/" -I "$path_to_llvm/lib/Target/$llvm_target_dir/" "$path_to_llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_c_inc_dir"/""$arch""GenSubtargetInfo.inc"
verify_status $? "[X] Failed to generate SubtargetInfo tables for capstone"

echo "[*] Generate Mapping tables..."
"$tblgen" --printerLang=CCS --gen-asm-matcher -I "$path_to_llvm/include/" -I "$path_to_llvm/lib/Target/$llvm_target_dir/" "$path_to_llvm/lib/Target/$llvm_target_dir/$arch.td"
verify_status $? "[X] Failed to generate Mapping tables for capstone"

echo "[*] Generate System Register tables..."
"$tblgen" --printerLang=CCS --gen-searchable-tables -I "$path_to_llvm/include/" -I "$path_to_llvm/lib/Target/$llvm_target_dir/" "$path_to_llvm/lib/Target/$llvm_target_dir/$arch.td"
verify_status $? "[X] Failed to generate System Register tables for capstone"

if find -- "../vendor/tree-sitter-cpp/" -prune -type d -empty | grep -q '^'; then
  echo "[*] Clone tree-sitter-cpp..."
  git submodule update --init --recursive
fi

echo "[*] Translate LLVM source files..."
cd ../CppTranslator/ || print_and_pause "[X] Failed to enter the CppTranslator directory"
if [ ! -d "./.venv" ] ; then
  echo "[*] Setup python3 venv and install dependencies"
  python3 -m venv .venv
  verify_status $? "[X] Failed to create a venv"
  . ./.venv/bin/activate
  pip3 install -r requirements.txt
  verify_status $? "[X] pip failed to install requirements"
else
  . ./.venv/bin/activate
fi
python3 CppTranslator.py -a "$arch" -g "../vendor/tree-sitter-cpp/" -l "../build/ts_libs/ts-cpp.so"
verify_status $? "[X] Translation Failed"

echo "[*] Run differ..."
python3 Differ.py -a "$arch" -g "../vendor/tree-sitter-cpp"
verify_status $? "[X] Differ Failed"
cd ../build || print_and_pause "[X] Failed to enter the build directory"

cs_root=$(git rev-parse --show-toplevel)

cd "$llvm_root" || print_and_pause "[X] Failed to enter the llvm root directory"
llvm_release_tag=$(git describe --tag "$llvm_release_commit")
cd "$cs_root/suite/auto-sync/build" || print_and_pause "[X] Failed to enter the build directory inside auto-sync"

cs_arch_dir="$cs_root/arch/$arch/"
cs_inc_dir="$cs_root/include/capstone"

into_arch_main_header=$arch"GenCSInsnEnum.inc "$arch"GenCSFeatureEnum.inc "$arch"GenCSRegEnum.inc "$arch"GenCSSystemRegisterEnum.inc"
header_file=$(echo "$arch" | awk '{print tolower($0)}')
main_header="$cs_inc_dir/$header_file.h"

for f in $into_arch_main_header; do
  python3 ../PatchMainHeader.py --header "$main_header" --inc "$f"
done

for f in "$arch"*.inc; do
  if ! echo "$into_arch_main_header" | grep -q -w "$f"; then
    sed -i "s|LLVM-commit: <commit>|LLVM-commit: $llvm_release_commit|g" "$f"
    sed -i "s|LLVM-tag: <tag>|LLVM-tag: $llvm_release_tag|g" "$f"
    cp "$f" "$cs_arch_dir"
    echo "[*] Copy $f"
  fi
done

for f in "$llvm_c_inc_dir/$arch"*; do
  if [ -f "$f" ]; then
    sed -i "s|LLVM-commit: <commit>|LLVM-commit: $llvm_release_commit|g" "$f"
    sed -i "s|LLVM-tag: <tag>|LLVM_tag: $llvm_release_tag|g" "$f"
    cp "$f" "$cs_arch_dir"
    echo "[*] Copy $f"
  fi
done

for f in "$diff_dir/$arch"*; do
  if [ -f "$f" ]; then
    sed -i "s|LLVM-commit: <commit>|LLVM-commit: $llvm_release_commit|g" "$f"
    sed -i "s|LLVM-tag: <tag>|LLVM-tag: $llvm_release_tag|g" "$f"
    cp "$f" "$cs_arch_dir"
    echo "[*] Copy $f"
  fi
done

echo "[*] Apply patches to inc files"

cd "$cs_root" || print_and_pause "[X] Failed to enter capstone's root directory"
p_dir="$cs_root/suite/auto-sync/inc_patches"

for f in "$p_dir"/*; do
  if [ -f "$f" ]; then
    echo "[*] Apply $f"
    git apply "$f"
  fi
done

pause
