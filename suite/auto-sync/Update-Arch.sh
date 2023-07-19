#!/bin/sh

check_llvm() {
  llvm_root=$1
  tblgen=$2

  if [ ! -e "../vendor/llvm_root" ]; then
    echo "[*] Create symlink '../vendor/llvm_root -> $llvm_root'."
    ln -s "$llvm_root" ../vendor/llvm_root
  fi

  if [ ! -f $tblgen ]; then
    echo "[x] llvm-tblgen not found at '$tblgen'"
    exit
  fi
}


llvm_c_inc_dir="llvm_c_inc"
llvm_inc_dir="llvm_inc"
translator_dir="trans_out"
ts_so_dir="ts_libs"
diff_dir="diff_out"

setup_build_dir() {
  if [ ! -d "$llvm_inc_dir" ]; then
    echo "[*] Create ./$llvm_inc_dir directory"
    mkdir $llvm_inc_dir
  fi  

  if [ ! -d "$llvm_c_inc_dir" ]; then
    echo "[*] Create ./$llvm_c_inc_dir directory"
    mkdir $llvm_c_inc_dir
  fi

  if [ ! -d "$translator_dir" ]; then
    echo "[*] Create ./$translator_dir directory"
    mkdir $translator_dir
  fi

  if [ ! -d "$ts_so_dir" ]; then
    echo "[*] Create ./$ts_so_dir directory"
    mkdir $ts_so_dir
  fi

  if [ ! -d "$diff_dir" ]; then
    echo "[*] Create ./$diff_dir directory"
    mkdir $diff_dir
  fi  
}

#
# Main
#

supported="ARM"

if [ $# -ne 3 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
  echo "$0 <arch> <path-llvm-project> <llvm-release-commit>"
  echo "\nCurrently supported architectures: $supported"
  exit
fi

arch="$1"
llvm_root="$2"
llvm_release_commit="$3"
tblgen="$llvm_root/build/bin/llvm-tblgen"
llvm_target_dir="$1"

if ! echo $supported | grep -q -w "$arch" ; then
  echo "[x] $arch is not supported by the updater. Supported are: $supported"
  exit
fi

if [ $arch = "PPC" ]; then
  llvm_target_dir="PowerPC"
fi

setup_build_dir
check_llvm $llvm_root $tblgen

echo "[*] Generate Disassembler tables..."
$tblgen --printerLang=CCS --gen-disassembler -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_c_inc_dir"/"$arch"GenDisassemblerTables.inc"
$tblgen --printerLang=C++ --gen-disassembler -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_inc_dir"/"$arch"GenDisassemblerTables.inc"

echo "[*] Generate AsmWriter tables..."
$tblgen --printerLang=CCS --gen-asm-writer -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_c_inc_dir"/"$arch"GenAsmWriter.inc"
$tblgen --printerLang=C++ --gen-asm-writer -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_inc_dir"/"$arch"GenAsmWriter.inc"

echo "[*] Generate RegisterInfo tables..."
$tblgen --printerLang=CCS --gen-register-info -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_c_inc_dir"/"$arch"GenRegisterInfo.inc"

echo "[*] Generate InstrInfo tables..."
$tblgen --printerLang=CCS --gen-instr-info -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_c_inc_dir"/"$arch"GenInstrInfo.inc"

echo "[*] Generate SubtargetInfo tables..."
$tblgen --printerLang=CCS --gen-subtarget -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_c_inc_dir"/"$arch"GenSubtargetInfo.inc"

echo "[*] Generate Mapping tables..."
$tblgen --printerLang=CCS --gen-asm-matcher -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td"

echo "[*] Generate System Register tables..."
$tblgen --printerLang=CCS --gen-searchable-tables -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td"
sed -i "s/##ARCH##/$arch/g" __ARCH__GenCSSystemRegisterEnum.inc
sed -i "s/##ARCH##/$arch/g" __ARCH__GenSystemRegister.inc
cp __ARCH__GenCSSystemRegisterEnum.inc $arch"GenCSSystemRegisterEnum.inc"
cp __ARCH__GenSystemRegister.inc $arch"GenSystemRegister.inc"

if find -- "../vendor/tree-sitter-cpp/" -prune -type d -empty | grep -q '^'; then
  echo "[*] Clone tree-sitter-cpp..."
  git submodule update --init --recursive
fi

echo "[*] Translate LLVM source files..."
cd ../CppTranslator/
if [ ! -d "./.venv" ] ; then
  echo "[*] Setup python3 venv and install dependencies"
  python3 -m venv .venv
  . ./.venv/bin/activate
  pip3 install -r requirements.txt
else
  . ./.venv/bin/activate
fi
./CppTranslator.py -a "$arch" -g "../vendor/tree-sitter-cpp/" -l "../build/ts_libs/ts-cpp.so"
echo "[*] Run differ..."
./Differ.py -a "$arch" -g "../vendor/tree-sitter-cpp"
cd ../build

cs_root=$(git rev-parse --show-toplevel)

cd $llvm_root
llvm_release_tag=$(git describe --tag $llvm_release_commit)
cd "$cs_root/suite/auto-sync/build"

cs_arch_dir="$cs_root/arch/$arch/"
cs_inc_dir="$cs_root/include/capstone"

into_arch_main_header=$arch"GenCSInsnEnum.inc "$arch"GenCSFeatureEnum.inc "$arch"GenCSRegEnum.inc "$arch"GenCSSystemRegisterEnum.inc"
header_file=$(echo "$arch" | awk '{print tolower($0)}')
main_header="$cs_inc_dir/$header_file.h"

for f in $into_arch_main_header; do
  ../PatchMainHeader.py --header "$main_header" --inc "$f"
done

for f in $(ls | grep "\.inc"); do
  if ! echo $into_arch_main_header | grep -q -w $f ; then
    sed -i "s/LLVM-commit: <commit>/LLVM-commit: $llvm_release_commit/g" $f
    sed -i "s/LLVM-tag: <tag>/LLVM-tag: $llvm_release_tag/g" $f
    cp $f $cs_arch_dir
    echo "[*] Copy $f"
  fi
done
for f in $(ls $llvm_c_inc_dir/$arch*); do
  sed -i "s/LLVM-commit: <commit>/LLVM-commit: $llvm_release_commit/g" $f
  sed -i "s/LLVM-tag: <tag>/LLVM-tag: $llvm_release_tag/g" $f
  cp $f $cs_arch_dir
  echo "[*] Copy $f"
done

for f in $(ls $diff_dir/$arch*); do
  sed -i "s/LLVM-commit: <commit>/LLVM-commit: $llvm_release_commit/g" $f
  sed -i "s/LLVM-tag: <tag>/LLVM-tag: $llvm_release_tag/g" $f
  cp $f $cs_arch_dir
  echo "[*] Copy $f"
done

echo "[*] Apply patches to inc files"

cd $cs_root
p_dir="$cs_root/suite/auto-sync/inc_patches"
for f in $(ls $p_dir); do
  echo "[*] Apply $f"
  git apply "$p_dir/$f"
done
