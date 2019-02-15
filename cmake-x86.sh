# Capstone disassembler engine (www.capstone-engine.org)
# Build Capstone libs for X86 only (libcapstone.so & libcapstone.a) on *nix with CMake & make
# By Nguyen Anh Quynh, 2019

# Uncomment below line to compile in Diet mode
# cmake -DCMAKE_BUILD_TYPE=Release -DCAPSTONE_BUILD_DIET=ON -DCAPSTONE_X86_ONLY=1 ..

cmake -DCMAKE_BUILD_TYPE=Release -DCAPSTONE_X86_ONLY=1 ..

make -j8
