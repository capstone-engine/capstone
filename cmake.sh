# Capstone disassembler engine (www.capstone-engine.org)
# Build Capstone libs (libcapstone.so & libcapstone.a) on *nix with CMake & make
# By Nguyen Anh Quynh, 2019

# Uncomment below line to compile in Diet mode
# cmake -DCMAKE_BUILD_TYPE=Release -DCAPSTONE_BUILD_DIET=ON ..

cmake -DCMAKE_BUILD_TYPE=Release ..

make -j8
