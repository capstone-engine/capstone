:: Capstone disassembler engine (www.capstone-engine.org)
:: Build Capstone libs for X86 only (capstone.dll & capstone.lib) on Windows with CMake & Nmake
:: By Nguyen Anh Quynh, 2017

:: Uncomment below line to compile in Diet mode
:: cmake -DCMAKE_BUILD_TYPE=Release -DCAPSTONE_BUILD_DIET=ON -DCAPSTONE_X86_ONLY=1 -DCAPSTONE_BUILD_STATIC_RUNTIME=ON -G "NMake Makefiles" ..

cmake -DCMAKE_BUILD_TYPE=Release -DCAPSTONE_X86_ONLY=1 -DCAPSTONE_BUILD_STATIC_RUNTIME=ON -G "NMake Makefiles" ..

nmake
