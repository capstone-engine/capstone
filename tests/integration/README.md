This directory contains some test code to show how to use Capstone API.

- test_iter.c:
  This code shows how to use the API cs_disasm_iter() to decode one instruction at
  a time inside a loop.

- test_customized_mnem.c:
  This code shows how to use MNEMONIC option to customize instruction mnemonic
  at run-time, and then how to reset the engine to use the default mnemonic.

- test_winkernel.cpp
  This code shows how to use Capstone from a Windows driver.
