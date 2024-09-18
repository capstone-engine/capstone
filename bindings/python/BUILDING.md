0. This documentation explains how to install the Python bindings for Capstone
   from source. If you want to install it from a PyPi package (recommended if
   you are on Windows), see README.txt.

1. To install Capstone and the Python bindings on *nix, run the command below:

```
pip install bindings/python/
```

2. The tests directory contains some test code to show how to use the Capstone API.

- test_lite.py
  Similarly to test_basic.py, but this code shows how to use disasm_lite(), a lighter
  method to disassemble binary. Unlike disasm() API (used by test_basic.py), which returns
  CsInsn objects, this API just returns tuples of (address, size, mnemonic, op_str).

  The main reason for using this API is better performance: disasm_lite() is at least
  20% faster than disasm(). Memory usage is also less. So if you just need basic
  information out of disassembler, use disasm_lite() instead of disasm().
