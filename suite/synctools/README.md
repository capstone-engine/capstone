# synctool

## `convert_unit_tests.py`

### Help

```bash
$ python convert_unit_tests.py --help

usage: convert_unit_tests.py [-h] input output

Convert LLVM MC unit tests into Capstone MC unit tests

positional arguments:
  input       Input folder
  output      Output folder

optional arguments:
  -h, --help  show this help message and exit
```

### Usage Example

```bash
$ python convert_unit_tests.py /path/to/llvm-project/llvm/test/MC/AArch64 /path/to/capstone/suite/MC/AArch64

 > Processing: inst-directive-other.s
 > Processing: coff-align.s
 > Processing: inline-asm-modifiers.s
 > Processing: arm64-target-specific-sysreg.s
 > Processing: neon-crypto.s
  - Writting file: /path/to/capstone/suite/MC/AArch64/neon-crypto.s.cs
 > Processing: armv8.2a-uao.s
  - Writting file: /path/to/capstone/suite/MC/AArch64/armv8.2a-uao.s.cs
...SNIP...
```