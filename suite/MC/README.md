# Input files for fuzzing input

These files were the legacy test files but replaced.
No it only is consumed by `test_corpus3.py` to generate input cases for the fuzzer.

### Test file formatting

**Format of input files:**
```
# ARCH, MODE, OPTION
<hexcode> = <assembly-text>
```

**Example**
```
# CS_ARCH_ARM, CS_MODE_ARM+CS_MODE_V8, None
0xa0,0x0b,0x71,0xee = vadd.f64 d16, d17, d16
...
```
