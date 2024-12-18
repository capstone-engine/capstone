---
name: Bug report - Incorrect disassembly
about: Create a report about incorrect disassembly.
---

<!-- This template is meant for disassembly related bug reports, please be as descriptive as possible -->

### Work environment

<!-- Filling this table is mandatory -->

| Questions                                | Answers
|------------------------------------------|--------------------
| System Capstone runs on OS/arch/bits     | Debian arm 64, MacOS AArch64, MacOS x86, Windows x86 etc.
| Capstone module affected                 | ppc, x86, arm, aarch64 etc.
| Source of Capstone                       | `git clone`, brew, pip, release binaries etc.
| Version/git commit                       | v5.0.1, <commit hash>

<!-- INCORRECT DISASSEMBLY BUGS -->

### Instruction bytes giving faulty results

```
0x00,0x00,0x00,0x00
```

### Expected results

It should be:
```
<this or that>
```

### Steps to get the wrong result

With `cstool`:

```sh
cstool arm -d 0x00,0x00,0x00,0x00
```

or with `Python`

```python
CODE = b'\x90\x90\x90\x90'

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.detail = True
for insn in md.disasm(CODE, 0x1000):
  # Print the faulty disassembly
```

<!-- ADDITIONAL CONTEXT -->

### Additional Logs, screenshots, source code,  configuration dump, ...

Drag and drop zip archives containing the Additional info here, don't use external services or link.
Screenshots can be directly dropped here.
