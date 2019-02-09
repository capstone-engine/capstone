# Regression testing
This directory contains a tool for regression testing core of Capstone

## Build
```
cd issues
make
```

## Usage
- Test for all closed issues
```
cd issues
./build/issues ./issues.cs
```
- Test for some input from LLVM
```
cd issues
./build/issues ../suite/MC/AArch64/basic-a64-instructions.s.cs
```
