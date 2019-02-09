# Regression testing
This directory contains a tool for regression testing core of Capstone

## Build
```
cd suite/cstest
make
```

## Usage
- Test for all closed issues
```
cd suite/cstest
./build/cstest ./issues.cs
```
- Test for some input from LLVM
```
cd suite/cstest
./build/cstest ../MC/AArch64/basic-a64-instructions.s.cs
```
- Test all
```
cd suite/cstest
make cstest
```
