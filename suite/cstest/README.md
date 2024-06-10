# Regression testing
This directory contains a tool for regression testing core of Capstone

## Dependency

- MacOS users can install cmocka with:

```
brew install cmocka
```

- Or download & build from source code [Cmocka](https://git.cryptomilk.org/projects/cmocka.git)

- Build Cmocka

## Build

You can build `cstest` with `cmake` when building Capstone. Just pass the `CAPSTONE_BUILD_CSTEST` flag
during configuration.

Alternatively you can use the `build_cstest.sh` file in this directory.

## Usage

- Usage: `cstest [-e] [-f <file_name.cs>] [-d <directory>]`
	- `-e` : test all commented test

- Test for all closed issues

```
cd suite/cstest
./build/cstest -f ./issues.cs
```

- Test for some input from LLVM

```
cd suite/cstest
./build/cstest -f ../MC/AArch64/basic-a64-instructions.s.cs
```

- Test for all cs file in a folder

```
cd suite/cstest
./build/cstest -d ../MC
```

- Test all

```
cd suite/cstest
make cstest
```

## Report tool

- Usage `cstest_report.py [-Dc] -t <cstest_path> [-f <file_name.cs>] [-d <directory>]`
	- `-D` : print details
	- `-c` : auto comment out failed test

- Example: 

```
./cstest_report.py -t build/cstest -d ../MC/PowerPC/
./cstest_report.py -t build/cstest -f issues.cs
```
