# Regression testing
This directory contains a tool for regression testing core of Capstone

## Dependency

- MacOS users can install cmocka with:

```
brew install cmocka
```

- Or download & build from source code [Cmocka](https://git.cryptomilk.org/projects/cmocka.git)

- Build Cmocka

```
cd cmocka_dir
mkdir build
cd build
cmake ..
make
sudo make isntall
```

## Build

- Build `cstest`

```
cd suite/cstest
make
```

## Usage

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

## Using report tool

- Usage `python report.py -t <cstest_path> [-f <file_name.cs>] [-d <directory>]`

- Example: 

```
./report.py -t build/cstest -d ../MC/PowerPC/
./python report.py -t build/cstest -f issues.cs
```
