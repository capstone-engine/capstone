# Benchmark

## Build capstone

```bash
mkdir build
cd build
cmake ..

#This last command is also where you can pass additional CMake configuration flags
#using `-D<key>=<value>`. Then to build use:
cmake --build . --config Release
cd ..
```

## Build benchmark

```bash
cd suite/benchmark
make
```

## test_iter_benchmark

```bash
./test_iter_benchmark
```

## test_file_benchmark

```bash
./test_file_benchmark
```
The optional `test_file_benchmark` arguments are:

- `[loop-count]` = optional loop count. Total number of bytes decoded and formatted is `<code-len> * [loop-count]`
- `<code-offset>` = offset of the code section (in decimal or 0x hex)
- `<code-len>` = length of the code section (in decimal or 0x hex)
- `<filename>` = 64-bit x86 binary file to decode and format
