# Testing in Capstone

## Running tests

### Types of test and their location

_YAML test files_

These test files are consumed by the various `cstest` tools.
They contain all detail tests. As well as the LLVM regression tests (`MC` tests).

Directories group tests by the category they intent to test.

_Legacy (integration)_

Legacy tests which only printed to `stdout`. In practice they only test if the code segfaults.
Checking the produced output was not implemented.

### Testing tools and usage

#### `cstest`

`cstest` is the testing tool written in C. It is implemented in `suite/cstest/`
It consumes the `yaml` files and reports errors or mismatches for disassembled instructions and their details.

**Building**

> _Dependencies:_ `cstest` requires the `libyaml` library.

You build `cstest` by adding the `-DCAPSTONE_BUILD_CSTEST=1` option during configuration of the Capstone build.

If you build and install Capstone `cstest` gets installed as well.
Otherwise you find it in the build directory.

```bash
# Install libyaml
# sudo apt install libyaml-dev
# or
# sudo dnf install libyaml-devel
cd "<capstone-repo-root>"
# Optionally add the `-DENABLE_ASAN=1` flag.
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DCAPSTONE_BUILD_CSTEST=ON
cmake --build build --config Debug
cmake --install build --prefix "<install-prefix>"
```

Run the integration tests for `cstest` itself

```bash
./suite/cstest/test/integration_tests.py cstest
```

**Run the tests**

```bash
# Check supported options
cstest -h
# Run all
cstest tests/
```

Alternatively, you can use the `CMake` test manager.

```bash
# List available tests
ctest --test-dir build -N
# Run a specific test
ctest --test-dir build -R "<name>"
```

#### `cstest_py`

`cstest_py` is the testing tool written in Python. It is implemented in `bindings/python/cstest_py`
It consumes the `yaml` files and reports errors or mismatches for disassembled instructions and their details.

**Installing**

You need to install the Capstone Python bindings first and afterwards the `cstest_py`.

```bash
# Optionally, create a new virtual environment
python3 -m venv .venv
source .venv/bin/activate

cd bindings/python
pip install -e .
pip install -e cstest_py
cd ../..
```

Run the integration tests for `cstest_py` itself

```bash
./suite/cstest/test/integration_tests.py cstest_py
```

And run the tests

```bash
# Check supported options
cstest_py -h
# Run all
cstest_py tests/
```

## Add new tests

### Unit and integration tests

Add the source into `test/integration` or `test/unit` respectively and update the `CMakeLists.txt` file.

### YAML

There are very few fields which are mandatory to fill.
Check `suite/cstest/test/min_valid_test_file.yaml` to see which one.

- In general it is useful to just copy a previous test file and rewrite it accordingly.
- If you assign C enumeration identifiers to some fields (to check enumeration values),
ensure they are added on the `suite/cstest/include/test_mapping.h`. Otherwise, `cstest` cannot map the strings
to the values for comparison.
- Rarely used, but useful fields are: `name`, `skip`, `skip_reason`.

#### MC regression tests

The `MCUpdater` translates most test files of the LLVM MC regression tests into our YAML files.

The LLVM regression tests, check the bytes and assembly for all instructions of an architecture.
They do it by passing bytes or assembly to the `llvm-mc` and `FileCheck` tool and compare the output.
We capture this output and process it into YAML.
So you need to install `llvm-mc` and `FileCheck` for our updater to work.

To update the YAML MC regression tests, you need to install `Auto-Sync` and run the `MCUpdater`.

```bash
cd suite/auto-sync/
# Follow install instructions of Auto-Sync described in the README
# And run the updater:
./src/autosync/MCUpdater.py -a ARCH
ls build/mc_out/
# The produce yaml files. Copy them manually to tests/MC/ARCH
```

**Please note:**

Each of the LLVM test files can contain several `llvm-mc` commands to run on the same file.
This is done to test the same file with different CPU features enabled.
So it can test different assembly flavors etc.

In Capstone all modules enable always all CPU features (even if this is not
possible in reality).
Due to this, we always parse all `llvm-mc` commands but only write the last version of them to disk.
So if the same test file is tested with three different features enables, once with `FeatureA`, `FeatureB` and `FeatureC`
we only save the output with `FeatureC` enabled.

This might give you MC test files which fail due to valid but mismatching disassembly.
You can set the `skip` field for those tests and add a `skip_reason`.

Once https://github.com/capstone-engine/capstone/issues/1992 is resolved, we can
test all variants.
