Fuzzing
===============


Build the fuzz target
-------

To build the fuzz target, you can simply run `make` with appropriate flags set :
```
ASAN_OPTIONS=detect_leaks=0 CXXFLAGS="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize=fuzzer-no-link" CFLAGS="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize=fuzzer-no-link" LDFLAGS="-fsanitize=address" make
```
You can replace `address` with another sanitizer : `memory` or `undefined`
The fuzz target is then `suite/fuzz/fuzz_bindisasm2`

You can find this in travis configuration `.travis.yml`

Another way is to use oss-fuzz, see https://github.com/google/oss-fuzz/blob/master/projects/capstone/build.sh

Fuzz drivers
------

There are custom drivers :
- driverbin.c : prints cstool command before running one input
- drivermc.c : converts MC test data to raw binary data before running as many inputs as there are lines in a file
- onefile.c : simple one file driver

For libfuzzer, the preferred main function is now to use linker option `-fsanitize=fuzzer`

Fuzzit integration
------

Travis will build the fuzz target with the different sanitizers.
Then, Travis will launch sanity fuzzit jobs as part of continuous integration (for each of the sanitizers)
The fuzzit target ids are stored in a configuration file fuzzitid.txt and used by fuzzit.sh
