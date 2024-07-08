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

Troubleshooting
------

If you get `cc: error: unrecognized argument to ‘-fsanitize=’ option: ‘fuzzer’` check if you have a workable
version of `libfuzz` installed. Also try to build with `CC=clang make`

Interpret OSS-Fuzz report
------

A reported bug by OSS-fuzz looks usually like this:

```
...
    #20 0x7f3a42062082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)
    #21 0x55ad814876dd in _start (build-out/fuzz_disasmnext+0x5246dd)

DEDUP_TOKEN: raise--abort--
AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: ABRT (/lib/x86_64-linux-gnu/libc.so.6+0x4300b) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e) in raise
==62==ABORTING
MS: 0 ; base unit: 0000000000000000000000000000000000000000
0x7,0xe8,0x3,0x4e,0xc0,0xf8,
\007\350\003N\300\370
```

It emits the bytes fed to Capstone in the last two lines.

The first byte determines the `arch+mode`. The following bytes the actual data producing the crash.

You can run `./fuzz_decode_platform` to get the `arch+mode` used:

```
./fuzz_decode_platform 0x7
cstool arch+mode = aarch64
```

And reproduce the bug with `cstool`:

```bash
# Make sureevery hex number has two digits!
cstool -d aarch64 0xe8,0x03,0x4e,0xc0,0xf8,
```

Make sure the every hex number has two digits (`0x3 -> 0x03`)!
`cstool` won't parse it correctly otherwise.

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
