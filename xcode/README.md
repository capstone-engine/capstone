Xcode Project for Capstone
================================================================================

The *Capstone.xcodeproj* project is an Xcode project that mimicks the Visual
Studio solution for Capstone. It embeds nicely into Xcode workspaces. It has 13
targets, two of which are the most likely to be of interest:

* CapstoneStatic, producing `libcapstone.a`, Capstone as a static library;
* CapstoneDynamic, producing `libcapstone.dylib`, Capstone as a shared library;
* test, test_arm, test_arm64, test_detail, test_mips, test_ppc, test_skipdata,
	test_sparc, test_systemz, test_xcore, testing all the things.

The project is configured to include all targets and use the system
implementations of `malloc`, `calloc`, `realloc`, `free` and `vsnprintf`. This
can be modified by editing the *Preprocessor Macros* build setting of either
CapstoneStatic or CapstoneDynamic, whichever you plan to use. These settings are
all at the target level: no specific overrides were used at the project level.

### A Word of Warning: Static vs. Shared Library

There is a bug in how Xcode handles static libraries and dynamic libraries of
the same name. Currently, if you integrate the Capstone project in a workspace
and both the static *and* the dynamic libraries are built, if you try to link
against either, you will *always* link against the dynamic one. To work around
this issue, you can avoid building the dynamic library if you don't plan to use
it, or you could change the *Product Name* build setting of either.