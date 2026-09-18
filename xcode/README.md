Xcode Project for Capstone
================================================================================

The *Capstone.xcodeproj* project is an Xcode project that mimics the Visual
Studio solution for Capstone. It embeds nicely into Xcode workspaces. It has 3
targets:

* CapstoneStatic, producing `libcapstone.a`, Capstone as a static library;
* CapstoneDynamic, producing `libcapstone.dylib`, Capstone as a shared library;
* CapstoneFramework, producing `Capstone.framework`, Capstone as a macOS
  framework bundle containing the library and public headers.

The project is configured to include all targets and use the system
implementations of `malloc`, `calloc`, `realloc`, `free` and `vsnprintf`. This
can be modified by editing the *Preprocessor Macros* build setting of the
target you plan to use. These settings are all at the target level: no specific
overrides were used at the project level.

### Building

The project can be built in Xcode or using `xcodebuild`:

```sh
xcodebuild -target CapstoneStatic -configuration Release
xcodebuild -target CapstoneDynamic -configuration Release
xcodebuild -target CapstoneFramework -configuration Release
```

### Including the Xcode project in a workspace

There is a bug in how Xcode handles static libraries and dynamic libraries of
the same name. Currently, if you integrate the Capstone project in a workspace
and both the static *and* the dynamic libraries are built, if you try to link
against either, you will *always* link against the dynamic one. To work around
this issue, you can avoid building the dynamic library if you don't plan to use
it, or you could change the *Product Name* build setting of either.
