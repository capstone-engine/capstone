Capstone needs to support features which were removed by LLVM in the past.
All the steps described must be done in the LLVM repository.

To get the old features back we copy them from the old `.td` files and include them in the new ones.

To include removed features from previous LLVM versions do the following:

1. Checkout the last LLVM version the feature was present.
2. Copy all feature related definitions into a `<ARCH>Deprecated.td` file.
3. Checkout the newest LLVM version again.
4. Wrap the different definition types in include guards. For example the `InstrInfo` definitions could be included in:

```
#ifndef INCLUDED_CAPSTONE_DEPR_INSTR
#ifdef CAPSTONE_DEPR_INSTR
#define INCLUDED_CAPSTONE_DEPR_INSTR // Ensures it is only included once

[Instruction definitions of removed feature]

#endif // INCLUDED_CAPSTONE_DEPR_INSTR
#endif // CAPSTONE_DEPR_INSTR
```

Note that the order of `#ifndef` and `#ifdef` matters (otherwise you'll get an error from `tblgen`).

4. Include the definitions in the current definition files with:

```
#define CAPSTONE_DEPR_INSTR
include "<ARCH>Deprecated.md"
```

- It is possible that you have to change some definitions slightly (e.g.: `GCCBuiltin` -> `ClangBuiltin`).
- Some new processors might need to have the feature flag (`Has<DeprecatedFeature>`) added to their `UnsupportedFeatures` list.
