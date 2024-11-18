Incomplete Debian package implementation.
It can be used to generate an easily installable Capstone, but misses a lot of
mandatory things to add it in the Debian repos (`debian/control` is incomplete, no dependencies added etc.).

You can build the package by dispatching the `Build Debian Package` workflow or executing the commands in the `Dockerfile`.
It assumes the current commit is tagged and `"$(git describe --tags --abbrev=0)"` returns a valid version number.
The package is uploaded as artifact.
