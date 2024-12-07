# Capstone Docker packaging

This assumes your working directory is in the `packages/deb/` directory. 
To build a Debian package for Capstone, run the script, where `<tag-name>` is going to be the version 
attached to both the `capstone.pc` file and the Debian package itself. The version is expected to be compliant with Debian versioning (a major/minor/patch), e. g. `5.0.4`. Debian versions can also support values to indicate pre-release, e. g. `6.0.0-Alpha1`.

**Note**: if a value such as `6.0.0-Alpha1` is provided, the major/minor/patch number is extracted for `capstone.pc`, which would have version `6.0.0`, but the Debian package would have the full version name on the control file.

**Note**: Currently the package is hard coded to the `amd64` architecture. Independently on what machine you built it. Also see [issue #2537](https://github.com/capstone-engine/capstone/issues/2537).

```bash
./setup.sh <tag-name>
```

The output Debian file would be in the form `libcapstone-dev_<tag-version>_amd64.deb`, as to match what would be expected in a standard Debian library package.

To confirm the necessary libraries and `capstone.pc` is filled correctly, there exists a `check_capstone.sh` script to confirm `libcapstone-dev` was built correctly. 

If you want to check the contents of the Debian package, use the following:
```bash
# Check the DEBIAN/ folder
dpkg-deb -e libcapstone-dev_<tag-version>_amd64.deb ./unpacked

# Check the content of the package, EXCEPT the DEBIAN/ folder
dpkg-deb -x libcapstone-dev_<tag-version>_amd64.deb ./unpacked
```
