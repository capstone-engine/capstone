#!/bin/bash

# Usage: ./check_capstone_pc.sh <path_to_deb_file> <expected_version>

DEB_FILE=$1
EXPECTED_VERSION=$2

# Check if the deb file exists
if [[ ! -f "$DEB_FILE" ]]; then
  echo "Debian package file not found!"
  exit 1
fi

# Create a temporary directory to extract the deb file
TEMP_DIR=$(mktemp -d)

# Extract the deb file
dpkg-deb -x "$DEB_FILE" "$TEMP_DIR"

# Remove leading 'v' if present, e. g. v1.5.1 -> 1.5.1
if [[ "$EXPECTED_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    EXPECTED_VERSION=${EXPECTED_VERSION:1}
fi

# Check if the version follows the format X.Y.Z, e. g. 1.5.1 or 1.9.1
if [[ ! "$EXPECTED_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: Version must be in the format X.Y.Z"
    exit 1
fi

# Extract the major version
major_version=$(echo "$EXPECTED_VERSION" | cut -d. -f1)
# Create the variable with the major version
libcapstone_name="libcapstone${major_version}"

# Check if libcapstone.so is included in the package
LIBCAPSTONE_SO="$TEMP_DIR/usr/lib/x86_64-linux-gnu/${libcapstone_name}.so"
if [[ ! -f "$LIBCAPSTONE_SO" ]]; then
  echo "${libcapstone_name}.so not found in the package!"
  rm -rf "$TEMP_DIR"
  exit 1
fi

echo "${libcapstone_name}.deb file is correct."
rm -rf "$TEMP_DIR"
exit 0