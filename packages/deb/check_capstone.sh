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

# Path to the capstone.pc file
CAPSTONE_PC="$TEMP_DIR/usr/lib/pkgconfig/capstone.pc"

# Check if the capstone.pc file exists
if [[ ! -f "$CAPSTONE_PC" ]]; then
  echo "capstone.pc file not found in the package!"
  rm -rf "$TEMP_DIR"
  exit 1
fi

# Remove leading 'v' if present, e. g. v1.5.1 -> 1.5.1
if [[ "$EXPECTED_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    EXPECTED_VERSION=${EXPECTED_VERSION:1}
fi

# Check if the version follows the format X.Y.Z, e. g. 1.5.1 or 1.9.1
if [[ ! "$EXPECTED_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: Version must be in the format X.Y.Z"
    exit 1
fi


# Check the version in the capstone.pc file
ACTUAL_VERSION=$(grep "^Version:" "$CAPSTONE_PC" | awk '{print $2}')
if [[ "$ACTUAL_VERSION" != "$EXPECTED_VERSION" ]]; then
  echo "Version mismatch! Expected: $EXPECTED_VERSION, Found: $ACTUAL_VERSION"
  rm -rf "$TEMP_DIR"
  exit 1
fi

# Check if libcapstone.a is included in the package
LIBCAPSTONE_A="$TEMP_DIR/usr/lib/libcapstone.a"
if [[ ! -f "$LIBCAPSTONE_A" ]]; then
  echo "libcapstone.a not found in the package!"
  rm -rf "$TEMP_DIR"
  exit 1
fi

# Check if libcapstone.so is included in the package
LIBCAPSTONE_SO="$TEMP_DIR/usr/lib/libcapstone.so"
if [[ ! -f "$LIBCAPSTONE_SO" ]]; then
  echo "libcapstone.so not found in the package!"
  rm -rf "$TEMP_DIR"
  exit 1
fi

echo "libcapstone-dev.deb file is correct."
rm -rf "$TEMP_DIR"
exit 0
