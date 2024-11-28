# SPDX-License-Identifier: MIT
# Copyright (C) 2024 Andrew Quijano
# Contact: andrewquijano92@gmail.com

#!/bin/bash
set -eu

# Usage: ./check_capstone_pc.sh <path_to_deb_file>

DEB_FILE=$1

# Check if the deb file exists
if [[ ! -f "$DEB_FILE" ]]; then
  echo "Debian package file not found!"
  exit 1
fi

# Create a temporary directory to extract the deb file
TEMP_DIR=$(mktemp -d)

# Extract the deb file
dpkg-deb -x "$DEB_FILE" "$TEMP_DIR"

# Check if the capstone.pc file exists
CAPSTONE_PC="$TEMP_DIR/usr/lib/x86_64-linux-gnu/pkgconfig/capstone.pc"
if [[ ! -f "$CAPSTONE_PC" ]]; then
  echo "capstone.pc file not found in the package!"
  rm -rf "$TEMP_DIR"
  exit 1
fi

# Check if libcapstone.a is included in the package
LIBCAPSTONE_A="$TEMP_DIR/usr/lib/x86_64-linux-gnu/libcapstone.a"
if [[ ! -f "$LIBCAPSTONE_A" ]]; then
  echo "libcapstone.a not found in the package!"
  rm -rf "$TEMP_DIR"
  exit 1
fi

# Check if libcapstone.so is included in the package
LIBCAPSTONE_SO="$TEMP_DIR/usr/lib/x86_64-linux-gnu/libcapstone.so"
if [[ ! -f "$LIBCAPSTONE_SO" ]]; then
  echo "libcapstone.so not found in the package!"
  rm -rf "$TEMP_DIR"
  exit 1
fi

echo "libcapstone-dev.deb file is correct."
rm -rf "$TEMP_DIR"
exit 0
