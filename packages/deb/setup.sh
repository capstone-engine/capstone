# SPDX-License-Identifier: MIT
# Copyright (C) 2024 Andrew Quijano
# Contact: andrewquijano92@gmail.com

# !/bin/bash
set -eu

# Function to get the current Ubuntu version
get_os_version() {
    lsb_release -i -s 2>/dev/null
}

# Check if the script is running in the ./packages/deb folder
if [[ $(basename "$PWD") != "deb" ]]; then
    echo "ERROR: Script must be run from the ./deb directory"
    exit 1
fi

OS_VERSION=$(get_os_version)
if [[ "$OS_VERSION" != "Ubuntu" && "$OS_VERSION" != "Debian" ]]; then
    echo "ERROR: OS is not Ubuntu or Debian and unsupported"
    exit 1
fi

# Get the version number as an input
# Check if version argument is provided
if [[ $# -ne 1 ]]; then
    echo "ERROR: Version argument is required"
    exit 1
fi

# Get the version number as an input
version=$1

# Remove leading 'v' if present, e. g. v1.5.1 -> 1.5.1
if [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    version=${version:1}
fi

# Check if the version follows the format for Debian Packages
if [[ ! "$version" =~ ^[0-9]+(.[0-9]+)*(-[A-Za-z0-9]+)?$ ]]; then
  echo "ERROR: Version must be in a valid Debian package format"
  exit 1
fi

# Now build the packager container from that
pushd ../../
docker build -f ./packages/deb/Dockerfile -t packager --build-arg VERSION="${version}" .
popd

# Copy deb file out of container to host
docker run --rm -v $(pwd):/out packager bash -c "cp /*.deb /out"

# Check which files existed before and after 'make install' was executed.
# docker run --rm -v $(pwd):/out packager bash -c "cp /before-install.txt /out"
# docker run --rm -v $(pwd):/out packager bash -c "cp /after-install.txt /out"
# diff before-install.txt after-install.txt
