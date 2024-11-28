# SPDX-License-Identifier: MIT
# Copyright (C) 2024 Andrew Quijano
# Contact: andrewquijano92@gmail.com
ARG VERSION=""

# Run in the root of the repo
# docker build -f ./packages/deb/Dockerfile -t packager .
FROM debian:bookworm-slim

# Install necessary tools for packaging
RUN apt-get -qq update && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y \
        fakeroot dpkg-dev dos2unix cmake

# Copy project files into the container
RUN mkdir /capstone
COPY . /capstone
WORKDIR /capstone/

# Using cmake, see BUILDING.md file
# For debug build change "Release" to "Debug"
ARG VERSION
RUN cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=1 -DPROJECT_VERSION=${VERSION} -DCMAKE_INSTALL_PREFIX=/usr
RUN cmake --build build

# List files before cmake install
# RUN find / -type f > /before-install.txt

# Make directories as needed
RUN mkdir -p /package-root/usr/include/capstone/
RUN mkdir -p /package-root/usr/lib/pkgconfig/
RUN mkdir -p /package-root/usr/bin/
RUN mkdir -p /package-root/usr/share/doc/libcapstone-dev

# Run cmake install
RUN cmake --install build --prefix /package-root/usr/

# List files after cmake install
# RUN find / -type f > /after-install.txt

# Create DEBIAN directory and control file
COPY ./packages/deb/control /package-root/DEBIAN/control

# Copy documentation over
COPY ./ChangeLog /package-root/usr/share/doc/libcapstone-dev
COPY ./CREDITS.TXT /package-root/usr/share/doc/libcapstone-dev
COPY ./HACK.TXT /package-root/usr/share/doc/libcapstone-dev
COPY ./LICENSE.TXT /package-root/usr/share/doc/libcapstone-dev
COPY ./README.md /package-root/usr/share/doc/libcapstone-dev
COPY ./SPONSORS.TXT /package-root/usr/share/doc/libcapstone-dev

# Generate MD5 checksums for all files and save to DEBIAN/md5sums
RUN cd /package-root && \
    find . -type f ! -path './DEBIAN/*' -exec md5sum {} + | sed 's| \./| |' > /package-root/DEBIAN/md5sums

# Update control file with the correct information
ARG VERSION
RUN INSTALLED_SIZE=$(du -sk /package-root | cut -f1) && \
    sed -i "s/^Installed-Size:.*/Installed-Size: ${INSTALLED_SIZE}/" /package-root/DEBIAN/control
RUN sed -i "s/^Version:.*/Version: ${VERSION}/" /package-root/DEBIAN/control

# Add triggers script to run ldconfig after installation
COPY ./packages/deb/triggers /package-root/DEBIAN/triggers

# Build the package
RUN fakeroot dpkg-deb --build /package-root /libcapstone-dev_${VERSION}_amd64.deb

# The user can now extract the .deb file from the container with something like
# docker run --rm -v $(pwd):/out packager bash -c "cp /libcapstone-dev.deb /out"
