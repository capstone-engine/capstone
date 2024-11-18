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
RUN cmake -B build -DCMAKE_BUILD_TYPE=Release -DCAPSTONE_BUILD_SHARED_LIBS=1
RUN cmake --build build

# List files before cmake install
# RUN find / -type f > /before-install.txt

# Make directories as needed
RUN mkdir -p /package-root/usr/include/capstone/
RUN mkdir -p /package-root/usr/lib/pkgconfig/
RUN mkdir -p /package-root/usr/bin/

# Run cmake install
RUN cmake --install build --prefix /package-root/usr/

# List files after cmake install
# RUN find / -type f > /after-install.txt

# Create DEBIAN directory and control file
COPY ./packages/deb/control /package-root/DEBIAN/control

# Update capstone.pc file with the correct version and remove archs field
# Update control file with the correct version
ARG VERSION
RUN sed -i "s/^Version:.*/Version: ${VERSION}/" /package-root/DEBIAN/control
RUN sed -i "s/^Version:.*/Version: ${VERSION}/" /package-root/usr/lib/pkgconfig/capstone.pc
RUN sed -i "/^archs=/d" /package-root/usr/lib/pkgconfig/capstone.pc

# Add triggers script to run ldconfig after installation
COPY ./packages/deb/triggers /package-root/DEBIAN/triggers

# Build the package
RUN fakeroot dpkg-deb --build /package-root /libcapstone-dev.deb

# The user can now extract the .deb file from the container with something like
# docker run --rm -v $(pwd):/out packager bash -c "cp /libcapstone-dev.deb /out"
