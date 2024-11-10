ARG VERSION=""
ARG LIBCAPSTONE_NAME=""

# Assume this is run from capstone/debian directory
# Run in the root of the repo
# docker build -f ./debian/Dockerfile -t packager .
FROM debian:bookworm-slim

# Install necessary tools for packaging
RUN apt-get -qq update && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y \
        fakeroot dpkg-dev dos2unix cmake

# Copy your project files into the container
RUN mkdir /capstone
COPY . /capstone
WORKDIR /capstone/ 

# Using cmake, see BUILDING.md file
# For debug build change "Release" to "Debug"
RUN cmake -B build -DCMAKE_BUILD_TYPE=Release -DCAPSTONE_BUILD_SHARED_LIBS=1
RUN cmake --build build

# List files before cmake install
# RUN find / -type f > /before-install.txt

# Run cmake install, by default everything goes into /usr/local
RUN cmake --install build

# List files after cmake install
# RUN find / -type f > /after-install.txt

# Make directories as needed
RUN mkdir -p /package-root/usr/include/capstone/
RUN mkdir -p /package-root/usr/lib/x86_64-linux-gnu/pkgconfig/
RUN mkdir -p /package-root/usr/share/doc/libcapstone-dev/

# Copy /usr/local/include/capstone/ to /package-root/usr/local/include/capstone/ and all other cases
RUN cp -r /usr/local/include/capstone/* /package-root/usr/include/capstone/
RUN cp -r /usr/local/lib/pkgconfig/capstone* /package-root/usr/lib/x86_64-linux-gnu/pkgconfig/
RUN cp -r /usr/local/lib/libcapstone.a /package-root/usr/lib/x86_64-linux-gnu/
# Need libcapstone.a too

# Create DEBIAN directory and control file
COPY ./libcapstone-dev/control /package-root/DEBIAN/control

# Update capstone.pc file with the correct version and remove archs field
# Update control file with the correct version
# TODO, I think pkgconfig needs to point from /usr/local to /usr?
ARG VERSION
ARG LIBCAPSTONE_NAME
RUN sed -i "s/^Version:.*/Version: ${VERSION}/" /package-root/DEBIAN/control
RUN sed -i "s/^Version:.*/Version: ${VERSION}/" /package-root/usr/lib/x86_64-linux-gnu/pkgconfig/capstone.pc
RUN sed -i "s/Depends: <libcapstone-name> (= <version-placeholder>)/Depends: ${LIBCAPSTONE_NAME} (= ${VERSION})/" /package-root/DEBIAN/control
RUN sed -i "/^archs=/d" /package-root/usr/lib/x86_64-linux-gnu/pkgconfig/capstone.pc

# Build the package
RUN fakeroot dpkg-deb --build /package-root /libcapstone-dev.deb

# The user can now extract the .deb file from the container with something like
# docker run --rm -v $(pwd):/out packager bash -c "cp /libcapstone-dev.deb /out"
