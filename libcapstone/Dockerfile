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
ARG LIBCAPSTONE_NAME
RUN mkdir -p /package-root/usr/lib/x86_64-linux-gnu/
RUN mkdir -p /package-root/usr/share/doc/${LIBCAPSTONE_NAME}

# Copy files to the package root
RUN cp -r /usr/local/lib/libcapstone* /package-root/usr/lib/x86_64-linux-gnu/
# RUN cp /usr/share/doc/${LIBCAPSTONE_NAME}

# Check if there is exactly one file in /package-root/usr/local/lib and rename it
RUN files=$(ls /package-root/usr/lib/x86_64-linux-gnu/libcapstone*.so) && \
    if [ $(echo "$files" | wc -l) -eq 1 ]; then \
        mv $files /package-root/usr/lib/x86_64-linux-gnu/${LIBCAPSTONE_NAME}.so; \
    else \
        echo "Error: Expected exactly one file in /package-root/usr/local/lib, found $(echo "$files" | wc -l)"; \
        exit 1; \
    fi

# Create DEBIAN directory and control file
COPY ./libcapstone/control /package-root/DEBIAN/control

# Update capstone.pc file with the correct version and remove archs field
# Update control file with the correct version
ARG VERSION
ARG LIBCAPSTONE_NAME
RUN sed -i "s/^Version:.*/Version: ${VERSION}/" /package-root/DEBIAN/control
RUN sed -i "s/Package: libcapstone<major-version-placeholder>/Package: ${LIBCAPSTONE_NAME}/" /package-root/DEBIAN/control

# Add postinst script to run ldconfig after installation
COPY ./debian/postinst /package-root/DEBIAN/postinst
RUN chmod 755 /package-root/DEBIAN/postinst

# Build the package
RUN fakeroot dpkg-deb --build /package-root /${LIBCAPSTONE_NAME}.deb

# The user can now extract the .deb file from the container with something like
# docker run --rm -v $(pwd):/out packager bash -c "cp /libcapstone-dev.deb /out"
