#!/bin/sh -x

cd cmocka
mkdir build
cd build

if [ "$(uname)" = Darwin ]; then
  cmake -DCMAKE_INSTALL_PREFIX=/usr/local .. && make -j2 && sudo make install
elif [ "$asan" = "ON" ]; then
  CMAKE_C_FLAGS="-fsanitize=address" CMAKE_LINK_FLAGS="-fsanitize=address" cmake -DCMAKE_INSTALL_PREFIX=/usr/local .. && make -j2 && sudo make install
else  # Linux
  cmake -DCMAKE_INSTALL_PREFIX=/usr .. && make -j2 && sudo make install
fi

cd ../..

if [ "$asan" = "ON" ]; then
  CMAKE_C_FLAGS="-fsanitize=address" make
else
  make
fi
