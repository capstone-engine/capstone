#!/bin/sh

cd cmocka && mkdir build && cd build
if [ "$(uname)" = Darwin ]; then
cmake -DCMAKE_INSTALL_PREFIX=/usr/local .. && make -j2 && sudo make install
else  # Linux
cmake -DCMAKE_INSTALL_PREFIX=/usr .. && make -j2 && sudo make install
fi
cd ../.. && make
