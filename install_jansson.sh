#! /bin/bash

cd third_party/jansson

autoreconf -fi
./configure
make
make check
sudo make install  # Should also build and install the static version
