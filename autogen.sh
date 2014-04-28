#!/bin/bash

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

pushd $srcdir &>/dev/null

if [ "$1" = "clean" ]; then
  [ -f "Makefile" ] && make maintainer-clean

  rm -f INSTALL README aclocal.m4 compile config.guess config.h \
    config.h.in config.log config.status config.sub configure depcomp \
    capstone.pc install-sh libtool ltmain.sh missing stamp-h1 \
    `find . -name Makefile` `find . -name Makefile.in`
  rm -rf autom4te.cache

  popd &>/dev/null
  exit 0
fi

# INSTALL is required by automake, but may be deleted by clean up rules.
# to get automake to work, simply touch these here, they will be
# regenerated from their corresponding *.in files by ./configure anyway.
touch INSTALL

autoreconf -ifv
result=$?

popd &>/dev/null

exit $result
