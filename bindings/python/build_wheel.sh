#!/bin/bash
set -e -x

cd bindings/python
if [ -f /opt/python/cp311-cp311/bin/python3 ];then
  # Use manylinux Python
  /opt/python/cp311-cp311/bin/python3 -m pip install wheel
  /opt/python/cp311-cp311/bin/python3 setup.py bdist_wheel
else
  python3 -m pip install wheel
  python3 setup.py bdist_wheel
fi

cd dist
auditwheel repair *.whl
mv -f wheelhouse/*.whl .