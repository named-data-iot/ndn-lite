# ndn-lite-tests
Unit tests for NDN-lite using CUnit framework

# Getting Started
To get started, you need CUnit library installed in your system. You may ignore this guide and install it your self, See CUnit (http://cunit.sourceforge.net/).

## Ubuntu
1. Get the CUnit source code tar ball from CUnit website and extract the content.
2. Install CUnit
```
cd CUnit-2.1-3
./bootstrap
./configure
make
make install
```
3. To run this test suite, LD_LIBRARY_PATH must be set:
```
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
export LD_LIBRARY_PATH
```
