# ndn-lite-tests
Unit tests for NDN-lite using CUnit framework

# Getting Started
To get started, you need CUnit and CMake library installed in your system. 
You may ignore this guide and install it your self, See CUnit (http://cunit.sourceforge.net/).

## Ubuntu
`libcunit` and `cmake` is required for running the unit tests on Ubuntu.
You can install by running:
```
sudo apt install -y libcunit1 cmake
```

# Compile
In project directory, run:
```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
```

# Run Unit Tests
In project directory, run:
```
./build/unittest
```
