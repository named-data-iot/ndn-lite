ndn-lite
========

This is a standalone Named Data Networking (NDN) network stack for Internet of Things (IoT) and other scenarios where a lightweight and high-efficient implementation of NDN is needed.

The library is written in standard C.

Structure and Components
------------------------

Fundamental NDN Features provided by ndn-lite
* lightweight implementation of NDN packet encoding and decoding following [NDN packet format 0.3](http://named-data.net/doc/NDN-packet-spec/current/)
* lightweight NDN security support, including signature signing/verification (ECC-DSA, HMAC, etc.) and content encryption/decryption (AES, etc.)
* lightweight NDN forwarding module realization

Application Support Features provided by ndn-lite
* Ease-of-use Security Bootstrapping Module to achieve efficient and secured trust anchor installation and identity certificate issuance
* Lightweight Name-based Access Control to provide data confidentiality and control of access to data
* Lightweight Service Discovery Protocol Module to enable an application provide services to the network or utilize existing services in the network system

Integrating ndn-lite Into Your Project
--------------------------------------

#### Step 1 ####
Adding the source files under `./encode`, `./security`, and `./forwarder` into your compiler's source file list.
For example,
```
# In the MakeFile
SRCS := \
ndn-lite/encode/data.c \
ndn-lite/encode/decoder.c \
ndn-lite/encode/encoder.c \
ndn-lite/encode/interest.c \
... # all the source files under ./encode, ./security, ./forwarder
```

#### Step 2 ####
Adding the root directory into your compiler's include search path.
For example,
```
# In the MakeFile
CFLAGS += /path/to/ndn-lite
```

#### Step 3 ####
Including the headers you need in your project source files.

#### Step 4 ####
Compile and utilize the features provided by ndn-lite.

Compatible Hardware/Software Platforms
--------------------------------------

The network stack can be applied to any platforms that support C.
To work with the network interfaces (e.g., Bluetooth, Bluetooth Low Energy, IEEE 802.15.4, etc.), usually an adaptation layer is required.

So far, we have tested our library with [RIOT OS](https://www.riot-os.org/) and [Nordic NRF52840 Development Kit](https://www.nordicsemi.com/eng/Products/nRF52840-DK).
We also provides related adaptation implementation under `./adaptation/`


