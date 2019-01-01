ndn-lite
========

The NDN-Lite library implements the Named Data Networking Stack with the high-level application support functionalities and low-level OS/hardware adaptations for Internet of Things (IoT) scenarios.

The library is written in standard C.

Please go to our [wiki page](https://github.com/Zhiyi-Zhang/ndn_standalone/wiki) for the project details.

Compatible Hardware/Software Platforms
--------------------------------------

The network stack can be applied to any platforms that support C.
To work with the network interfaces (e.g., Bluetooth, Bluetooth Low Energy, IEEE 802.15.4, etc.), usually an adaptation layer is required.

So far, we have tested our library with [RIOT OS](https://www.riot-os.org/) and [Nordic NRF52840 Development Kit](https://www.nordicsemi.com/eng/Products/nRF52840-DK).
We also provides related adaptation implementation under `./adaptation/`


