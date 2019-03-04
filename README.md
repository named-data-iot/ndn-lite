ndn-lite
========

<img src="https://zhiyi-zhang.com/images/ndn-lite-logo.jpg" alt="logo" width="500"/>

The NDN-Lite library implements the Named Data Networking Stack with the high-level application support functionalities and low-level OS/hardware adaptations for Internet of Things (IoT) scenarios.

The library is written in standard C and requires a minimum version of C11 (ISO/IEC 9899:2011).

Please go to our [wiki page](https://github.com/Zhiyi-Zhang/ndn_standalone/wiki) for the project details.

Compatible Hardware/Software Platforms
--------------------------------------

The network stack can be applied to any platforms that support C.
To work with the network interfaces (e.g., Bluetooth, Bluetooth Low Energy, IEEE 802.15.4, etc.) and hardware crypto interfaces (e.g., hardware ECC support, hardware pseudo random generator, etc.), proper adaptation work is required.

So far, we have developed ndn-lite based IoT packages (with platform adaptation ready) for [RIOT OS](https://www.riot-os.org/) and [Nordic NRF52840 Development Kit](https://www.nordicsemi.com/eng/Products/nRF52840-DK).
Developers can directly develop IoT applications based on these packages without worrying about the adaptation.

Check the ndn-lite based packages in the following list (more to be added in the future):

* [NDN-Lite Unit Tests over RIOT OS](https://github.com/named-data-iot/ndn-lite-test-over-riot) \
Maintainer: Edward Lu, Zhiyi Zhang, Tianyuan Yu

* [NDN IoT Package for Nordic SDK using Segger IDE and Android Phone](https://github.com/named-data-iot/ndn-iot-package-over-nordic-sdk) \
Maintainer: Edward Lu, Bo Chen

* [NDN IoT Package for Nordic SDK using GCC](https://github.com/named-data-iot/ndn-iot-package-over-nordic-sdk-gcc) \
Maintainer: Tianyuan Yu
