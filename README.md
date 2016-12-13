NDN-RIOT: NDN protocol stack for RIOT-OS
========================================

## Getting started

To build applications, create environment using the following commands:

    mkdir riot
    cd riot
    git clone https://github.com/named-data-iot/RIOT
    git clone https://github.com/named-data-iot/ndn-riot

Afterwards, you can create RIOT-OS applications using the module, e.g., based on the template in [ndn-riot-examples repository](https://github.com/named-data-iot/ndn-riot-examples):

    git clone https://github.com/named-data-iot/ndn-riot-examples
    cd ndn-riot-examples
    cp -r ndn-template <YOUR-APP>
    cd <YOUR-APP>
    ... add necessary files ...
    make <FLAGS_REQUIRED>

## Compatibility

The examples were known to work with the following versions of RIOT-OS (our own fork) and NDN-RIOT module,
but may work with later (latest) versions:

- **RIOT-OS**: 49574ee4e427d966da23a06ed5aa97bfeba90a6e
- **ndn-riot-examples**: ce60229775fafdcedd7f8be5181c0d45d5e13097
