/*
 * Copyright (C) 2018-2019 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_SECURITY_UTILS_H_
#define NDN_SECURITY_UTILS_H_

#include <inttypes.h>
#include <stdbool.h>

#include "detail/default-backend/sec-lib/micro-ecc/uECC.h"

#define ECDSA_WITH_SHA256_SECP_256_ASN_ENCODED_SIGNATURE_SIZE 80

enum {
  ASN1_SEQUENCE = 0x30,
  ASN1_INTEGER = 0x02,
};

int
ndn_const_time_memcmp(const uint8_t* a, const uint8_t* b, uint32_t size);

// the below utility functions for asn encoding a micro-ecc generated ecdsa signature
// adapted from: 
// https://github.com/yoursunny/esp8266ndn/blob/master/src/security/detail/ec-impl-microecc.hpp

bool ndn_(uint8_t *sig, uint32_t *sigLength, uECC_Curve curve);

#endif // NDN_SECURITY_UTILS_H_
