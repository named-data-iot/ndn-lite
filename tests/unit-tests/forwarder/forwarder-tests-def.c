
/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "forwarder-tests-def.h"

#include "ndn-lite/ndn-enums.h"

char *forwarder_test_names[FORWARDER_NUM_TESTS] = {
  "test_forwarder",
};

bool forwarder_test_results[FORWARDER_NUM_TESTS];

forwarder_test_t forwarder_tests[FORWARDER_NUM_TESTS] = {
    {
      forwarder_test_names,
      0,
      NDN_ECDSA_CURVE_SECP256R1,
      test_ecc_secp256r1_public_raw_1,
      sizeof(test_ecc_secp256r1_public_raw_1),
      test_ecc_secp256r1_private_raw_1,
      sizeof(test_ecc_secp256r1_private_raw_1),
      &forwarder_test_results[0]
    },
};

const uint8_t test_ecc_secp256r1_private_raw_1[SECP256R1_PRI_KEY_SIZE] = {
  0x38, 0x67, 0x54, 0x73, 0x8B, 0x72, 0x4C, 0xD6,
  0x3E, 0xBD, 0x52, 0xF3, 0x64, 0xD8, 0xF5, 0x7F,
  0xB5, 0xE6, 0xF2, 0x9F, 0xC2, 0x7B, 0xD6, 0x90,
  0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3
};

const uint8_t test_ecc_secp256r1_public_raw_1[SECP256R1_PUB_KEY_SIZE] = {
  0x2C, 0x3C, 0x18, 0xCB, 0x31, 0x88, 0x0B, 0xC3,
  0x73, 0xF4, 0x4A, 0xD4, 0x3F, 0x8C, 0x80, 0x24,
  0xD4, 0x8E, 0xBE, 0xB4, 0xAD, 0xF0, 0x69, 0xA6,
  0xFE, 0x29, 0x12, 0xAC, 0xC1, 0xE1, 0x26, 0x7E,
  0x2B, 0x25, 0x69, 0x02, 0xD5, 0x85, 0x51, 0x4B,
  0x91, 0xAC, 0xB9, 0xD1, 0x19, 0xE9, 0x5E, 0x97,
  0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11,
  0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
};

uint8_t content_store_packet_sample[143] = {
  0x06, 0x8D, 0x07, 0x11, 0x08, 0x05, 0x74, 0x65,
  0x73, 0x74, 0x34, 0x08, 0x08, 0x63, 0x6F, 0x6E,
  0x74, 0x65, 0x6E, 0x74, 0x31, 0x14, 0x03, 0x18,
  0x01, 0x00, 0x15, 0x0A, 0x02, 0x02, 0x02, 0x02,
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x16, 0x1E,
  0x1B, 0x01, 0x03, 0x1C, 0x19, 0x07, 0x17, 0x08,
  0x03, 0x6E, 0x64, 0x6E, 0x08, 0x05, 0x7A, 0x68,
  0x69, 0x79, 0x69, 0x08, 0x03, 0x4B, 0x45, 0x59,
  0x08, 0x04, 0x00, 0x00, 0x04, 0xD2, 0x17, 0x47,
  0x30, 0x45, 0x02, 0x20, 0x49, 0x97, 0xEB, 0xF6,
  0xD2, 0xC5, 0xEE, 0x8F, 0x66, 0x7E, 0x68, 0x85,
  0x8B, 0x74, 0xA1, 0xE6, 0x63, 0x54, 0x8C, 0x19,
  0x61, 0x08, 0xE7, 0x68, 0x22, 0x00, 0x34, 0x60,
  0x50, 0xAF, 0xFB, 0x09, 0x02, 0x21, 0x00, 0xEE,
  0xEF, 0x1D, 0xAE, 0x4C, 0x52, 0x0A, 0xE6, 0xE6,
  0x78, 0x82, 0x72, 0xDC, 0x71, 0x7E, 0xBC, 0xB7,
  0x98, 0xE0, 0xD6, 0x27, 0x88, 0xE6, 0x79, 0x7D,
  0xA3, 0x8F, 0x9E, 0x70, 0x89, 0xBB, 0xC0
};
