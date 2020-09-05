
/*
 * Copyright (C) Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef ASN_ENCODE_DECODE_TESTS_H
#define ASN_ENCODE_DECODE_TESTS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../../../ndn-lite/ndn-constants.h"

// returns true if all tests passed, false otherwise
bool run_asn_encode_decode_tests(void);

// ASN Encode/Decode CUnit test for Sign Verify test suite
void asn_encode_decode_multi_test(void);

    typedef struct
{
  char **test_names;
  uint8_t test_name_index;
  uint8_t *sig;
  uint32_t sig_len;
  uint32_t sig_buf_len;
  uint8_t *sig_decoded;
  uint32_t sig_decoded_buf_len;
  uint32_t sig_asn_encoded_probe_length_expected;
  uint8_t *sig_asn_encoded_expected;
  uint32_t sig_asn_encoded_expected_len;
  uint8_t *sig_decoded_expected;
  uint32_t sig_decoded_expected_len;
  bool *passed;
} asn_encode_decode_test_t;

#endif // ASN_ENCODE_DECODE_TESTS_H
