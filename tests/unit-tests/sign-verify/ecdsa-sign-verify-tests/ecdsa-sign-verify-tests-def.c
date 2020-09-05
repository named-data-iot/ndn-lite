
/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "ecdsa-sign-verify-tests-def.h"

#include "../../../ndn-lite/ndn-enums.h"

#include "test-secp256r1-def.h"

char *ecdsa_sign_verify_test_names[ECDSA_SIGN_VERIFY_NUM_TESTS] = {
  "test_keypair_secp256r1_int1_pad_int2_pad",
  "test_keypair_secp256r1_int1_no_pad_int2_no_pad",
  "test_keypair_secp256r1_int1_pad_int2_no_pad",
  "test_keypair_secp256r1_int1_no_pad_int2_pad",
};

bool ecdsa_sign_verify_test_results[ECDSA_SIGN_VERIFY_NUM_TESTS];

ecdsa_sign_verify_test_t ecdsa_sign_verify_tests[ECDSA_SIGN_VERIFY_NUM_TESTS] = {
    {
      ecdsa_sign_verify_test_names,
      0,
      NDN_ECDSA_CURVE_SECP256R1,
      test_ecc_secp256r1_pub_raw_1, sizeof(test_ecc_secp256r1_pub_raw_1),
      test_ecc_secp256r1_prv_raw_1, sizeof(test_ecc_secp256r1_prv_raw_1),
      &ecdsa_sign_verify_test_results[0]
    },
    {
      ecdsa_sign_verify_test_names,
      1,
      NDN_ECDSA_CURVE_SECP256R1,
      test_ecc_secp256r1_pub_raw_2, sizeof(test_ecc_secp256r1_pub_raw_2),
      test_ecc_secp256r1_prv_raw_2, sizeof(test_ecc_secp256r1_prv_raw_2),
      &ecdsa_sign_verify_test_results[1]
    },
    {
      ecdsa_sign_verify_test_names,
      2,
      NDN_ECDSA_CURVE_SECP256R1,
      test_ecc_secp256r1_pub_raw_3, sizeof(test_ecc_secp256r1_pub_raw_3),
      test_ecc_secp256r1_prv_raw_3, sizeof(test_ecc_secp256r1_prv_raw_3),
      &ecdsa_sign_verify_test_results[2]
    },
    {
      ecdsa_sign_verify_test_names,
      3,
      NDN_ECDSA_CURVE_SECP256R1,
      test_ecc_secp256r1_pub_raw_4, sizeof(test_ecc_secp256r1_pub_raw_4),
      test_ecc_secp256r1_prv_raw_4, sizeof(test_ecc_secp256r1_prv_raw_4),
      &ecdsa_sign_verify_test_results[3]
    },
};
