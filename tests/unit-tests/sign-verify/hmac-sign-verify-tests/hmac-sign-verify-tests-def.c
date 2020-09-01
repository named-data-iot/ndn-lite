
/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "hmac-sign-verify-tests-def.h"

char *hmac_sign_verify_test_names[HMAC_SIGN_VERIFY_NUM_TESTS] = {
  "test_hmac",
};

bool hmac_sign_verify_test_results[HMAC_SIGN_VERIFY_NUM_TESTS];

hmac_sign_verify_test_t hmac_sign_verify_tests[HMAC_SIGN_VERIFY_NUM_TESTS] = {
    {
      hmac_sign_verify_test_names,
      0,
      test_hmac_key_1,
      sizeof(test_hmac_key_1),
      &hmac_sign_verify_test_results[0]
    }
};

const uint8_t test_hmac_key_1[TEST_HMAC_KEY_SIZE] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
};
