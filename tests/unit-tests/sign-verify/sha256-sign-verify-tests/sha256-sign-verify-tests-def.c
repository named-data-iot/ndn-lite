
/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "sha256-sign-verify-tests-def.h"

char *sha256_sign_verify_test_names[SHA256_SIGN_VERIFY_NUM_TESTS] = {
  "test_sha256",
};

bool sha256_sign_verify_test_results[SHA256_SIGN_VERIFY_NUM_TESTS];

sha256_sign_verify_test_t sha256_sign_verify_tests[SHA256_SIGN_VERIFY_NUM_TESTS] = {
    {
      sha256_sign_verify_test_names,
      0,
      &sha256_sign_verify_test_results[0]
    }
};
