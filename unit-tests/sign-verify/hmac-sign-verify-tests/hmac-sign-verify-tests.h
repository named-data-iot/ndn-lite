
/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef HMAC_SIGN_VERIFY_TESTS_H
#define HMAC_SIGN_VERIFY_TESTS_H

#include <stdbool.h>
#include <stdint.h>

// returns true if all tests passed, false otherwise
bool run_hmac_sign_verify_tests(void);

// HMAC CUnit test for Sign Verify test suite
void hmac_multi_test(void);

typedef struct {
  char **test_names;
  uint32_t test_name_index;
  const uint8_t *key_val;
  uint32_t key_len;
  bool *passed;
} hmac_sign_verify_test_t;

#endif // HMAC_SIGN_VERIFY_TESTS_H
