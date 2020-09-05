
/*
 * Copyright (C) Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef SHA256_SIGN_VERIFY_TESTS_H
#define SHA256_SIGN_VERIFY_TESTS_H

#include <stdbool.h>
#include <stdint.h>

// returns true if all tests passed, false otherwise
bool run_sha256_sign_verify_tests(void);

// SHA256 CUnit test for Sign Verify test suite
void sha256_sign_verify_multi_test(void);

typedef struct {
  char **test_names;
  uint32_t test_name_index;
  bool *passed;
} sha256_sign_verify_test_t;

#endif // SHA256_SIGN_VERIFY_TESTS_H
