
/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef ECDSA_SIGN_VERIFY_TESTS_H
#define ECDSA_SIGN_VERIFY_TESTS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// returns true if all tests passed, false otherwise
bool run_ecdsa_sign_verify_tests(void);

// ECDSA CUnit test for Sign Verify test suite
void ecdsa_multi_test(void);

typedef struct {
  char **test_names;
  uint32_t test_name_index;
  int ndn_ecdsa_curve;
  const uint8_t *ecc_pub_raw;
  uint32_t ecc_pub_raw_len;
  const uint8_t *ecc_prv_raw;
  uint32_t ecc_prv_raw_len;
  bool *passed;
} ecdsa_sign_verify_test_t;

#endif // ECDSA_SIGN_VERIFY_TESTS_H
