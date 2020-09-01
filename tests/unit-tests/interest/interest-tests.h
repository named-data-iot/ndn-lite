
/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef INTEREST_TESTS_H
#define INTEREST_TESTS_H

#include <stdbool.h>
#include <stdint.h>

// returns true if all tests passed, false otherwise
bool run_interest_tests(void);

// add interest test suite to CUnit registry
void add_interest_test_suite(void);

typedef struct {
  char **test_names;
  uint32_t test_name_index;
  int ndn_ecdsa_curve;
  const uint8_t *ecc_pub_key_val;
  uint32_t ecc_pub_key_len;
  const uint8_t *ecc_prv_key_val;
  uint32_t ecc_prv_key_len;
  const uint8_t *hmac_key_val;
  uint32_t hmac_key_len;
  bool *passed;
} interest_test_t;

#endif // INTEREST_TESTS_H
