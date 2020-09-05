
/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef SIGNATURE_TESTS_H
#define SIGNATURE_TESTS_H

#include <stdbool.h>
#include <stdint.h>

// returns true if all tests passed, false otherwise
bool run_signature_tests(void);

// add signature test suite to CUnit registry
void add_signature_test_suite(void);

typedef struct {
  char **test_names;
  uint32_t test_name_index;
  int ndn_ecdsa_curve;
  const uint8_t *dummy_signature;
  uint32_t dummy_signature_len;
  bool *passed;
} signature_test_t;


#endif // SIGNATURE_TESTS_H
