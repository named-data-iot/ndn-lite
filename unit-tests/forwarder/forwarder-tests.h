
/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_TESTS_H
#define FORWARDER_TESTS_H

#include <stdbool.h>
#include <stdint.h>

// returns true if all tests passed, false otherwise
bool run_forwarder_tests(void);

// add forwarder test suite to CUnit registry
void add_forwarder_test_suite(void);

typedef struct {
  char **test_names;
  uint32_t test_name_index;
  int ndn_ecdsa_curve;
  const uint8_t *pub_key_raw_val;
  uint32_t pub_key_raw_len;
  const uint8_t *prv_key_raw_val;
  uint32_t prv_key_raw_len;
  bool *passed;
} forwarder_test_t;

#endif // FORWARDER_TESTS_H
