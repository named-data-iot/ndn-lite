/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef TRUST_SCHEMA_TESTS_H
#define TRUST_SCHEMA_TESTS_H

#include <stdbool.h>
#include <stdint.h>

#include "../../ndn-lite/encode/trust-schema/ndn-trust-schema-rule.h"
#include "../../ndn-lite/encode/name.h"

// returns true if all tests passed, false otherwise
bool run_trust_schema_tests(void);

// add trust schema test suite to CUnit registry
void add_trust_schema_test_suite(void);

typedef struct {
  char **test_names;
  uint32_t test_name_index;
  const char *rule_data_pattern_string;
  int rule_data_pattern_string_size;
  const char *rule_key_pattern_string;
  int rule_key_pattern_string_size;
  const char *data_name_string;
  int data_name_string_size;
  const char *key_name_string;
  int key_name_string_size;
  int expected_rule_compilation_result;
  int expected_match_result;
  bool *passed;
} trust_schema_test_t;

#endif // TRUST_SCHEMA_TESTS_H
