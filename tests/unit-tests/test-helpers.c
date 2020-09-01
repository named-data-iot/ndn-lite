/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "test-helpers.h"

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

static char test_passed_string[] = "PASSED";
static char test_failed_string[] = "FAILED";

bool check_all_tests_passed(bool *test_results, char **test_names, size_t test_results_len) {
  bool all_tests_passed = true;
  for (uint32_t i = 0; i < test_results_len; i++) {
    char *result_string = test_failed_string;
    if (test_results[i])
      result_string = test_passed_string;
    printf("[%s] %s \n", result_string, test_names[i]);
    if (test_results[i] != true) {
      all_tests_passed = false;
    }
  }
  return all_tests_passed;
}
