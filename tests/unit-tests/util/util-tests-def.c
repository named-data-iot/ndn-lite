
/*
 * Copyright (C) 2019 Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "util-tests-def.h"

#include <stdbool.h>

char *util_test_names[UTIL_NUM_TESTS] = {
  "test_util",
};

bool util_test_results[UTIL_NUM_TESTS];

util_test_t util_tests[UTIL_NUM_TESTS] = {
    {
      util_test_names,
      0,
      &util_test_results[0]
    },
};
