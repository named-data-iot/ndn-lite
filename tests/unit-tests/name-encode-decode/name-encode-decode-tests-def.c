
/*
 * Copyright (C) 2018 Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "name-encode-decode-tests-def.h"

#include "ndn-lite/ndn-enums.h"

#include <stdbool.h>

char *name_encode_decode_test_names[NAME_ENCODE_DECODE_NUM_TESTS] = {
  "test_data",
};

bool name_encode_decode_test_results[NAME_ENCODE_DECODE_NUM_TESTS];

name_encode_decode_test_t name_encode_decode_tests[NAME_ENCODE_DECODE_NUM_TESTS] = {
    {
      name_encode_decode_test_names,
      0,
      &name_encode_decode_test_results[0]
    },
};
