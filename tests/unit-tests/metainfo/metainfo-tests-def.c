
/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "metainfo-tests-def.h"

#include "ndn-lite/ndn-enums.h"

#include <stdbool.h>

char *metainfo_test_names[METAINFO_NUM_TESTS] = {
  "test_metainfo",
};

bool metainfo_test_results[METAINFO_NUM_TESTS];

metainfo_test_t metainfo_tests[METAINFO_NUM_TESTS] = {
    {
      metainfo_test_names,
      0,
      &metainfo_test_results[0]
    },
};
