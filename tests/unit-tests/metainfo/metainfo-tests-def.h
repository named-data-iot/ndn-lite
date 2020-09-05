
/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef METAINFO_TESTS_DEF_H
#define METAINFO_TESTS_DEF_H

#include <stdint.h>
#include <stdbool.h>

#include "metainfo-tests.h"

#define METAINFO_NUM_TESTS 1

extern char *metainfo_test_names[METAINFO_NUM_TESTS];

extern bool metainfo_test_results[METAINFO_NUM_TESTS];

extern metainfo_test_t metainfo_tests[METAINFO_NUM_TESTS];

#endif // METAINFO_TESTS_DEF_H
