
/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FRAGMENTATION_SUPPORT_TESTS_DEF_H
#define FRAGMENTATION_SUPPORT_TESTS_DEF_H

#include <stdint.h>
#include <stdbool.h>

#include "fragmentation-support-tests.h"

#define FRAGMENTATION_SUPPORT_TEST_PAYLOAD_SIZE 104

#define FRAGMENTATION_SUPPORT_NUM_TESTS 1

extern char *fragmentation_support_test_names[FRAGMENTATION_SUPPORT_NUM_TESTS];

extern bool fragmentation_support_test_results[FRAGMENTATION_SUPPORT_NUM_TESTS];

extern fragmentation_support_test_t fragmentation_support_tests[FRAGMENTATION_SUPPORT_NUM_TESTS];

extern const uint8_t fragmentation_support_test_payload[FRAGMENTATION_SUPPORT_TEST_PAYLOAD_SIZE];

#endif // FRAGMENTATION_SUPPORT_TESTS_DEF_H
