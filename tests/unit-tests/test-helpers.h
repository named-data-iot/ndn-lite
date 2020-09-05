
/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include <stdbool.h>
#include <stddef.h>

bool check_all_tests_passed(bool *test_results, char **test_names, size_t test_results_len);

#endif // TEST_HELPERS_H
