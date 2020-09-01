
/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef SHA256_SIGN_VERIFY_TESTS_DEF_H
#define SHA256_SIGN_VERIFY_TESTS_DEF_H

#include "sha256-sign-verify-tests.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define SHA256_SIGN_VERIFY_NUM_TESTS 1

extern char *sha256_sign_verify_test_names[SHA256_SIGN_VERIFY_NUM_TESTS];

extern bool sha256_sign_verify_test_results[SHA256_SIGN_VERIFY_NUM_TESTS];

extern sha256_sign_verify_test_t sha256_sign_verify_tests[SHA256_SIGN_VERIFY_NUM_TESTS];

#endif // SHA256_SIGN_VERIFY_TESTS_DEF_H
