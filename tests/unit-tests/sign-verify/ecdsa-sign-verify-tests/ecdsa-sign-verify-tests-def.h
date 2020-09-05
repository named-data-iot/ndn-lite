
/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef ECDSA_SIGN_VERIFY_TESTS_DEF_H
#define ECDSA_SIGN_VERIFY_TESTS_DEF_H

#include "ecdsa-sign-verify-tests.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define ECDSA_SIGN_VERIFY_NUM_TESTS 4

extern char *ecdsa_sign_verify_test_names[ECDSA_SIGN_VERIFY_NUM_TESTS];

extern bool ecdsa_sign_verify_test_results[ECDSA_SIGN_VERIFY_NUM_TESTS];

extern ecdsa_sign_verify_test_t ecdsa_sign_verify_tests[ECDSA_SIGN_VERIFY_NUM_TESTS];

#endif // ECDSA_SIGN_VERIFY_TESTS_DEF_H
