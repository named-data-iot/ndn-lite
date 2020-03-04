/*
 * Copyright (C) Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include <stdio.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "access-control/access-control-tests.h"
#include "aes/aes-tests.h"
#include "data/data-tests.h"
#include "encoder-decoder/encoder-decoder-tests.h"
#include "hmac/hmac-tests.h"
#include "sign-verify/sign-verify-tests.h"

int main() {
    /* initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    add_aes_test_suite();
    add_data_test_suite();
    add_encoder_decoder_test_suite();
    add_hmac_test_suite();
    add_sign_verify_test_suite();

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    printf("\n");
    CU_basic_show_failures(CU_get_failure_list());
    printf("\n\n");
    CU_cleanup_registry();
    return CU_get_error();
}