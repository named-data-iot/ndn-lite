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
#include "CUnit/CUnit.h"
#include "CUnit/Basic.h"
//#include "access-control/access-control-tests.h"
#include "aes/aes-tests.h"
#include "data/data-tests.h"
#include "encoder-decoder/encoder-decoder-tests.h"
#include "forwarder/forwarder-tests.h"
#include "fib/fib-tests.h"
#include "fragmentation-support/fragmentation-support-tests.h"
#include "forwarder-with-fragmentation-support/forwarder-fragmentation-tests.h"
#include "interest/interest-tests.h"
#include "hmac/hmac-tests.h"
#include "metainfo/metainfo-tests.h"
#include "name-encode-decode/name-encode-decode-tests.h"
#include "random/random-tests.h"
#include "schematized-trust/trust-schema-tests.h"
// #include "service-discovery/service-discovery-tests.h"
#include "sign-verify/sign-verify-tests.h"
#include "signature/signature-tests.h"
#include "util/util-tests.h"

int main() {
    /* initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    add_aes_test_suite();
    add_data_test_suite();
    add_encoder_decoder_test_suite();
    add_fib_test_suite();
    add_forwarder_test_suite();
    add_fragmentation_support_test_suite();
    add_forwarder_fragmentation_test_suite();
    add_interest_test_suite();
    add_hmac_test_suite();
    add_metainfo_test_suite();
    add_name_encode_decode_test_suite();
    add_random_test_suite();
    add_sign_verify_test_suite();
    add_signature_test_suite();
    add_util_test_suite();
    add_trust_schema_test_suite();

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    printf("\n");
    CU_basic_show_failures(CU_get_failure_list());
    printf("\n\n");
    CU_cleanup_registry();
    return CU_get_error();
}