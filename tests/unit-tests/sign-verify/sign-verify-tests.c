
/*
 * Copyright (C) Tianyuan Yu, Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */
#include "sign-verify-tests.h"

#include "asn-encode-decode-tests/asn-encode-decode-tests.h"
#include "ecdsa-sign-verify-tests/ecdsa-sign-verify-tests.h"
#include "hmac-sign-verify-tests/hmac-sign-verify-tests.h"
#include "sha256-sign-verify-tests/sha256-sign-verify-tests.h"
#include "../CUnit/CUnit.h"

void add_sign_verify_test_suite(void) {
  CU_pSuite pSuite = NULL;

  /* add a suite to the registry */
  pSuite = CU_add_suite("Sign Verify Test", NULL, NULL);
  if (NULL == pSuite)
  {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
  if (NULL == CU_add_test(pSuite, "asn_encode_decode_multi_test", asn_encode_decode_multi_test) ||
      NULL == CU_add_test(pSuite, "ecdsa_multi_test", ecdsa_multi_test) ||
      NULL == CU_add_test(pSuite, "hmac_multi_test", hmac_multi_test) ||
      NULL == CU_add_test(pSuite, "sha256_sign_verify_multi_test", sha256_sign_verify_multi_test))
  {
    CU_cleanup_registry();
  }
}
