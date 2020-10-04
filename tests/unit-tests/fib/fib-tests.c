/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
#include "../forwarder/forwarder-tests.h"
#include "fib-tests.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include "../CUnit/CUnit.h"

#include "ndn-lite/ndn-constants.h"
#include "ndn-lite/encode/interest.h"
#include "ndn-lite/encode/data.h"
#include "ndn-lite/forwarder/fib.h"
#include "ndn-lite/forwarder/name-tree.h"
#include "ndn-lite/forwarder/face-table.h"
#include "ndn-lite/face/dummy-face.h"

void run_fib_test_1(void) {
  uint8_t memory[6264];
  uint8_t *ptr = (uint8_t *)memory;
  ndn_nametree_init(ptr, NDN_NAMETREE_MAX_SIZE);
  ndn_nametree_t * nametree = (ndn_nametree_t *)ptr;
  ptr += NDN_NAMETREE_RESERVE_SIZE(NDN_NAMETREE_MAX_SIZE);
  ndn_facetab_init(ptr, NDN_FACE_TABLE_MAX_SIZE);
  // ndn_face_table_t *facetab = (ndn_face_table_t *)ptr;
  ptr += NDN_FACE_TABLE_RESERVE_SIZE(NDN_FACE_TABLE_MAX_SIZE);
  ndn_fib_init(ptr, NDN_FIB_MAX_SIZE, nametree);
  ndn_fib_t *fib = (ndn_fib_t *)ptr;

  // ndn_dummy_face_t *dummy_face;
  // dummy_face = ndn_dummy_face_construct();

  char prefix_string[] = "/ucla";
  ndn_name_t prefix;
  int ret_val = ndn_name_from_string(&prefix, prefix_string, sizeof(prefix_string));
  CU_ASSERT_EQUAL(ret_val, 0);
  uint8_t tmp_name_buf[256] = {0};
  ndn_encoder_t tmp_name_encoder;
  encoder_init(&tmp_name_encoder, tmp_name_buf, 256);
  ndn_name_tlv_encode(&tmp_name_encoder, &prefix);
  ndn_fib_entry_t *fib_entry;
  fib_entry = ndn_fib_find(fib, tmp_name_buf, tmp_name_encoder.offset);
  CU_ASSERT_PTR_NULL(fib_entry);
  fib_entry = ndn_fib_find_or_insert(fib, tmp_name_buf, tmp_name_encoder.offset);
  CU_ASSERT_PTR_NOT_NULL(fib_entry);

  char prefix_string2[] = "/ucla/cs";
  ndn_name_t prefix2;
  ret_val = ndn_name_from_string(&prefix2, prefix_string2, sizeof(prefix_string2));
  CU_ASSERT_EQUAL(ret_val, 0);
  encoder_init(&tmp_name_encoder, tmp_name_buf, 256);
  ndn_name_tlv_encode(&tmp_name_encoder, &prefix2);

  ndn_fib_entry_t *ret_entry = ndn_fib_prefix_match(fib, tmp_name_buf, tmp_name_encoder.offset);
  CU_ASSERT_PTR_NOT_NULL(ret_entry);
}

void add_fib_test_suite()
{
  CU_pSuite pSuite = NULL;

  /* add a suite to the registry */
  pSuite = CU_add_suite("FIB Test", NULL, NULL);
  if (NULL == pSuite)
  {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
  if (NULL == CU_add_test(pSuite, "fib_test_1", run_fib_test_1)) {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
}