/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "metainfo-tests.h"
#include <stdio.h>
#include "../CUnit/CUnit.h"
#include "metainfo-tests-def.h"
#include "../print-helpers.h"
#include "../test-helpers.h"
#include "ndn-lite/encode/metainfo.h"
#include "ndn-lite/encode/name.h"

static const char *_current_test_name;
static bool _all_function_calls_succeeded = true;

void _run_metainfo_test(metainfo_test_t *test);

bool run_metainfo_tests(void) {
  memset(metainfo_test_results, 0, sizeof(bool)*METAINFO_NUM_TESTS);
  printf("\n");
  for (int i = 0; i < METAINFO_NUM_TESTS; i++) {
    _run_metainfo_test(&metainfo_tests[i]);
  }

  return check_all_tests_passed(metainfo_test_results, metainfo_test_names,
                                METAINFO_NUM_TESTS);
}

void _run_metainfo_test(metainfo_test_t *test) {

  _current_test_name = test->test_names[test->test_name_index];
  _all_function_calls_succeeded = true;

  int ret_val = -1;

  // component initialization
  char comp1[] = "aaaaaa";
  name_component_t component;
  name_component_from_string(&component, comp1, sizeof(comp1));
  printf("***component init***\ncheck type %u\n", (unsigned int) component.type);
  printf("check length %u\n", component.size);
  printf("check buffer content\n");
  for (size_t i = 0; i < component.size; i++) {
    printf("%d ", component.value[i]);
  }

  // metainfo test
  putchar('\n');
  ndn_metainfo_t meta;
  ndn_metainfo_init(&meta);
  ndn_metainfo_set_final_block_id(&meta, &component);

  // metainfo encode
  size_t block_size = ndn_metainfo_probe_block_size(&meta);
  uint8_t block_value[block_size];
  ndn_encoder_t encoder;
  encoder_init(&encoder, block_value, block_size);
  ret_val = ndn_metainfo_tlv_encode(&encoder, &meta);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_metainfo_test", "ndn_metainfo_tlv_encode", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("***metainfo encode***\n");
  printf("check block size %d\n", (int) block_size);
  printf("check wire_encode content\n");
  for (size_t i = 0; i < block_size; i++) {
    printf("%d ", block_value[i]);
  }
  printf("\n***metainfo decode***\n");

  // metainfo decode
  ndn_metainfo_t meta_decode;
  printf("create a new metainfo \n");
  ret_val = ndn_metainfo_from_tlv_block(&meta_decode, block_value, block_size);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_metainfo_test", "ndn_metainfo_from_tlv_block", ret_val);
    _all_function_calls_succeeded = false;
  }
  if (meta_decode.enable_ContentType == 0)
    printf("content_type correct\n");
  if (meta_decode.enable_FreshnessPeriod == 0)
    printf("freshness correct\n");
  printf("check finalblock_id content\n");
  for (size_t i = 0; i < meta_decode.final_block_id.size; i++) {
    printf("%d ", meta_decode.final_block_id.value[i]);
  }

  if (_all_function_calls_succeeded)
  {
    *test->passed = true;
  }
  else {
    printf("In _run_metainfo_test, something went wrong.\n");
    *test->passed = false;
  }
}

void add_metainfo_test_suite(void)
{
  CU_pSuite pSuite = NULL;

  /* add a suite to the registry */
  pSuite = CU_add_suite("Metainfo Test", NULL, NULL);
  if (NULL == pSuite)
  {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
  if (NULL == CU_add_test(pSuite, "metainfo_tests", (void (*)(void))run_metainfo_tests))
  {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
}