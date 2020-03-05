/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "fragmentation-support-tests.h"
#include "fragmentation-support-tests-def.h"
#include "../print-helpers.h"
#include "../test-helpers.h"
#include "ndn-lite/encode/fragmentation-support.h"
#include <stdio.h>
#include <string.h>
#include <CUnit/CUnit.h>

static const char *_current_test_name;
static bool _all_function_calls_succeeded = true;

void _run_fragmentation_support_test(fragmentation_support_test_t *test);

bool run_fragmentation_support_tests(void) {
  memset(fragmentation_support_test_results, 0, sizeof(bool)*FRAGMENTATION_SUPPORT_NUM_TESTS);
  printf("\n");
  for (int i = 0; i < FRAGMENTATION_SUPPORT_NUM_TESTS; i++) {
    _run_fragmentation_support_test(&fragmentation_support_tests[i]);
  }

  return check_all_tests_passed(fragmentation_support_test_results, fragmentation_support_test_names,
                                FRAGMENTATION_SUPPORT_NUM_TESTS);
}

void _run_fragmentation_support_test(fragmentation_support_test_t *test) {

  _current_test_name = test->test_names[test->test_name_index];
  _all_function_calls_succeeded = true;

  int ret_val = -1;

  const uint8_t *payload = test->payload;
  uint32_t payload_size = test->payload_size;

  ndn_fragmenter_t fragmenter;
  ndn_fragmenter_init(&fragmenter, payload, payload_size, 16, 123);
  //printf("total frag pkt num: %d\n", fragmenter.total_frag_num);

  uint8_t original[200];
  ndn_frag_assembler_t assembler;
  ndn_frag_assembler_init(&assembler, original, 200);

  uint8_t frag[16] = {0};
  while (fragmenter.counter < fragmenter.total_frag_num) {
    ret_val = ndn_fragmenter_fragment(&fragmenter, frag);
    CU_ASSERT_EQUAL(ret_val, 0);
    if (ret_val != 0) {
      print_error(_current_test_name, "_run_fragmentation_support_test", "ndn_fragmenter_fragment", ret_val);
      _all_function_calls_succeeded = false;
    }
    /* printf("fragmented pkt: \n"); */
    /* for (int i = 0; i < 16; i++) { */
    /*   printf("%d ", frag[i]); */
    /* } */
    /* printf("\n"); */

    ret_val = ndn_frag_assembler_assemble_frag(&assembler, frag, 16);
    CU_ASSERT_EQUAL(ret_val, 0);
    if (ret_val != 0) {
      print_error(_current_test_name, "_run_fragmentation_support_test", "ndn_frag_assembler_assemble_frag", ret_val);
      _all_function_calls_succeeded = false;
    }
    //printf("assembling: is finished?: %d\n", assembler.is_finished);
  }

  /* printf("after assembling pkt: \n"); */
  /* printf("is finished?: %d\n", assembler.is_finished); */
  /* printf("offset?: %d\n", assembler.offset); */
  /* for (uint32_t i = 0; i < assembler.offset; i++) { */
  /*   printf("%d ", original[i]); */
  /* } */
  /* printf("\n"); */

  // should probably have some memcmp here

  if (_all_function_calls_succeeded)
  {
    *test->passed = true;
  }
  else {
    printf("In _run_fragmentation_support_test, something went wrong.\n");
    *test->passed = false;
  }

}

void add_fragmentation_support_test_suite(void)
{
  CU_pSuite pSuite = NULL;

  /* add a suite to the registry */
  pSuite = CU_add_suite("Fragmentation Support Test", NULL, NULL);
  if (NULL == pSuite)
  {
    CU_cleanup_registry();
    return CU_get_error();
  }
  if (NULL == CU_add_test(pSuite, "fragmentation_support_tests", run_fragmentation_support_tests))
  {
    CU_cleanup_registry();
    return CU_get_error();
  }
}