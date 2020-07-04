/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "fragmentation-support-tests.h"
#include "../print-helpers.h"
#include "../test-helpers.h"
#include "ndn-lite/encode/fragmentation-support.h"
#include <stdio.h>
#include <string.h>
#include "../CUnit/CUnit.h"

const uint8_t fragmentation_support_test_payload[FRAGMENTATION_SUPPORT_TEST_PAYLOAD_SIZE] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

static const char *_current_test_name = "fragmentation support test";
static bool _all_function_calls_succeeded = true;

void run_fragmentation_support_test_1(void)
{
  _all_function_calls_succeeded = true;
  int ret_val = -1;

  const uint8_t *payload = fragmentation_support_test_payload;
  uint32_t payload_size = sizeof(fragmentation_support_test_payload);

  ndn_fragmenter_t fragmenter;
  ndn_fragmenter_init(&fragmenter, payload, payload_size, 16, 123);
  //printf("total frag pkt num: %d\n", fragmenter.total_frag_num);

  uint8_t original[200];
  ndn_frag_assembler_t assembler;
  ndn_frag_assembler_init(&assembler, original, 200);

  uint8_t frag[16] = {0};
  while (fragmenter.counter < fragmenter.total_frag_num)
  {
    ret_val = ndn_fragmenter_fragment(&fragmenter, frag);
    CU_ASSERT_EQUAL(ret_val, 0);
    if (ret_val != 0)
    {
      print_error(_current_test_name, "_run_fragmentation_support_test", "ndn_fragmenter_fragment", ret_val);
      _all_function_calls_succeeded = false;
    }
    // printf("fragmented pkt: \n");
    // for (int i = 0; i < 16; i++) {
    //   printf("%d ", frag[i]);
    // }
    // printf("\n");

    ret_val = ndn_frag_assembler_assemble_frag(&assembler, frag, 16);
    CU_ASSERT_EQUAL(ret_val, 0);
    if (ret_val != 0)
    {
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

    // compare original with assembled fragments
    ret_val = memcmp(assembler.original, payload, assembler.offset);
    CU_ASSERT_EQUAL(ret_val, 0);
    CU_ASSERT_TRUE(_all_function_calls_succeeded);
}

// test fragmentation support on unfragmented packet
void run_fragmentation_support_test_2(void)
{
  int ret_val = -1;

  const uint8_t *payload = fragmentation_support_test_payload;
  uint32_t payload_size = 10;

  // fragmentation
  ndn_fragmenter_t fragmenter;
  ndn_fragmenter_init(&fragmenter, payload, payload_size, 16, 123);
  uint8_t frag[16] = {0};
  ret_val = ndn_fragmenter_fragment(&fragmenter, frag);
  CU_ASSERT_EQUAL(fragmenter.counter, 1);
  CU_ASSERT_EQUAL(fragmenter.total_frag_num, 1);

  // assembly
  uint8_t original[200];
  ndn_frag_assembler_t assembler;
  ndn_frag_assembler_init(&assembler, original, 200);
  ret_val = ndn_frag_assembler_assemble_frag(&assembler, frag, 16);
  CU_ASSERT_EQUAL(ret_val, 0);
  ret_val = memcmp(assembler.original, payload, payload_size);
  CU_ASSERT_EQUAL(ret_val, 0);
}

  void add_fragmentation_support_test_suite(void)
  {
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("Fragmentation Support Test", NULL, NULL);
    if (NULL == pSuite)
    {
      CU_cleanup_registry();
    // return CU_get_error();
    return;
    }
    if (NULL == CU_add_test(pSuite, "fragmentation_support_test_1", run_fragmentation_support_test_1) ||
        NULL == CU_add_test(pSuite, "fragmentation_support_test_2", run_fragmentation_support_test_2))
    {
      CU_cleanup_registry();
    // return CU_get_error();
    return;
    }
  }