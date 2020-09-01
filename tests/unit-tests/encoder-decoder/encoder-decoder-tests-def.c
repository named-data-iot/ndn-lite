
/*
 * Copyright (C) 2018 Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "encoder-decoder-tests-def.h"

#include "ndn-lite/ndn-enums.h"

#include <stdbool.h>

char *encoder_decoder_test_names[ENCODER_DECODER_NUM_TESTS] = {
  "test_encoder_decoder",
};

bool encoder_decoder_test_results[ENCODER_DECODER_NUM_TESTS];

encoder_decoder_test_t encoder_decoder_tests[ENCODER_DECODER_NUM_TESTS] = {
    {
      encoder_decoder_test_names,
      0,
      &encoder_decoder_test_results[0]
    },
};
