
/*
 * Copyright (C) 2018 Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef ENCODER_DECODER_TESTS_DEF_H
#define ENCODER_DECODER_TESTS_DEF_H

#include <stdint.h>
#include <stdbool.h>

#include "encoder-decoder-tests.h"

#define ENCODER_DECODER_NUM_TESTS 1

extern char *encoder_decoder_test_names[ENCODER_DECODER_NUM_TESTS];

extern bool encoder_decoder_test_results[ENCODER_DECODER_NUM_TESTS];

extern encoder_decoder_test_t encoder_decoder_tests[ENCODER_DECODER_NUM_TESTS];


#endif // ENCODER_DECODER_TESTS_DEF_H
