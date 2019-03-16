/*
 * Copyright (C) 2018-2019 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */
#ifndef NDN_ENCODING_INTEREST_H
#define NDN_ENCODING_INTEREST_H

#include <stdint.h>

typedef struct interest_options{
  uint64_t lifetime;
  uint32_t nonce;
  uint8_t hop_limit;
  bool can_be_prefix;
  bool must_be_fresh;
}interest_options_t;

#endif