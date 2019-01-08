/*
 * Copyright (C) 2018-2019 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_LITE_DEFAULT_ECC_IMPL_H
#define NDN_LITE_DEFAULT_ECC_IMPL_H

#include <stddef.h>
#include <stdint.h>
#include "sec-lib/tinycrypt/tc_ecc.h"
#include "sec-lib/micro-ecc/uECC.h"

struct abstract_ecc_pub_key {
  uint8_t key_value[64];
  uint32_t key_size;
};

struct abstract_ecc_prv_key {
  uint8_t key_value[32];
  uint32_t key_size;
};

void
ndn_lite_default_ecc_load_backend(void);

#endif // NDN_LITE_DEFAULT_ECC_IMPL_H
