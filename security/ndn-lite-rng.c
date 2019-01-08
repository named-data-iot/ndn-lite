/*
 * Copyright (C) 2018-2019 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "ndn-lite-rng.h"
#include "ndn-lite-sec-config.h"

int
ndn_rng(uint8_t* dest, unsigned size)
{
  (void)dest;
  (void)size;
  int result = NDN_SUCCESS;
#ifdef NDN_LITE_SEC_BACKEND_RANDOM_NRF_CRYPTO
  resut = ndn_lite_nrf_crypto_rng(dest, size);
#endif
  return result;
}
