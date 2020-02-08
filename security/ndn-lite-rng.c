/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "ndn-lite-rng.h"
#include "ndn-lite-sec-config.h"

ndn_rng_backend_t ndn_rng_backend;

ndn_rng_backend_t*
ndn_rng_get_backend(void)
{
  return &ndn_rng_backend;
}

int
ndn_rng(uint8_t* dest, unsigned size)
{
  int ret = ndn_rng_backend.rng(dest, size);
  if (ret == 1)
    return NDN_SUCCESS;
  else
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
}
