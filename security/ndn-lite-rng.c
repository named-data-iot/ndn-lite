/*
 * Copyright (C) 2018-2019 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
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
  return ndn_rng_backend.rng(dest, size);
}
