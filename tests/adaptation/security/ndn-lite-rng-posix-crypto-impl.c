/*
 * Copyright (C) 2018-2019 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "ndn-lite-rng-posix-crypto-impl.h"
#include <ndn-lite/security/ndn-lite-rng.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#if defined(__APPLE__)
  #include <stdlib.h>
#endif

int
ndn_lite_posix_rng(uint8_t *dest, unsigned size)
{
#if defined(__APPLE__)
  arc4random_buf((void*)dest, size);
  return 1;
#endif
  int randomData = open("/dev/urandom", O_RDONLY);
  if (randomData < 0) {
    return 0;
  }
  else {
    int result = read(randomData, dest, size);
    if (result < 0) {
      return 0;
    }
  }
  return 1;
}

void
ndn_lite_posix_rng_load_backend(void)
{
  ndn_rng_backend_t* backend = ndn_rng_get_backend();
  backend->rng = ndn_lite_posix_rng;
}