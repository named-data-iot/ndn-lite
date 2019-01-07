/*
 * Copyright (C) 2018-2019 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_LITE_DEFAULT_CRYPTO_KEY_H
#define NDN_LITE_DEFAULT_CRYPTO_KEY_H

#include "../../ndn-lite-crypto-key.h"

#ifdef __cplusplus
extern "C" {
#endif

struct abstract_key {
  /**
   * The key bytes buffer of current key.
   * Default backend at most support 2048 bits key.
   */
  uint8_t key_value[256];
  /**
   * The key size of key bytes.
   */
  uint32_t key_size;
}

#ifdef __cplusplus
}
#endif

#endif // NDN_LITE_DEFAULT_CRYPTO_KEY_H
