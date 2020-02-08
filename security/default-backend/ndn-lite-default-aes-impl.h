/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_LITE_AES_TINYCRIPT_IMPL_H
#define NDN_LITE_AES_TINYCRIPT_IMPL_H

#include <stdint.h>

struct abstract_aes_key {
  /**
   * The key bytes buffer of current key.
   */
  uint8_t key_value[32];
  /**
   * The key size of key bytes.
   */
  uint32_t key_size;
};

void
ndn_lite_default_aes_load_backend(void);

#endif // NDN_LITE_AES_TINYCRIPT_IMPL_H
