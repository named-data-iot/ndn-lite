/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_ENCODING_BLOCK_H_
#define NDN_ENCODING_BLOCK_H_

#include <inttypes.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// non-TLV encoded buffer
typedef struct ndn_buffer {
  uint8_t* value;
  size_t size;
} ndn_buffer_t;

// TLV encoded block
typedef struct ndn_block {
  uint8_t* value;
  uint32_t size;
  uint32_t max_size;
} ndn_block_t;

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_BLOCK_H
