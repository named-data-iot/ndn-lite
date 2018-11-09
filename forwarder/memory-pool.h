/*
 * Copyright (C) 2018 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef memory_pool_h
#define memory_pool_h

// This value should be larger than Data and Interest
#define NDN_POOL_BLOCK_SIZE 2560
#define NDN_POOL_BLOCK_CNT 3

// Memory pool deals with temp large memory like Interest and Data.
// Memory blocks are allocated in fixed size

int
ndn_memory_pool_init(void);

uint8_t*
ndn_memory_pool_alloc(void);

int
ndn_memory_pool_free(void* ptr);

#endif /* memory_pool_h */
