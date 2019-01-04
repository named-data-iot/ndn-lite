/*
 * Copyright (C) 2018 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef memory_pool_h
#define memory_pool_h

#include "../encode/name.h"

/*
 * Memory pool manages temporary memory blocks to store Name.
 * Memory blocks are allocated in fixed size.
 */

/**
 * The size of memory block in bytes.
 * This value should be equal to sizeof(Name)
 */
#define NDN_POOL_BLOCK_SIZE (sizeof(ndn_name_t))

/**
 * Maximum number of blocks can be allocated.
 * When program statrts, memory pool will reserve
 * (NDN_POOL_BLOCK_CNT * NDN_POOL_BLOCK_SIZE) bytes.
 */
#define NDN_POOL_BLOCK_CNT 4

/**
 * Initialize the memory pool.
 * Reserve (NDN_POOL_BLOCK_CNT * NDN_POOL_BLOCK_SIZE) bytes.
 */
int
ndn_memory_pool_init(void);

/**
 * Allocate a new block in size NDN_POOL_BLOCK_SIZE.
 * @return A pointer to the allocated block.
 */
uint8_t*
ndn_memory_pool_alloc(void);

/**
 * Free allocated memory block.
 * @param ptr. Pointer to the block to be freed.
 */
int
ndn_memory_pool_free(void* ptr);

#endif /* memory_pool_h */
