/*
 * Copyright (C) 2018-2019 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef memory_pool_h
#define memory_pool_h

#include <stdint.h>
#include <stddef.h>

/*
 * Memory pool manages pseudo memory blocks in a static memory array.
 * Memory blocks should be in fixed size.
 */

#define NDN_MEMORY_POOL_RESERVE_SIZE(block_size, block_count) \
    (sizeof(void*) * ((block_count) + 1) + (block_size) * (block_count))

/**
 * Initialize a memory array pool for @c block_count elements in the size of @c block_size.
 * @pre @code (block_size * block_count + sizeof(void*) * (block_count+1)) @endcode bytes needed.
 * @param block_size Input. Size of a block.
 * @param block_count Input. Length of the array.
 * @param pool Input. The base address of memory array.
 * @note Do not check for (base != NULL) here since generally only internal codes use it.
 */
void
ndn_memory_pool_init(void* pool, size_t block_size, size_t block_count);

/**
 * Allocate a new block in size NDN_POOL_BLOCK_SIZE.
 * @param pool Input. The pool address of memory array.
 * @return A pointer to the allocated block. NULL for insufficient memory.
 */
uint8_t*
ndn_memory_pool_alloc(void* pool);

/**
 * Free allocated memory block.
 * @param pool Input. The pool address of memory array.
 * @param ptr Input. Pointer to the block to be freed.
 * @retval  0 Succeeded.
 * @retval -1 Illegal input.
 */
int
ndn_memory_pool_free(void* pool, void* ptr);

#endif /* memory_pool_h */
