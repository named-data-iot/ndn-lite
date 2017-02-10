/*
 * Copyright (C) 2016 Wentao Shang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_ndn    NDN packet processing
 * @ingroup     net
 * @brief       NDN packet sending and receiving.
 * @{
 *
 * @file
 * @brief   A shared pointer wrapper for @ref ndn_block_t
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */
#ifndef NDN_SHARED_BLOCK_H_
#define NDN_SHARED_BLOCK_H_

#include "block.h"

#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Type to represent a shared block structure.
 */
typedef struct ndn_shared_block {
    atomic_int ref;
    ndn_block_t block;
} ndn_shared_block_t;

/**
 * @brief    Creates a shared block by copying.
 * @details  This function copies the caller-supplied block to a
 *           newly allocated buffer.
 *
 * @param[in]  block  Block to be shared.
 *
 * @return   Shared block pointer, if success.
 * @return   NULL, if @p block is NULL or invalid.
 * @return   NULL, if out of memory.
 */
ndn_shared_block_t* ndn_shared_block_create(ndn_block_t* block);

/**
 * @brief    Creates a shared block using move semantics.
 * @details  This function moves the caller-supplied block into the new
 *           shared block. The pointer in the original block is set to
 *           NULL.
 *
 * @param[in]  block  Block to be shared.
 *
 * @return   Shared block pointer, if success.
 * @return   NULL, if @p block is NULL or invalid.
 * @return   NULL, if out of memory.
 */
ndn_shared_block_t* ndn_shared_block_create_by_move(ndn_block_t* block);

/**
 * @brief    Release a shared block pointer.
 * @details  The ref counter of the shared pointer is decremented by 1.
 *           If the counter reaches zero, the memory associated with the 
 *           shared block is deallocated.
 *
 * @param[in]  shared   Shared block pointer to be released.
 */
void ndn_shared_block_release(ndn_shared_block_t* shared);

/**
 * @brief    Makes a copy of the shared block pointer by incrementing the
 *           ref counter.
 *
 * @param[in]  shared    Shared block pointer to be copied.
 */
ndn_shared_block_t* ndn_shared_block_copy(ndn_shared_block_t* shared);

#ifdef __cplusplus
}
#endif

#endif /* NDN_SHARED_BLOCK_H_ */
/** @} */
