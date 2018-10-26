/*
 * Copyright (C) 2016 Wentao Shang, 2018 Tianyuan Yu
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
 * @brief   A shared pointer wrapper for @ref ndn_buffer_t
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */
#ifndef NDN_ENCODING_SHARED_BUFFER_H_
#define NDN_ENCODING_SHARED_BUFFER_H_

#include "block.h"

#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Type to represent a shared buffer structure.
 */
typedef struct ndn_buffer_block {
    atomic_int ref;
    ndn_buffer_t buffer;
} ndn_shared_buffer_t;


ndn_shared_buffer_t* ndn_shared_buffer_create(ndn_buffer_t* buffer);


ndn_shared_buffer_t* ndn_shared_buffer_create_by_move(ndn_buffer_t* buffer);


void ndn_shared_buffer_release(ndn_shared_buffer_t* shared);


ndn_shared_buffer_t* ndn_shared_buffer_copy(ndn_shared_buffer_t* shared);

#ifdef __cplusplus
}
#endif

#endif /* NDN_SHARED_BUFFER_H_ */
/** @} */
