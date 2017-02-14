/*
 * Copyright (C) 2017 Wentao Shang
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
 * @brief   NDN forwarding strategy framework.
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */
#ifndef NDN_FORWARDING_STRATEGY_H_
#define NDN_FORWARDING_STRATEGY_H_

#include "encoding/shared-block.h"

#include <kernel_types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ndn_pit_entry;

/**
 * @brief  Type to represent a forwarding strategy.
 */
typedef struct ndn_forwarding_strategy {
    // Must not be NULL.
    void (*after_receive_interest)(ndn_shared_block_t* interest,
				   kernel_pid_t incoming_face,
				   struct ndn_pit_entry* pit_entry);
    // Optional.
    void (*before_satisfy_interest)(ndn_block_t* data,
				    kernel_pid_t incoming_face,
				    struct ndn_pit_entry* pit_entry);
    // Optional.
    void (*before_expire_pending_interest)(struct ndn_pit_entry* pit_entry);
} ndn_forwarding_strategy_t;

/**
 * @brief   Finds a longest-matching forwarding strategy by Interest name.
 *
 * @param[in]  name   TLV block of the Interest name.
 *
 * @return  Pointer to the forwarding strategy, if a match is found.
 * @return  NULL, if strategy table is empty.
 */
ndn_forwarding_strategy_t* ndn_forwarding_strategy_lookup(ndn_block_t* name);

/**
 * @brief   Adds a forwarding strategy for a given prefix to the strategy table.
 *          If an entry with the same prefix already exists, the strategy will
 *          be overwritten with the new strategy.
 *
 * @param[in]  prefix    The name prefix the uses the strategy. This function
 *                       acquires the ownership of @p prefix.
 * @param[in]  strategy  The forwarding strategy to be added.
 *
 * @return  0, if the strategy is successfully added for the prefix.
 * @return  -1, if @p prefix is NULL.
 * @return  -1, if @p strategy is NULL.
 * @return  -1, if @p strategy does not have after_receive_interest trigger.
 * @return  -1, if the table is full.
 */
int ndn_forwarding_strategy_add(ndn_shared_block_t* prefix,
				ndn_forwarding_strategy_t* strategy);

/**
 * @brief   Forwarding strategy action for sending Interest @p si to face
 *          @p face_id of type @p face_type.
 *
 * @param[in]  si  Shared block of the interest to send. This function acquires
 *                 the ownership of @p si and will release @p si before it
 *                 returns.
 * @param[in]  face_id  ID of the face to which @p si will be sent.
 * @param[in]  face_type  Type of the face to which @p si will be sent.
 */
void ndn_forwarding_strategy_action_send_interest(ndn_shared_block_t* si,
						  kernel_pid_t face_id,
						  int face_type);

/**
 * @brief   Initializes the forwarding strategy table.
 */
void ndn_forwarding_strategy_init(void);


// Global objects for built-in strategies
extern ndn_forwarding_strategy_t default_strategy;
extern ndn_forwarding_strategy_t multicast_strategy;

#ifdef __cplusplus
}
#endif

#endif /* NDN_FORWARDING_STRATEGY_H_ */
/** @} */
