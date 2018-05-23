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
 * @brief   NDN L2 interface support.
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */
#ifndef NDN_NETIF_H_
#define NDN_NETIF_H_

#include <kernel_types.h>

#include "encoding/block.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Type to represent the NDN netif entry.
 */
typedef struct ndn_netif {
    kernel_pid_t iface;  /**< pid of the interface */
    uint16_t mtu;        /**< mtu of the interface */
} ndn_netif_t;

/**
 * @brief  Initializes the netif table and try to add existing
 *         network devices into the netif and face tables.
 */
void ndn_netif_auto_add(void);

/**
 * @brief  Sends an NDN packet over the specified network interface.
 *
 * @param[in]  iface    PID of the network interface.
 * @param[in]  block    TLV block to send.
 *
 * @return 0, if success.
 * @return -1, if out of memory during sending.
 * @return -1, if @p block requries more than 32 L2 fragments to send.
 * @return -1, if the interface with id @p iface does not exist.
 * @return -1, if fails to send the packet.
 */
int ndn_netif_send(kernel_pid_t iface, ndn_block_t* block);

#ifdef __cplusplus
}
#endif

#endif /* NDN_NETIF_H_ */
/** @} */
