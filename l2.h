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
 * @brief   NDN L2 adaptation layer support.
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */
#ifndef NDN_L2_H_
#define NDN_L2_H_

#include "encoding/shared-block.h"

#include <kernel_types.h>
#include <net/gnrc/pktbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   NDN L2 fragmentation header format:
 *
 * @details
 *
 *    0           1           2
 *    0 1 2  3    8         15           23
 *    +-+-+--+----+----------------------+
 *    |1|X|MF|Seq#|    Identification    |
 *    +-+-+--+----+----------------------+
 *
 *    First bit: header bit, always 1 (indicating the fragmentation header)
 *    Second bit: reserved, always 0
 *    Third bit: MF bit
 *    4th to 8th bit: sequence number (5 bits, encoding up to 31)
 *    9th to 24th bit: identification (2-byte random number)
 */
typedef struct ndn_l2_frag_hdr {
    uint8_t bits;
    uint8_t id[2];
} ndn_l2_frag_hdr_t;

#define NDN_L2_FRAG_HDR_LEN   3  /* Size of the NDN L2 fragmentation header */

#define NDN_L2_FRAG_HB_MASK  0x80   /* 1000 0000 */
#define NDN_L2_FRAG_MF_MASK  0x20   /* 0010 0000 */
#define NDN_L2_FRAG_SEQ_MASK 0x1F   /* 0001 1111 */

/**
 * @brief  Builds a packet snip containing the L2 fragmentation header.
 *
 * @param[in]  mf     Whether MF bit is set.
 * @param[in]  seq    Sequence number of the fragment.
 * @param[in]  id     Identification of the fragment.
 *
 * @return Pointer to the packet snip, if success.
 * @return NULL, if out of memory.
 * @return NULL, if @p seq >= 32.
 */
gnrc_pktsnip_t* ndn_l2_frag_build_hdr(bool mf, uint8_t seq, uint16_t id);

/**
 * @brief  Processes a received L2 fragment packet.
 *
 * @param[in]  iface  Face ID where @p pkt is received.
 * @param[in]  pkt    Received packet snip. Caller will release ownership to
 *                    this packet snip.
 * @param[in]  id     L2 fragmentation id.
 *
 * @return Pointer to a shared block if a complete NDN packet can be
 *         reassembled.
 * @return NULL, if @p pkt does not contain L2 header information.
 * @return NULL, if out of memory.
 */
ndn_shared_block_t* ndn_l2_frag_receive(kernel_pid_t iface,
					gnrc_pktsnip_t* pkt, uint16_t id);

/**
 * @brief  Removes pending fragments that have timed out.
 *
 * @param[in]  msg    Message pointer that identifies the expired entry.
 */
void ndn_l2_frag_timeout(msg_t* msg);

/**
 * @brief  Initializes L2 adaptation layer.
 */
void ndn_l2_init(void);

#ifdef __cplusplus
}
#endif

#endif /* NDN_L2_H_ */
/** @} */
