/*
 * Copyright (C) 2016 Wentao Shang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     net_ndn
 * @{
 *
 * @file
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */

#include "netif.h"
#include "face-table.h"
#include "fib.h"
#include "l2.h"

#include <debug.h>
#include <net/netopt.h>
#include <net/gnrc/netapi.h>
#include <net/gnrc/netif.h>
#include <net/gnrc/netif/hdr.h>
#include <net/gnrc/netreg.h>
#include <random.h>
#include <thread.h>

static ndn_netif_t _netif_table[GNRC_NETIF_NUMOF];

void ndn_netif_auto_add(void)
{
    /* initialize the netif table entry */
    for (int i = 0; i < GNRC_NETIF_NUMOF; ++i) {
        _netif_table[i].iface = KERNEL_PID_UNDEF;
    }

    /* get list of interfaces */
    size_t ifnum = gnrc_netif_numof();

    if (ifnum == 0) {
        DEBUG("ndn: no interfaces registered, cannot add netif\n");
        return;
    }

    int i = -1;
    gnrc_netif_t *netif = NULL;

    while ((netif = gnrc_netif_iter(netif))) {
        i++;
        kernel_pid_t iface = netif->pid;
        gnrc_nettype_t proto;

        // get device mtu
        if (gnrc_netapi_get(iface, NETOPT_MAX_PACKET_SIZE, 0,
                            &_netif_table[i].mtu,
                            sizeof(uint16_t)) < 0) {
            DEBUG("ndn: cannot get device mtu (pid=%"
                  PRIkernel_pid ")\n", iface);
            continue;
        }

        // set device net proto to NDN
        if (gnrc_netapi_get(iface, NETOPT_PROTO, 0,
                            &proto, sizeof(proto)) == sizeof(proto)) {
            // this device supports PROTO option
            if (proto != GNRC_NETTYPE_NDN) {
                proto = GNRC_NETTYPE_NDN;
                gnrc_netapi_set(iface, NETOPT_PROTO, 0,
                                &proto, sizeof(proto));
            }
        }

        _netif_table[i].iface = iface;
        if (ndn_face_table_add(iface, NDN_FACE_NETDEV) == 0) {
            DEBUG("ndn: add network device (pid=%"
                  PRIkernel_pid ") into face table\n", iface);
            // add default route for this face
            uint8_t buf[] = { NDN_TLV_NAME, 0 };
            ndn_block_t empty = { buf, sizeof(buf) }; // URI = /
            ndn_shared_block_t* shared = ndn_shared_block_create(&empty);
            if (shared != NULL
                && ndn_fib_add(shared, iface, NDN_FACE_NETDEV) == 0) {
                DEBUG("ndn: default route added for network device\n");
            }
        }
        else {
            DEBUG("ndn: failed to add network device (pid=%"
                  PRIkernel_pid ") into face table\n", iface);
        }
    }
}

/* helper function to find the netif entry by pid */
static ndn_netif_t* _ndn_netif_find(kernel_pid_t iface)
{
    if (iface == KERNEL_PID_UNDEF) return NULL;

    for (int i = 0; i < GNRC_NETIF_NUMOF; ++i) {
        if (_netif_table[i].iface == iface)
            return &_netif_table[i];
    }
    return NULL;
}

static int _ndn_netif_send_packet(kernel_pid_t iface, gnrc_pktsnip_t* pkt)
{
    /* allocate interface header */
    gnrc_pktsnip_t *netif_hdr = gnrc_netif_hdr_build(NULL, 0, NULL, 0);

    if (netif_hdr == NULL) {
        DEBUG("ndn: error on interface header allocation, dropping packet\n");
        gnrc_pktbuf_release(pkt);
        return -1;
    }

    /* add interface header to packet */
    LL_PREPEND(pkt, netif_hdr);

    /* mark as broadcast */
    ((gnrc_netif_hdr_t *)pkt->data)->flags |= GNRC_NETIF_HDR_FLAGS_BROADCAST;
    ((gnrc_netif_hdr_t *)pkt->data)->if_pid = iface;

    /* send to interface */
    if (gnrc_netapi_send(iface, pkt) < 1) {
        DEBUG("ndn: failed to send packet (iface=%" PRIkernel_pid ")\n", iface);
        gnrc_pktbuf_release(pkt);
        return -1;
    }

    DEBUG("ndn: successfully sent packet (iface=%" PRIkernel_pid ")\n", iface);
    return 0;
}

static int _ndn_netif_send_fragments(kernel_pid_t iface, ndn_block_t* block,
                                     uint16_t mtu)
{
    if (mtu <= NDN_L2_FRAG_HDR_LEN) {
        DEBUG("ndn: mtu smaller than L2 fragmentation header size (iface=%"
              PRIkernel_pid ")\n", iface);
        return -1;
    }

    int total_frags = block->len / (mtu - NDN_L2_FRAG_HDR_LEN) + 1;
    if (total_frags > 32) {
        DEBUG("ndn: too many fragments to send (iface=%"
              PRIkernel_pid ")\n", iface);
        return -1;
    }

    bool mf = true;
    uint8_t seq = 0;
    uint16_t id = (uint16_t)((random_uint32() >> 11) & 0xFFFF);

    ndn_block_t tmp;
    int bytes_sent = 0;
    while (bytes_sent < block->len) {
        tmp.buf = block->buf + bytes_sent;
        tmp.len = mtu - NDN_L2_FRAG_HDR_LEN;
        if (tmp.len + bytes_sent > block->len) {
            tmp.len = block->len - bytes_sent;
            mf = false;
            assert(seq <= 31);
        }

        gnrc_pktsnip_t* pkt = ndn_block_create_packet(&tmp);
        if (pkt == NULL) {
            DEBUG("ndn: cannot create packet during sending fragments (iface=%"
                  PRIkernel_pid ")\n", iface);
            return -1;
        }

        gnrc_pktsnip_t* l2frag = ndn_l2_frag_build_hdr(mf, seq, id);
        if (l2frag == NULL) {
            DEBUG("ndn: cannot create l2frag header during sending (iface=%"
                  PRIkernel_pid ")\n", iface);
            gnrc_pktbuf_release(pkt);
            return -1;
        }

        LL_PREPEND(pkt, l2frag);

        if (_ndn_netif_send_packet(iface, pkt) < 0) return -1;
        DEBUG("ndn: sent fragment (MF=%x, SEQ=%u, ID=%02X, "
              "size=%d, iface=%" PRIkernel_pid ")\n",
              mf, seq, id, tmp.len, iface);

        // yield after sending a fragment
        thread_yield();

        seq++;
        bytes_sent += tmp.len;
    }

    return 0;
}


int ndn_netif_send(kernel_pid_t iface, ndn_block_t* block)
{
    assert(block != NULL);
    assert(block->buf != NULL);
    assert(block->len > 0);

    ndn_netif_t* netif = _ndn_netif_find(iface);
    if (netif == NULL) {
        DEBUG("ndn: no such network device (iface=%" PRIkernel_pid ")", iface);
        return -1;
    }

    /* check mtu */
    if (block->len > (int)netif->mtu) {
        DEBUG("ndn: packet size (%d) exceeds device mtu (%u); "
              "send with fragmentation (iface=%" PRIkernel_pid ")\n",
              block->len, netif->mtu, iface);
        return _ndn_netif_send_fragments(iface, block, netif->mtu);
    }

    gnrc_pktsnip_t* pkt = ndn_block_create_packet(block);
    if (pkt == NULL) {
        DEBUG("ndn: cannot create packet during sending (iface=%"
              PRIkernel_pid ")\n", iface);
        return -1;
    }

    return _ndn_netif_send_packet(iface, pkt);
}

/** @} */
