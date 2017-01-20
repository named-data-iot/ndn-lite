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

#include "l2.h"
#include "msg-type.h"
#include "encoding/shared-block.h"
#include "ndn.h"

#include <xtimer.h>
#include <net/gnrc/netif/hdr.h>
#include <debug.h>

#include <stdlib.h>
#include <string.h>

gnrc_pktsnip_t* ndn_l2_frag_build_hdr(bool mf, uint8_t seq, uint16_t id)
{
    if (seq >= 32) return NULL;

    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, NULL, NDN_L2_FRAG_HDR_LEN,
                                          GNRC_NETTYPE_NDN);
    if (pkt == NULL) {
        DEBUG("ndn: cannot allocate packet snip for l2 frag hdr\n");
        return NULL;
    }

    ndn_l2_frag_hdr_t* hdr = (ndn_l2_frag_hdr_t*)(pkt->data);
    hdr->bits = seq;
    hdr->bits |= NDN_L2_FRAG_HB_MASK;

    if (mf) hdr->bits |= NDN_L2_FRAG_MF_MASK;

    hdr->id[0] = (id >> 8) & 0xFF;
    hdr->id[1] = id & 0xFF;

    return pkt;
}

typedef struct _l2_frag_block {
    struct _l2_frag_block* next;
    uint8_t* data;
    size_t len;
} _l2_frag_block_t;

typedef struct _l2_frag_entry {
    struct _l2_frag_entry* prev;
    struct _l2_frag_entry* next;
    xtimer_t timer;
    msg_t timer_msg;
    uint8_t* netif_hdr;
    size_t netif_hdr_len;
    uint32_t frags_map;
    uint16_t id;
    _l2_frag_block_t* frags;
} _l2_frag_entry_t;

//TODO: use larger timeout value in non-test environment
#define NDN_L2_FRAG_MAX_LIFETIME    (10U * US_PER_SEC)

static _l2_frag_entry_t* _l2_frag_list;

static void _release_l2_frag_entry(_l2_frag_entry_t* entry) {
    DL_DELETE(_l2_frag_list, entry);
    xtimer_remove(&entry->timer);
    _l2_frag_block_t *blk, *tmp;
    LL_FOREACH_SAFE(entry->frags, blk, tmp) {
        free(blk->data);
        free(blk);
    }
    free(entry->netif_hdr);
    free(entry);
}

ndn_shared_block_t* ndn_l2_frag_receive(kernel_pid_t iface,
                                        gnrc_pktsnip_t* pkt, uint16_t id)
{
    (void)iface;

    gnrc_pktsnip_t* netif_hdr_pkt =
        gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_NETIF);
    if (netif_hdr_pkt == NULL) {
        DEBUG("ndn: no l2 netif hdr (iface=%" PRIkernel_pid ")\n", iface);
        gnrc_pktbuf_release(pkt);
        return NULL;
    }

    uint8_t seq = ((uint8_t*)(pkt->data))[0] & NDN_L2_FRAG_SEQ_MASK;
    uint32_t seq_map = 0x1 << (31 - seq);
    uint8_t mf = ((uint8_t*)(pkt->data))[0] & NDN_L2_FRAG_MF_MASK;
    if (mf == 0) {
        // this is the last fragment
        // set all bits after the last fragment seq#
        seq_map |= 0xFFFFFFFF >> (seq + 1);
    }

    _l2_frag_entry_t* entry = NULL;
    DL_FOREACH(_l2_frag_list, entry) {
        gnrc_netif_hdr_t* hdr = (gnrc_netif_hdr_t*)(entry->netif_hdr);
        gnrc_netif_hdr_t* hdr_pkt = (gnrc_netif_hdr_t*)(netif_hdr_pkt->data);

        // compare l2 src addr len
        if (hdr->src_l2addr_len != hdr_pkt->src_l2addr_len) continue;

        // compare l2 src addr
        uint8_t* l2_src = gnrc_netif_hdr_get_src_addr(hdr);
        uint8_t* l2_src_pkt = gnrc_netif_hdr_get_src_addr(hdr_pkt);
        if (memcmp(l2_src, l2_src_pkt, hdr->src_l2addr_len) != 0) continue;

        // compare fragment id
        if (entry->id == id) break;  // found a match
    }

    if (entry == NULL) {
        // no existing entry with the same src l2 addr and frag id is found
        // create entry first
        DEBUG("ndn: received fragment of a new packet (iface=%" PRIkernel_pid
              ")\n", iface);

        entry = (_l2_frag_entry_t*)malloc(sizeof(_l2_frag_entry_t));
        if (entry == NULL) {
            DEBUG("ndn: cannot allocate memory for frag entry (iface=%"
                  PRIkernel_pid ")\n", iface);
            gnrc_pktbuf_release(pkt);
            return NULL;
        }
        memset(entry, 0, sizeof(_l2_frag_entry_t));

        // copy netif_hdr
        entry->netif_hdr_len = netif_hdr_pkt->size;
        entry->netif_hdr = (uint8_t*)malloc(entry->netif_hdr_len);
        if (entry->netif_hdr == NULL) {
            DEBUG("ndn: cannt allocate netif_hdr in frag entry (iface=%"
                  PRIkernel_pid ")\n", iface);
            free(entry);
            gnrc_pktbuf_release(pkt);
            return NULL;
        }
        memcpy(entry->netif_hdr, netif_hdr_pkt->data, netif_hdr_pkt->size);

        // copy fragmentation id
        entry->id = id;

        // initialize timer
        entry->timer.target = entry->timer.long_target = 0;
        entry->timer_msg.type = NDN_L2_FRAG_MSG_TYPE_TIMEOUT;
        entry->timer_msg.content.ptr = (char*)(&entry->timer_msg);

        // insert entry into frag list
        DL_PREPEND(_l2_frag_list, entry);
    }

    assert(entry != NULL);

    // set (reset) timer
    xtimer_set_msg(&entry->timer, NDN_L2_FRAG_MAX_LIFETIME,
                   &entry->timer_msg, ndn_pid);

    if ((entry->frags_map & seq_map) != 0) {
        // duplicate packet
        DEBUG("ndn: duplicate fragment (SEQ=%u, ID=%02x) (iface=%"
              PRIkernel_pid ")\n", seq, id, iface);
        gnrc_pktbuf_release(pkt);
        return NULL;
    }

    // copy pkt data into new memory
    _l2_frag_block_t* blk =
        (_l2_frag_block_t*)malloc(sizeof(_l2_frag_block_t));
    if (blk == NULL) {
        DEBUG("ndn: cannt allocate frag block (iface=%"
              PRIkernel_pid ")\n", iface);
        free(entry->netif_hdr);
        free(entry);
        gnrc_pktbuf_release(pkt);
        return NULL;
    }

    blk->next = NULL;
    blk->len = pkt->size;
    blk->data = (uint8_t*)malloc(blk->len);
    if (blk->data == NULL) {
        DEBUG("ndn: cannt allocate frag block data (iface=%"
              PRIkernel_pid ")\n", iface);
        free(blk);
        free(entry->netif_hdr);
        free(entry);
        gnrc_pktbuf_release(pkt);
        return NULL;
    }
    memcpy(blk->data, pkt->data, pkt->size);

    // insert frag block into frag entry
    entry->frags_map |= seq_map;

    if (entry->frags == NULL) {
        entry->frags = blk;
    }
    else {
        // insert into frags according to the order of the seq#
        uint8_t ps, s;
        _l2_frag_block_t* p = entry->frags;
        ps = p->data[0] & NDN_L2_FRAG_SEQ_MASK;
        if (ps > seq) {
            // insert before p
            blk->next = p;
            entry->frags = blk;
        }
        else {
            _l2_frag_block_t* n = p->next;
            while (n != NULL) {
                ps = p->data[0] & NDN_L2_FRAG_SEQ_MASK;
                s = n->data[0] & NDN_L2_FRAG_SEQ_MASK;
                if (ps < seq && s > seq) {
                    // insert after p and before n
                    break;
                }
                p = n;
                n = n->next;
            }

            // insert after p and before n
            p->next = blk;
            blk->next = n;
        }
    }

    // finally, release packet buffer
    gnrc_pktbuf_release(pkt);

    // check for complete packet
    if (entry->frags_map == 0xFFFFFFFF) {
        // reassemble into a single shared block
        size_t total = 0;
        _l2_frag_block_t* p = entry->frags;
        while (p != NULL) {
            total += p->len - NDN_L2_FRAG_HDR_LEN;
            p = p->next;
        }
        assert(total > 0);

        uint8_t* buf = (uint8_t*)malloc(total);
        if (buf == NULL) {
            DEBUG("ndn: cannot allocate buffer for reassembly (ID=%02x, iface=%"
                  PRIkernel_pid ")\n", id, iface);
            _release_l2_frag_entry(entry);
            return NULL;
        }
        ndn_block_t b;
        b.len = total;
        b.buf = buf;

        p = entry->frags;
        while (p != NULL) {
            memcpy(buf, p->data + NDN_L2_FRAG_HDR_LEN,
                   p->len - NDN_L2_FRAG_HDR_LEN);
            buf += p->len - NDN_L2_FRAG_HDR_LEN;
            p = p->next;
        }

        _release_l2_frag_entry(entry);
        ndn_shared_block_t* sb = ndn_shared_block_create_by_move(&b);
        if (sb == NULL) {
            DEBUG("ndn: cannot allocate shared block for reassembly (ID=%02X, "
                  "iface=%" PRIkernel_pid ")\n", id, iface);
            free((void*)b.buf);
            return NULL;
        }
        DEBUG("ndn: complete packet reassembled (ID=%02x, size=%d, iface=%"
                  PRIkernel_pid ")\n", id, sb->block.len, iface);
        return sb;
    }
    // packet not complete yet; wait for more fragments
    return NULL;
}

void ndn_l2_frag_timeout(msg_t *msg)
{
    _l2_frag_entry_t *entry, *tmp;
    DL_FOREACH_SAFE(_l2_frag_list, entry, tmp) {
        if (&entry->timer_msg == msg) {
            DEBUG("ndn: remove expired l2 frag entry (ID=%u)\n", entry->id);
            _release_l2_frag_entry(entry);
        }
    }
}

void ndn_l2_init(void)
{
    _l2_frag_list = NULL;
}

/** @} */
