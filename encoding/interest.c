/*
 * Copyright (C) 2016 Wentao Shang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     net_ndn_encoding
 * @{
 *
 * @file
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */

#include "interest.h"

#include <debug.h>
#include <net/gnrc/nettype.h>
#include <random.h>

#include <stdlib.h>
#include <string.h>

ndn_shared_block_t* ndn_interest_create(ndn_block_t* name, void* selectors,
                                        uint32_t lifetime)
{
    if (name == NULL || name->buf == NULL || name->len <= 0) return NULL;

    (void)selectors;  //TODO: support selectors.

    // Get length of the lifetime value
    int lt_len = ndn_block_integer_length(lifetime);

    ndn_block_t inst;
    int inst_len = name->len + lt_len + 8;
    inst.len = ndn_block_total_length(NDN_TLV_INTEREST, inst_len);
    uint8_t* buf = (uint8_t*)malloc(inst.len);
    if (buf == NULL) {
        DEBUG("ndn_encoding: cannot allocate memory for interest block\n");
        return NULL;
    }
    inst.buf = buf;

    // Fill in the Interest header.
    buf[0] = NDN_TLV_INTEREST;
    int l = ndn_block_put_var_number(inst_len, buf + 1, inst.len - 1);
    buf += l + 1;
    assert(inst.len == inst_len + 1 + l);

    // Fill in the name.
    memcpy(buf, name->buf, name->len);
    buf += name->len;

    // Fill in the nonce.
    uint32_t nonce = random_uint32();
    buf[0] = NDN_TLV_NONCE;
    buf[1] = 4;  // Nonce field length
    buf[2] = (nonce >> 24) & 0xFF;
    buf[3] = (nonce >> 16) & 0xFF;
    buf[4] = (nonce >> 8) & 0xFF;
    buf[5] = nonce & 0xFF;

    // Fill in the lifetime
    buf[6] = NDN_TLV_INTERESTLIFETIME;
    buf[7] = lt_len;
    ndn_block_put_integer(lifetime, buf + 8, buf[7]);

    ndn_shared_block_t* shared = ndn_shared_block_create_by_move(&inst);
    if (shared == NULL) {
        free((void*)inst.buf);
        return NULL;
    }

    return shared;
}

ndn_shared_block_t* ndn_interest_create2(ndn_name_t* name, void* selectors,
                                         uint32_t lifetime)
{
    if (name == NULL) return NULL;

    (void)selectors;  //TODO: support selectors.

    int name_len = ndn_name_total_length(name);
    if (name_len <= 0) return NULL;

    // Get length of the lifetime value
    int lt_len = ndn_block_integer_length(lifetime);

    ndn_block_t inst;
    int inst_len = name_len + lt_len + 8;
    inst.len = ndn_block_total_length(NDN_TLV_INTEREST, inst_len);
    uint8_t* buf = (uint8_t*)malloc(inst.len);
    if (buf == NULL) {
        DEBUG("ndn_encoding: cannot allocate memory for interest block\n");
        return NULL;
    }
    inst.buf = buf;

    // Fill in the Interest header.
    buf[0] = NDN_TLV_INTEREST;
    int l = ndn_block_put_var_number(inst_len, buf + 1, inst.len - 1);
    buf += l + 1;
    assert(inst.len == inst_len + 1 + l);

    // Fill in the name.
    ndn_name_wire_encode(name, buf, name_len);
    buf += name_len;

    // Fill in the nonce.
    uint32_t nonce = random_uint32();
    buf[0] = NDN_TLV_NONCE;
    buf[1] = 4;  // Nonce field length
    buf[2] = (nonce >> 24) & 0xFF;
    buf[3] = (nonce >> 16) & 0xFF;
    buf[4] = (nonce >> 8) & 0xFF;
    buf[5] = nonce & 0xFF;

    // Fill in the lifetime
    buf[6] = NDN_TLV_INTERESTLIFETIME;
    buf[7] = lt_len;
    ndn_block_put_integer(lifetime, buf + 8, buf[7]);

    ndn_shared_block_t* shared = ndn_shared_block_create_by_move(&inst);
    if (shared == NULL) {
        free((void*)inst.buf);
        return NULL;
    }

    return shared;
}

int ndn_interest_get_name(ndn_block_t* block, ndn_block_t* name)
{
    if (name == NULL || block == NULL) return -1;

    const uint8_t* buf = block->buf;
    int len = block->len;
    uint32_t num;
    int l;

    /* read interest type */
    if (*buf != NDN_TLV_INTEREST) return -1;
    buf += 1;
    len -= 1;

    /* read interest length and ignore the value */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    buf += l;
    len -= l;

    /* read name type */
    if (*buf != NDN_TLV_NAME) return -1;
    buf += 1;
    len -= 1;

    /* read name length */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;

    if ((int)num > len - l)  // name block is incomplete
        return -1;

    name->buf = buf - 1;
    name->len = (int)num + l + 1;
    return 0;
}

int ndn_interest_get_nonce(ndn_block_t* block, uint32_t* nonce)
{
    if (nonce == NULL || block == NULL) return -1;

    const uint8_t* buf = block->buf;
    int len = block->len;
    uint32_t num;
    int l;

    /* read interest type */
    if (*buf != NDN_TLV_INTEREST) return -1;
    buf += 1;
    len -= 1;

    /* read interest length and ignore the value */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    buf += l;
    len -= l;

    /* read name type */
    if (*buf != NDN_TLV_NAME) return -1;
    buf += 1;
    len -= 1;

    /* read name length and skip the components */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    buf += l + (int)num;
    len -= l + (int)num;

    /* read and skip selectors */
    if (*buf == NDN_TLV_SELECTORS) {
        /* skip type */
        buf += 1;
        len -= 1;

        /* read length and skip length and value */
        l = ndn_block_get_var_number(buf, len, &num);
        if (l < 0) return -1;
        buf += l + (int)num;
        len -= l + (int)num;
    }

    /* check for nonce type */
    if (*buf != NDN_TLV_NONCE) return -1;
    buf += 1;
    len -= 1;

    /* check nonce length */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    if (num != 4) return -1;
    buf += l;
    len -= l;

    /* read nonce value */
    if (len < 4) return -1;
    ndn_block_get_integer(buf, 4, nonce);
    return 0;
}

int ndn_interest_get_lifetime(ndn_block_t* block, uint32_t* life)
{
    if (life == NULL || block == NULL) return -1;

    const uint8_t* buf = block->buf;
    int len = block->len;
    uint32_t num;
    int l;

    /* read interest type */
    if (*buf != NDN_TLV_INTEREST) return -1;
    buf += 1;
    len -= 1;

    /* read interest length and ignore the value */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    buf += l;
    len -= l;

    /* read name type */
    if (*buf != NDN_TLV_NAME) return -1;
    buf += 1;
    len -= 1;

    /* read name length and skip the components */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    buf += l + (int)num;
    len -= l + (int)num;

    /* read and skip selectors */
    if (*buf == NDN_TLV_SELECTORS) {
        /* skip type */
        buf += 1;
        len -= 1;

        /* read length and skip length and value */
        l = ndn_block_get_var_number(buf, len, &num);
        if (l < 0) return -1;
        buf += l + (int)num;
        len -= l + (int)num;
    }

    /* check for nonce type */
    if (*buf != NDN_TLV_NONCE) return -1;
    buf += 1;
    len -= 1;

    /* check nonce length and skip the value */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    if (num != 4) return -1;
    buf += l + (int)num;
    len -= l + (int)num;

    /* read lifetime type */
    if (*buf != NDN_TLV_INTERESTLIFETIME) return -1;
    buf += 1;
    len -= 1;

    /* read lifetime length */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    buf += l;
    len -= l;

    l = ndn_block_get_integer(buf, num, life);
    if (l < 0) return -1;
    else return 0;
}

/** @} */
